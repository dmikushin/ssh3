//! A `Handler` that forwards every parser action to alacritty's `Term` and
//! records the state `Term` keeps private (scroll region, tab stops, titles,
//! active charset, keyboard-mode stacks, the inactive primary screen) so that
//! [`crate::Screen::resync`] can reproduce it.
//!
//! Every mirror below copies the logic of the corresponding `Term` method in
//! alacritty_terminal 0.26.0 (src/term/mod.rs, line numbers cited). The
//! continuation tests in tests/roundtrip.rs check the mirrors: after a
//! resync, both emulators are fed the same further bytes, so a mirror that
//! drifted from `Term` shows up as diverging screens.
//!
//! The same wrapper bounds what a program writing to the pty can make the
//! server allocate (SPEC O1): alacritty_terminal grows a cell's combining
//! characters without limit and panics on the 4097th kitty keyboard push
//! (both measured, see crate docs). Those inputs are cut here, before they
//! reach `Term`.

use std::collections::BTreeMap;

use alacritty_terminal::event::VoidListener;
use alacritty_terminal::grid::{Cursor, Dimensions, Grid};
use alacritty_terminal::index::{Column, Line};
use alacritty_terminal::term::cell::{Cell, Flags};
use alacritty_terminal::term::{Term, TermMode};
use alacritty_terminal::vte::ansi::cursor_icon::CursorIcon;
use alacritty_terminal::vte::ansi::{
    Attr, CharsetIndex, ClearMode, CursorShape, CursorStyle, Handler, Hyperlink, KeyboardModes,
    KeyboardModesApplyBehavior, LineClearMode, Mode, ModifyOtherKeys, NamedPrivateMode,
    PrivateMode, Rgb, ScpCharPath, ScpUpdateMode, StandardCharset, TabulationClearMode,
};
use unicode_width::UnicodeWidthChar;

pub(crate) type T = Term<VoidListener>;

/// Combining characters kept per cell; further ones are dropped.
pub(crate) const MAX_ZEROWIDTH: usize = 16;
/// Title stack depth; further pushes are dropped (alacritty allows 4096).
pub(crate) const MAX_TITLE_STACK: usize = 16;
/// Kitty keyboard-mode stack depth. alacritty's own limit is the same, but
/// its overflow branch removes from the *title* stack and panics when that is
/// empty (term/mod.rs:1295-1296), so the push is dropped here instead.
pub(crate) const MAX_KEYBOARD_STACK: usize = 4096;
/// Distinct modes alacritty does not implement whose last value is kept so
/// that resync restores them on the client.
pub(crate) const MAX_UNKNOWN_MODES: usize = 64;

/// State `Term` does not expose, mirrored from the parser actions.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Extra {
    /// Scroll region `[top, bottom)` in screen lines (term/mod.rs:2155-2177).
    pub scroll_top: usize,
    pub scroll_bottom: usize,
    /// Tab stops (term/mod.rs:2319-2347).
    pub tabs: Vec<bool>,
    pub title: Option<String>,
    pub title_stack: Vec<Option<String>>,
    pub active_charset: CharsetIndex,
    /// `None` = the terminal's default style (term/mod.rs:2204-2219).
    pub cursor_style: Option<CursorStyle>,
    /// Kitty keyboard-mode stack of the active screen and of the other one
    /// (swapped on alternate-screen switches, term/mod.rs:726).
    pub kb_stack: Vec<KeyboardModes>,
    pub kb_inactive: Vec<KeyboardModes>,
    /// XTMODKEYS modifyOtherKeys value (0, 1 or 2); alacritty ignores it.
    pub modify_other_keys: u8,
    /// Private (`CSI ? n h/l`) and ANSI (`CSI n h/l`) modes alacritty does
    /// not implement: last value set by the program.
    pub unknown_private: BTreeMap<u16, bool>,
    pub unknown_ansi: BTreeMap<u16, bool>,
    /// Copy of the primary screen while the alternate screen is active
    /// (`Term::inactive_grid` is private). Exact: the inactive grid is only
    /// ever changed by resize (mirrored in `Screen::resize`), by the switch
    /// back and by RIS.
    pub main_shadow: Option<Grid<Cell>>,
    /// Saved cursor of the alternate screen while the primary is active: it
    /// survives the switch (swap_alt does not reset it, term/mod.rs:714-735).
    pub alt_saved: Cursor<Cell>,
    /// Last character the parser printed: vte repeats it for REP (`CSI n
    /// b`) and never forgets it, not even on RIS (ansi.rs:1292, 1563).
    pub last_char: Option<char>,
}

impl Extra {
    pub fn new(columns: usize, lines: usize) -> Self {
        Self {
            scroll_top: 0,
            scroll_bottom: lines,
            tabs: default_tabs(columns),
            title: None,
            title_stack: Vec::new(),
            active_charset: CharsetIndex::G0,
            cursor_style: None,
            kb_stack: Vec::new(),
            kb_inactive: Vec::new(),
            modify_other_keys: 0,
            unknown_private: BTreeMap::new(),
            unknown_ansi: BTreeMap::new(),
            main_shadow: None,
            alt_saved: Cursor::default(),
            last_char: None,
        }
    }
}

/// A pending wrap exists only in the last column: that is where writing
/// leaves one, and every cursor movement ends it — in xterm, and here.
/// alacritty keeps it through tab movements (`move_backward_tabs`,
/// `move_forward_tabs`, term/mod.rs:1567-1614; cleared after them above)
/// and through a resize that changes the width (grid/resize.rs; cleared by
/// this after one). Kept elsewhere, it made the next character mark a
/// middle cell as wrapped, a flag insert mode could later shift into the
/// last column (measured, fuzz case in tests/fuzz.rs history).
pub(crate) fn settle_wrap(cur: &mut Cursor<Cell>, columns: usize) {
    if cur.point.column.0 + 1 != columns {
        cur.input_needs_wrap = false;
    }
}

/// alacritty keeps a wrap flag and a leading spacer per cell, so insert,
/// delete and a resize without reflow move them away from the last column,
/// where they mean nothing — until a later insert moves one back and the
/// row suddenly counts as wrapped (measured, fuzz case in tests/fuzz.rs
/// history). Terminals keep the wrap per line. Removed where they mean
/// nothing, they cannot come back.
pub(crate) fn strip_inert(g: &mut Grid<Cell>, line: usize) {
    let last = g.columns() - 1;
    let row = &mut g[Line(line as i32)];
    for c in 0..last {
        let cell = &mut row[Column(c)];
        if cell.flags.intersects(Flags::WRAPLINE | Flags::LEADING_WIDE_CHAR_SPACER) {
            cell.flags.remove(Flags::WRAPLINE | Flags::LEADING_WIDE_CHAR_SPACER);
        }
    }
}

pub(crate) fn strip_inert_all(g: &mut Grid<Cell>) {
    for l in 0..g.screen_lines() {
        strip_inert(g, l);
    }
}

/// `Row::reset` clears only up to a row's occupancy mark when the row's last
/// cell already has the template's background (grid/row.rs:90-110), and
/// `Row::grow` adds default cells on a resize without raising the mark. A
/// row cleared with a coloured background and then widened keeps its
/// coloured cells through any later clear (measured: `ESC[48;5;17m`, DL,
/// resize wider, DECCOLM left them; a terminal clears them). Marking every
/// row fully occupied after a resize makes clears complete.
pub(crate) fn mark_occupied(g: &mut Grid<Cell>) {
    for l in 0..g.screen_lines() {
        let _ = &mut g[Line(l as i32)][Column(0)..];
    }
}

pub(crate) fn default_tabs(columns: usize) -> Vec<bool> {
    (0..columns).map(|i| i.is_multiple_of(8)).collect()
}

/// `TabStops::resize` (term/mod.rs:2339-2346): keeps existing stops and
/// extends with the default every-8 pattern by absolute index.
pub(crate) fn resize_tabs(tabs: &mut Vec<bool>, columns: usize) {
    let mut index = tabs.len();
    tabs.resize_with(columns, || {
        let stop = index.is_multiple_of(8);
        index += 1;
        stop
    });
}

fn record(map: &mut BTreeMap<u16, bool>, mode: u16, on: bool) {
    if crate::resync::SCREEN_SWITCH_MODES.contains(&mode) {
        return;
    }
    if map.len() < MAX_UNKNOWN_MODES || map.contains_key(&mode) {
        map.insert(mode, on);
    }
}

pub(crate) struct Tracked<'a> {
    pub term: &'a mut T,
    pub extra: &'a mut Extra,
}

impl Tracked<'_> {
    fn alt(&self) -> bool {
        self.term.mode().contains(TermMode::ALT_SCREEN)
    }

    /// The cell `Term::input` attaches a zero-width character to
    /// (term/mod.rs:1070-1083).
    fn zerowidth_target(&self) -> &Cell {
        let g = self.term.grid();
        let mut column = g.cursor.point.column;
        if !g.cursor.input_needs_wrap {
            column.0 = column.saturating_sub(1);
        }
        let line = g.cursor.point.line;
        if g[line][column].flags.contains(Flags::WIDE_CHAR_SPACER) {
            column.0 = column.saturating_sub(1);
        }
        &g[line][Column(column.0)]
    }

    /// Entering the alternate screen: what `swap_alt` does to the primary
    /// grid (term/mod.rs:714-723) is applied to the shadow copy.
    fn enter_alt(&mut self) {
        let mut shadow = self.term.grid().clone();
        shadow.saved_cursor = shadow.cursor.clone();
        self.extra.main_shadow = Some(shadow);
        std::mem::swap(&mut self.extra.kb_stack, &mut self.extra.kb_inactive);
    }

    fn leave_alt(&mut self) -> Option<Grid<Cell>> {
        self.extra.alt_saved = self.term.grid().saved_cursor.clone();
        std::mem::swap(&mut self.extra.kb_stack, &mut self.extra.kb_inactive);
        self.extra.main_shadow.take()
    }

    fn style_mut(&mut self) -> &mut CursorStyle {
        // Config::default_cursor_style is CursorStyle::default().
        self.extra.cursor_style.get_or_insert_with(CursorStyle::default)
    }

    fn full_region(&mut self) {
        self.extra.scroll_top = 0;
        self.extra.scroll_bottom = self.term.screen_lines();
    }
}

impl Handler for Tracked<'_> {
    fn set_title(&mut self, title: Option<String>) {
        self.extra.title.clone_from(&title);
        self.term.set_title(title)
    }
    fn set_cursor_style(&mut self, style: Option<CursorStyle>) {
        self.extra.cursor_style = style;
        self.term.set_cursor_style(style)
    }
    fn set_cursor_shape(&mut self, shape: CursorShape) {
        self.style_mut().shape = shape;
        self.term.set_cursor_shape(shape)
    }
    fn input(&mut self, c: char) {
        self.extra.last_char = Some(c);
        if c.width() == Some(0) {
            let cell = self.zerowidth_target();
            if cell.zerowidth().is_some_and(|z| z.len() >= MAX_ZEROWIDTH) {
                return;
            }
        }
        if self.term.mode().contains(TermMode::INSERT) {
            let before = self.term.grid().cursor.point.line.0 as usize;
            self.term.input(c);
            let after = self.term.grid().cursor.point.line.0 as usize;
            let g = self.term.grid_mut();
            strip_inert(g, before);
            strip_inert(g, after);
            return;
        }
        self.term.input(c)
    }
    fn goto(&mut self, line: i32, col: usize) {
        self.term.goto(line, col)
    }
    fn goto_line(&mut self, line: i32) {
        self.term.goto_line(line)
    }
    fn goto_col(&mut self, col: usize) {
        self.term.goto_col(col)
    }
    fn insert_blank(&mut self, n: usize) {
        self.term.insert_blank(n);
        let line = self.term.grid().cursor.point.line.0 as usize;
        strip_inert(self.term.grid_mut(), line);
    }
    fn move_up(&mut self, n: usize) {
        self.term.move_up(n)
    }
    fn move_down(&mut self, n: usize) {
        self.term.move_down(n)
    }
    fn identify_terminal(&mut self, i: Option<char>) {
        self.term.identify_terminal(i)
    }
    fn device_status(&mut self, n: usize) {
        self.term.device_status(n)
    }
    fn move_forward(&mut self, col: usize) {
        self.term.move_forward(col)
    }
    fn move_backward(&mut self, col: usize) {
        self.term.move_backward(col)
    }
    fn move_down_and_cr(&mut self, row: usize) {
        self.term.move_down_and_cr(row)
    }
    fn move_up_and_cr(&mut self, row: usize) {
        self.term.move_up_and_cr(row)
    }
    fn put_tab(&mut self, count: u16) {
        self.term.put_tab(count)
    }
    fn backspace(&mut self) {
        self.term.backspace()
    }
    fn carriage_return(&mut self) {
        self.term.carriage_return()
    }
    fn linefeed(&mut self) {
        self.term.linefeed()
    }
    fn bell(&mut self) {
        self.term.bell()
    }
    fn substitute(&mut self) {
        self.term.substitute()
    }
    fn newline(&mut self) {
        self.term.newline()
    }
    fn set_horizontal_tabstop(&mut self) {
        // term/mod.rs:1479-1482
        let col = self.term.grid().cursor.point.column.0;
        self.extra.tabs[col] = true;
        self.term.set_horizontal_tabstop()
    }
    fn scroll_up(&mut self, n: usize) {
        self.term.scroll_up(n)
    }
    fn scroll_down(&mut self, n: usize) {
        self.term.scroll_down(n)
    }
    fn insert_blank_lines(&mut self, n: usize) {
        self.term.insert_blank_lines(n)
    }
    fn delete_lines(&mut self, n: usize) {
        self.term.delete_lines(n)
    }
    fn erase_chars(&mut self, n: usize) {
        self.term.erase_chars(n)
    }
    fn delete_chars(&mut self, n: usize) {
        self.term.delete_chars(n);
        let line = self.term.grid().cursor.point.line.0 as usize;
        strip_inert(self.term.grid_mut(), line);
    }
    fn move_backward_tabs(&mut self, count: u16) {
        self.term.move_backward_tabs(count);
        self.term.grid_mut().cursor.input_needs_wrap = false;
    }
    fn move_forward_tabs(&mut self, count: u16) {
        self.term.move_forward_tabs(count);
        self.term.grid_mut().cursor.input_needs_wrap = false;
    }
    fn save_cursor_position(&mut self) {
        self.term.save_cursor_position()
    }
    fn restore_cursor_position(&mut self) {
        self.term.restore_cursor_position()
    }
    fn clear_line(&mut self, mode: LineClearMode) {
        self.term.clear_line(mode)
    }
    fn clear_screen(&mut self, mode: ClearMode) {
        self.term.clear_screen(mode)
    }
    fn clear_tabs(&mut self, mode: TabulationClearMode) {
        // term/mod.rs:1821-1831
        match mode {
            TabulationClearMode::Current => {
                let col = self.term.grid().cursor.point.column.0;
                self.extra.tabs[col] = false;
            },
            TabulationClearMode::All => self.extra.tabs.iter_mut().for_each(|t| *t = false),
        }
        self.term.clear_tabs(mode)
    }
    fn set_tabs(&mut self, interval: u16) {
        self.term.set_tabs(interval)
    }
    fn reset_state(&mut self) {
        // term/mod.rs:1835-1858: everything tracked here returns to its
        // initial value; both grids are reset, including saved cursors.
        let was_alt = self.alt();
        self.term.reset_state();
        if was_alt {
            // RIS swaps the primary grid back and resets it, but a primary
            // grid resized while inactive could not be marked occupied
            // (`mark_occupied`), so the reset can leave coloured blanks
            // (measured: `ESC[104m`, DL, `ESC[?1049h`, resize wider, RIS).
            // The reset is completed here.
            let g = self.term.grid_mut();
            for l in 0..g.screen_lines() {
                for c in 0..g.columns() {
                    g[Line(l as i32)][Column(c)] = Cell::default();
                }
            }
        }
        let last_char = self.extra.last_char;
        *self.extra = Extra::new(self.term.columns(), self.term.screen_lines());
        self.extra.last_char = last_char;
    }
    fn reverse_index(&mut self) {
        self.term.reverse_index()
    }
    fn terminal_attribute(&mut self, attr: Attr) {
        self.term.terminal_attribute(attr)
    }
    fn set_mode(&mut self, mode: Mode) {
        if let Mode::Unknown(n) = mode {
            record(&mut self.extra.unknown_ansi, n, true);
        }
        self.term.set_mode(mode)
    }
    fn unset_mode(&mut self, mode: Mode) {
        if let Mode::Unknown(n) = mode {
            record(&mut self.extra.unknown_ansi, n, false);
        }
        self.term.unset_mode(mode)
    }
    fn report_mode(&mut self, mode: Mode) {
        self.term.report_mode(mode)
    }
    fn set_private_mode(&mut self, mode: PrivateMode) {
        match mode {
            PrivateMode::Named(NamedPrivateMode::SwapScreenAndSetRestoreCursor) if !self.alt() => {
                self.enter_alt()
            },
            PrivateMode::Named(NamedPrivateMode::ColumnMode) => self.full_region(),
            PrivateMode::Named(NamedPrivateMode::BlinkingCursor) => self.style_mut().blinking = true,
            PrivateMode::Unknown(n) => record(&mut self.extra.unknown_private, n, true),
            _ => (),
        }
        let was_alt = self.alt();
        self.term.set_private_mode(mode);
        if !was_alt && self.alt() {
            // Entering clears the alternate grid with `reset_region`, which
            // stops at each row's occupancy mark (see `mark_occupied`); a
            // grid resized while inactive keeps stale cells. The clear is
            // completed: every cell becomes a blank with the background in
            // effect (`Cell::reset`, term/cell.rs).
            let g = self.term.grid_mut();
            let blank = Cell { bg: g.cursor.template.bg, ..Cell::default() };
            for l in 0..g.screen_lines() {
                for c in 0..g.columns() {
                    g[Line(l as i32)][Column(c)] = blank.clone();
                }
            }
        }
    }
    fn unset_private_mode(&mut self, mode: PrivateMode) {
        let mut shadow = None;
        match mode {
            PrivateMode::Named(NamedPrivateMode::SwapScreenAndSetRestoreCursor) if self.alt() => {
                shadow = self.leave_alt()
            },
            PrivateMode::Named(NamedPrivateMode::ColumnMode) => self.full_region(),
            PrivateMode::Named(NamedPrivateMode::BlinkingCursor) => {
                self.style_mut().blinking = false
            },
            PrivateMode::Unknown(n) => record(&mut self.extra.unknown_private, n, false),
            _ => (),
        }
        let was_alt = self.alt();
        self.term.unset_private_mode(mode);
        if was_alt && !self.alt() {
            let g = self.term.grid_mut();
            // The shadow is the primary grid as this module kept it while
            // inactive (with the clean-ups below applied on resizes); the
            // one `Term` kept is not, and is replaced.
            if let Some(shadow) = shadow {
                *g = shadow;
            }
            // xterm restores the cursor saved on entry when leaving the
            // alternate screen (mode 1049); alacritty resumes the primary
            // grid's own cursor, which differs from the saved one once a
            // resize while inactive moved them differently
            // (grid/resize.rs). The client is xterm-like: follow it.
            g.cursor = g.saved_cursor.clone();
            let columns = g.columns();
            settle_wrap(&mut g.cursor, columns);
            settle_wrap(&mut g.saved_cursor, columns);
            strip_inert_all(g);
            // The primary grid was resized while inactive (see below).
            mark_occupied(g);
        }
    }
    fn report_private_mode(&mut self, mode: PrivateMode) {
        // term/mod.rs:2052-2056: reporting the blink mode materialises the
        // default style.
        if mode == PrivateMode::Named(NamedPrivateMode::BlinkingCursor) {
            self.style_mut();
        }
        self.term.report_private_mode(mode)
    }
    fn set_scrolling_region(&mut self, top: usize, bottom: Option<usize>) {
        // term/mod.rs:2155-2177
        let lines = self.term.screen_lines();
        let end = bottom.unwrap_or(lines);
        if top < end {
            self.extra.scroll_top = (top.saturating_sub(1)).min(lines);
            self.extra.scroll_bottom = end.min(lines);
        }
        self.term.set_scrolling_region(top, bottom)
    }
    fn set_keypad_application_mode(&mut self) {
        self.term.set_keypad_application_mode()
    }
    fn unset_keypad_application_mode(&mut self) {
        self.term.unset_keypad_application_mode()
    }
    fn set_active_charset(&mut self, index: CharsetIndex) {
        self.extra.active_charset = index;
        self.term.set_active_charset(index)
    }
    fn configure_charset(&mut self, index: CharsetIndex, charset: StandardCharset) {
        self.term.configure_charset(index, charset)
    }
    fn set_color(&mut self, index: usize, color: Rgb) {
        self.term.set_color(index, color)
    }
    fn dynamic_color_sequence(&mut self, prefix: String, index: usize, terminator: &str) {
        self.term.dynamic_color_sequence(prefix, index, terminator)
    }
    fn reset_color(&mut self, index: usize) {
        self.term.reset_color(index)
    }
    fn clipboard_store(&mut self, clipboard: u8, base64: &[u8]) {
        self.term.clipboard_store(clipboard, base64)
    }
    fn clipboard_load(&mut self, clipboard: u8, terminator: &str) {
        self.term.clipboard_load(clipboard, terminator)
    }
    fn decaln(&mut self) {
        self.term.decaln()
    }
    fn push_title(&mut self) {
        if self.extra.title_stack.len() >= MAX_TITLE_STACK {
            return;
        }
        self.extra.title_stack.push(self.extra.title.clone());
        self.term.push_title()
    }
    fn pop_title(&mut self) {
        // term/mod.rs:2249-2256
        if let Some(title) = self.extra.title_stack.pop() {
            self.extra.title = title;
        }
        self.term.pop_title()
    }
    fn text_area_size_pixels(&mut self) {
        self.term.text_area_size_pixels()
    }
    fn text_area_size_chars(&mut self) {
        self.term.text_area_size_chars()
    }
    fn set_hyperlink(&mut self, link: Option<Hyperlink>) {
        self.term.set_hyperlink(link)
    }
    fn set_mouse_cursor_icon(&mut self, icon: CursorIcon) {
        self.term.set_mouse_cursor_icon(icon)
    }
    fn report_keyboard_mode(&mut self) {
        self.term.report_keyboard_mode()
    }
    fn push_keyboard_mode(&mut self, mode: KeyboardModes) {
        if self.extra.kb_stack.len() >= MAX_KEYBOARD_STACK {
            return;
        }
        self.extra.kb_stack.push(mode);
        self.term.push_keyboard_mode(mode)
    }
    fn pop_keyboard_modes(&mut self, to_pop: u16) {
        // term/mod.rs:1308-1320
        let len = self.extra.kb_stack.len().saturating_sub(to_pop as usize);
        self.extra.kb_stack.truncate(len);
        self.term.pop_keyboard_modes(to_pop)
    }
    fn set_keyboard_mode(&mut self, mode: KeyboardModes, behavior: KeyboardModesApplyBehavior) {
        Handler::set_keyboard_mode(self.term, mode, behavior)
    }
    fn set_modify_other_keys(&mut self, mode: ModifyOtherKeys) {
        self.extra.modify_other_keys = match mode {
            ModifyOtherKeys::Reset => 0,
            ModifyOtherKeys::EnableExceptWellDefined => 1,
            ModifyOtherKeys::EnableAll => 2,
        };
        self.term.set_modify_other_keys(mode)
    }
    fn report_modify_other_keys(&mut self) {
        self.term.report_modify_other_keys()
    }
    fn set_scp(&mut self, char_path: ScpCharPath, update_mode: ScpUpdateMode) {
        self.term.set_scp(char_path, update_mode)
    }
}
