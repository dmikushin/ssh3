//! Everything [`crate::Screen::resync`] promises to reproduce, in comparable
//! form. Tests compare the snapshot of the emulator that produced a resync
//! with the snapshot of an emulator that consumed it.

use std::collections::BTreeMap;

use alacritty_terminal::grid::{Cursor, Dimensions, Grid};
use alacritty_terminal::index::{Column, Line};
use alacritty_terminal::term::cell::{Cell, Flags};
use alacritty_terminal::term::TermMode;
use alacritty_terminal::vte::ansi::{CharsetIndex, CursorStyle, KeyboardModes, Rgb};

use crate::track::{Extra, T};

/// Number of colours a program can change: 256 palette entries plus the
/// dynamic foreground, background and cursor colours (OSC 10/11/12).
pub(crate) const SETTABLE_COLORS: usize = 259;

#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    pub columns: usize,
    pub lines: usize,
    pub mode: TermMode,
    pub cells: Vec<Vec<Cell>>,
    pub cursor: Cursor<Cell>,
    pub saved_cursor: Cursor<Cell>,
    /// Primary screen while the alternate one is active. Its saved cursor is
    /// what the switch back restores on xterm-like terminals.
    pub main_cells: Option<Vec<Vec<Cell>>>,
    pub main_saved_cursor: Option<Cursor<Cell>>,
    /// Saved cursor of the inactive alternate screen.
    pub alt_saved_cursor: Option<Cursor<Cell>>,
    pub scroll_region: (usize, usize),
    pub tabs: Vec<bool>,
    /// `None` = never set by the program: the client keeps its own title,
    /// and a comparison accepts any value on the other side.
    pub title: Option<String>,
    pub title_stack: Vec<Option<String>>,
    pub active_charset: CharsetIndex,
    pub cursor_style: Option<CursorStyle>,
    pub keyboard_stack: Vec<KeyboardModes>,
    pub keyboard_stack_inactive: Vec<KeyboardModes>,
    pub modify_other_keys: u8,
    pub unknown_private_modes: BTreeMap<u16, bool>,
    pub unknown_ansi_modes: BTreeMap<u16, bool>,
    pub colors: Vec<Option<Rgb>>,
    /// Character REP repeats.
    pub last_char: Option<char>,
}

/// The cells, with the wrap and leading-spacer flags kept only where they
/// mean something: on a row's last cell. alacritty can leave it on another cell (a backward tab
/// keeps a pending wrap, and the next character then marks the cell the tab
/// moved to); no terminal reproduces that, and alacritty itself only reads
/// the flag on the last cell.
pub(crate) fn rows(g: &Grid<Cell>) -> Vec<Vec<Cell>> {
    let last = g.columns() - 1;
    (0..g.screen_lines())
        .map(|l| {
            (0..g.columns())
                .map(|c| {
                    let mut cell = g[Line(l as i32)][Column(c)].clone();
                    if c != last {
                        cell.flags.remove(Flags::WRAPLINE);
                    }
                    // Likewise a wide character's leading spacer means
                    // something only at the end of a row that wraps; a
                    // resize can leave one elsewhere, where it is a blank.
                    if c != last || !cell.flags.contains(Flags::WRAPLINE) {
                        cell.flags.remove(Flags::LEADING_WIDE_CHAR_SPACER);
                    }
                    // Combining characters on a spacer are not drawn by any
                    // terminal (alacritty attaches them there only after a
                    // scroll moved the row under the cursor's column).
                    if cell.flags.intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
                        && cell.zerowidth().is_some_and(|z| !z.is_empty())
                    {
                        // CellExtra's fields are private: rebuilt without them.
                        let (ul, link) = (cell.underline_color(), cell.hyperlink());
                        cell.extra = None;
                        cell.set_underline_color(ul);
                        cell.set_hyperlink(link);
                    }
                    // An emptied side record (combining characters cleared
                    // by overwriting a wide character) is no record.
                    if cell.zerowidth().is_some_and(<[char]>::is_empty)
                        && cell.underline_color().is_none()
                        && cell.hyperlink().is_none()
                    {
                        cell.extra = None;
                    }
                    cell
                })
                .collect()
        })
        .collect()
}

impl Snapshot {
    pub(crate) fn of(term: &T, extra: &Extra) -> Self {
        let g = term.grid();
        let alt = term.mode().contains(TermMode::ALT_SCREEN);
        let colors = term.colors();
        let mut cells = rows(g);
        // A pending wrap is recreated by writing the last cell again, which
        // clears a wrap flag already there (reachable by restoring a saved
        // cursor onto a row that wrapped since). The next character wraps
        // and sets the flag again, so it is not compared there.
        if g.cursor.input_needs_wrap {
            let line = g.cursor.point.line.0 as usize;
            if let Some(cell) = cells[line].last_mut() {
                cell.flags.remove(Flags::WRAPLINE);
            }
        }
        Snapshot {
            columns: g.columns(),
            lines: g.screen_lines(),
            mode: *term.mode(),
            cells,
            cursor: g.cursor.clone(),
            saved_cursor: g.saved_cursor.clone(),
            main_cells: extra.main_shadow.as_ref().map(rows),
            main_saved_cursor: extra.main_shadow.as_ref().map(|m| m.saved_cursor.clone()),
            alt_saved_cursor: (!alt).then(|| extra.alt_saved.clone()),
            scroll_region: (extra.scroll_top, extra.scroll_bottom),
            tabs: extra.tabs.clone(),
            title: extra.title.clone(),
            title_stack: extra.title_stack.clone(),
            active_charset: extra.active_charset,
            cursor_style: extra.cursor_style,
            keyboard_stack: extra.kb_stack.clone(),
            keyboard_stack_inactive: extra.kb_inactive.clone(),
            modify_other_keys: extra.modify_other_keys,
            unknown_private_modes: extra.unknown_private.clone(),
            unknown_ansi_modes: extra.unknown_ansi.clone(),
            colors: (0..SETTABLE_COLORS).map(|i| colors[i]).collect(),
            last_char: extra.last_char,
        }
    }

    /// Whether a resync reproduces the pending wraps of the cursor and the
    /// saved cursor. Not when the cursor's row ends in a wide character
    /// without its spacer (left by insert mode or by narrowing the
    /// alternate screen): a pending wrap is recreated by writing the last
    /// cell, and writing that one wraps instead.
    pub fn wrap_reproducible(&self) -> bool {
        let ok = |cells: &Vec<Vec<Cell>>, cur: &Cursor<Cell>| {
            let row = &cells[cur.point.line.0 as usize];
            let n = row.len();
            let last = &row[n - 1];
            !cur.input_needs_wrap || crate::resync::last_rewritable(last, n.checked_sub(2).map(|i| &row[i]))
        };
        let main_ok = match (&self.main_cells, &self.main_saved_cursor) {
            (Some(cells), Some(cur)) => ok(cells, cur),
            _ => true,
        };
        ok(&self.cells, &self.cursor)
            && ok(&self.cells, &self.saved_cursor)
            && main_ok
            && self.cursor_reachable()
            && self.saved_wrap_restorable()
            && !self.narrow_bottom_wrap()
    }

    /// On a two-column screen a wrapped bottom row ending in a wide
    /// character's spacer cannot be redrawn: the wrap is started by one more
    /// character, which can only land on that wide character (see
    /// `Redraw::wrap_last_row`).
    fn narrow_bottom_wrap(&self) -> bool {
        let bad = |cells: &Vec<Vec<Cell>>| {
            let last = cells.last().and_then(|r| r.last()).expect("cells");
            self.columns < 3
                && last.flags.contains(Flags::WRAPLINE)
                && last.flags.intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
        };
        bad(&self.cells) || self.main_cells.as_ref().is_some_and(bad)
    }

    /// A saved cursor's pending wrap on a row that wrapped since is
    /// recreated by rewriting the last cell and wrapping once more
    /// (`Redraw::restore_wrap`); the extra character lands at the start of
    /// the next row, which is drawn again. That fails when a wide character
    /// there reaches the next row's own wrapped last cell (rows of two or
    /// three columns): drawing it again clears that row's wrap flag.
    fn saved_wrap_restorable(&self) -> bool {
        let cur = &self.saved_cursor;
        let line = cur.point.line.0 as usize;
        let row = &self.cells[line];
        let cols = row.len();
        let wrapped = row[cols - 1].flags.contains(Flags::WRAPLINE);
        if !(cur.input_needs_wrap && cur.point.column.0 + 1 == cols && wrapped) {
            return true;
        }
        let next = &self.cells[(line + 1).min(self.lines - 1)];
        let keep = if !next[cols - 1].flags.contains(Flags::WRAPLINE) {
            cols
        } else if next[cols - 1].flags.contains(Flags::WIDE_CHAR_SPACER) {
            cols.saturating_sub(2)
        } else {
            cols - 1
        };
        let span = if next.len() > 2 && next[1].flags.contains(Flags::WIDE_CHAR) { 3 } else { 2 };
        let wide = next[..span.min(cols)].iter().any(|c| c.flags.intersects(Flags::WIDE_CHAR | Flags::WIDE_CHAR_SPACER));
        !wide || keep >= span
    }

    /// In origin mode the cursor can only be placed inside the scroll region
    /// or above it (`Redraw::goto_in`); a restored saved cursor can leave it
    /// below.
    fn cursor_reachable(&self) -> bool {
        !self.mode.contains(TermMode::ORIGIN) || (self.cursor.point.line.0 as usize) < self.scroll_region.1
    }

    /// Whether a resync can make the terminal's REP character equal to
    /// `last_char` (see `Redraw::run` and `final_state`): with a pending
    /// wrap only if recreating it prints that character (directly or through
    /// the DEC line-drawing set); on the primary screen always, unless the
    /// saved cursor's own pending wrap prints later; on the alternate screen
    /// only if it has a blank run to print and erase it in.
    pub fn rep_reproducible(&self) -> bool {
        let Some(r) = self.last_char else { return true };
        // Recreating a pending wrap rewrites the row's last cell, wherever
        // the cursor is (see `Redraw::position_rep`).
        let wrap_cell = |cur: &Cursor<Cell>| {
            let row = &self.cells[cur.point.line.0 as usize];
            let mut c = row.len() - 1;
            if row[c].flags.contains(Flags::WIDE_CHAR_SPACER) && c > 0 {
                c -= 1;
            }
            row[c].clone()
        };
        let rewrites = |cur: &Cursor<Cell>| {
            let row = &self.cells[cur.point.line.0 as usize];
            let n = row.len();
            cur.input_needs_wrap && crate::resync::last_rewritable(&row[n - 1], n.checked_sub(2).map(|i| &row[i]))
        };
        if rewrites(&self.cursor) {
            return crate::resync::reprints_as(&wrap_cell(&self.cursor), r);
        }
        if !self.mode.contains(TermMode::ALT_SCREEN) {
            return !rewrites(&self.saved_cursor);
        }
        let cell = |l: usize, x: usize| &self.cells[l][x];
        crate::resync::rep_cell(self.lines, self.columns, &cell, r).is_some()
            || crate::resync::rep_slot(self.lines, self.columns, &cell, r).is_some()
    }

    /// Differences between `self` (the reference) and `other`, one line per
    /// differing item. Titles the reference never set (`None`) match anything.
    pub fn diff(&self, other: &Snapshot) -> Vec<String> {
        if self.wrap_reproducible() {
            return self.diff_with(other, self.rep_reproducible());
        }
        // What the redraw cannot reproduce (see `wrap_reproducible`) is left
        // out on both sides: the pending wraps, and the wrap flags of the
        // rows they are on.
        let mask = |s: &Snapshot| {
            let mut s = s.clone();
            for line in [s.cursor.point.line.0 as usize, s.saved_cursor.point.line.0 as usize, s.lines - 1] {
                if let Some(c) = s.cells.get_mut(line).and_then(|r| r.last_mut()) {
                    c.flags.remove(Flags::WRAPLINE | Flags::LEADING_WIDE_CHAR_SPACER);
                }
            }
            let main_saved = s.main_saved_cursor.as_ref().map(|c| c.point.line.0 as usize);
            if let Some(m) = s.main_cells.as_mut() {
                let n = m.len();
                for line in [Some(n - 1), main_saved].into_iter().flatten() {
                    if let Some(c) = m.get_mut(line).and_then(|r| r.last_mut()) {
                        c.flags.remove(Flags::WRAPLINE | Flags::LEADING_WIDE_CHAR_SPACER);
                    }
                }
            }
            if let Some(c) = s.main_saved_cursor.as_mut() {
                c.input_needs_wrap = false;
            }
            s.cursor.input_needs_wrap = false;
            s.saved_cursor.input_needs_wrap = false;
            s
        };
        mask(self).diff_with(&mask(other), self.rep_reproducible())
    }

    /// [`Self::diff`], comparing the REP character only if `rep` (whether
    /// the resync could reproduce it, decided when it was generated).
    pub fn diff_with(&self, other: &Snapshot, rep: bool) -> Vec<String> {
        let mut d = Vec::new();
        macro_rules! cmp {
            ($f:ident) => {
                if self.$f != other.$f {
                    d.push(format!("{}: {:?} != {:?}", stringify!($f), self.$f, other.$f));
                }
            };
        }
        cmp!(columns);
        cmp!(lines);
        cmp!(mode);
        cmp!(cursor);
        cmp!(saved_cursor);
        cmp!(main_saved_cursor);
        cmp!(alt_saved_cursor);
        cmp!(scroll_region);
        cmp!(tabs);
        cmp!(active_charset);
        cmp!(cursor_style);
        cmp!(keyboard_stack);
        cmp!(keyboard_stack_inactive);
        cmp!(modify_other_keys);
        // Modes alacritty does not implement can only be restored when the
        // reference saw them; the emulator sees every byte the client saw,
        // so modes only the other side knows cannot come from the program.
        for (name, a, b) in [
            ("unknown_private_modes", &self.unknown_private_modes, &other.unknown_private_modes),
            ("unknown_ansi_modes", &self.unknown_ansi_modes, &other.unknown_ansi_modes),
        ] {
            for (k, v) in a {
                if b.get(k) != Some(v) {
                    d.push(format!("{name}[{k}]: {v} != {:?}", b.get(k)));
                }
            }
        }
        cmp!(colors);
        if self.last_char.is_some() && rep {
            cmp!(last_char);
        }
        if self.title.is_some() && self.title != other.title {
            d.push(format!("title: {:?} != {:?}", self.title, other.title));
        }
        let stack_ok = self.title_stack.len() == other.title_stack.len()
            && self.title_stack.iter().zip(&other.title_stack).all(|(a, b)| a.is_none() || a == b);
        if !stack_ok {
            d.push(format!("title_stack: {:?} != {:?}", self.title_stack, other.title_stack));
        }
        grid_diff("cells", &self.cells, &other.cells, &mut d);
        match (&self.main_cells, &other.main_cells) {
            (Some(a), Some(b)) => grid_diff("main_cells", a, b, &mut d),
            (None, None) => (),
            (a, b) => d.push(format!("main_cells present: {} != {}", a.is_some(), b.is_some())),
        }
        d
    }
}

fn grid_diff(name: &str, a: &[Vec<Cell>], b: &[Vec<Cell>], d: &mut Vec<String>) {
    if a.len() != b.len() {
        d.push(format!("{name}: {} lines != {}", a.len(), b.len()));
        return;
    }
    let mut n = 0;
    for (l, (ra, rb)) in a.iter().zip(b).enumerate() {
        for (c, (ca, cb)) in ra.iter().zip(rb).enumerate() {
            if ca != cb {
                n += 1;
                if n <= 8 {
                    d.push(format!("{name}[{l}][{c}]: {ca:?} != {cb:?}"));
                }
            }
        }
    }
    if n > 8 {
        d.push(format!("{name}: {} more differing cells", n - 8));
    }
}
