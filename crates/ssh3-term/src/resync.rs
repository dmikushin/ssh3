//! The redraw: bytes that take a terminal from any state — including the
//! middle of an escape sequence — to the emulator's state (SPEC §5).
//!
//! Drawing follows mosh's `Display::new_frame` with `initialized == false`
//! (src/terminal/terminaldisplay.cc in mobile-shell/mosh): reset the
//! scrolling region and clear (lines 126-129), hide the cursor while drawing
//! (142-145), draw row by row letting the real cursor autowrap through rows
//! that wrapped (put_row, 420-422 and 452-468), then place the cursor and
//! restore its visibility, renditions, hyperlink, bracketed paste and mouse
//! modes (258-318). mosh never redraws into an unknown terminal state, keeps
//! no alternate screen, saved cursors, tab stops, charsets or palette, so
//! those parts, and the parser-synchronising prefix, are ours.

use std::io::Write;

use alacritty_terminal::grid::{Cursor, Dimensions, Grid};
use alacritty_terminal::index::{Column, Line};
use alacritty_terminal::term::cell::{Cell, Flags, Hyperlink};
use alacritty_terminal::term::TermMode;
use alacritty_terminal::vte::ansi::{
    CharsetIndex, Color, CursorShape, CursorStyle, KeyboardModes, NamedColor, StandardCharset,
};

use unicode_width::UnicodeWidthChar;

use crate::snapshot::SETTABLE_COLORS;
use crate::track::{Extra, MAX_KEYBOARD_STACK, MAX_TITLE_STACK, MAX_UNKNOWN_MODES, MAX_ZEROWIDTH, T};
use crate::MAX_OSC_BYTES;

/// Ends any sequence the client parser may be inside (CAN aborts CSI, OSC,
/// DCS and SOS/PM/APC; ST ends strings on terminals that ignore CAN there),
/// then brings everything the drawing depends on to a known value. Not RIS:
/// a full reset clears the scrollback on several terminals.
const PROLOGUE: &[u8] = b"\x18\x1b\\\
\x1b[?2026h\
\x1b[?1049l\x1b[?1047l\x1b[?47l\
\x1b[0m\x1b]8;;\x1b\\\
\x1b(B\x1b)B\x1b*B\x1b+B\x0f\
\x1b[?6l\x1b[?7h\x1b[4l\x1b[20l\x1b[r\x1b[?25l";

/// Modes the prologue sets on the client for its own purposes; they are not
/// recorded as program state.
pub(crate) const SCREEN_SWITCH_MODES: [u16; 3] = [47, 1047, 1048];

const FLAGS_SGR: Flags = Flags::BOLD
    .union(Flags::DIM)
    .union(Flags::ITALIC)
    .union(Flags::ALL_UNDERLINES)
    .union(Flags::INVERSE)
    .union(Flags::HIDDEN)
    .union(Flags::STRIKEOUT);

/// Worst-case size of each part, used by [`max_resync_len`].
const SGR_MAX: usize = 96; // reset, 9 attributes, fg/bg/underline truecolor
const CELL_MAX: usize = SGR_MAX + 4 + 4 * MAX_ZEROWIDTH;
const POS_MAX: usize = 12; // CSI 9999;9999 H
const OSC8_MAX: usize = 12 + MAX_OSC_BYTES;
const CURSOR_MAX: usize = POS_MAX + CELL_MAX + SGR_MAX + OSC8_MAX + 16 + 2;
const KB_MAX: usize = 8 + MAX_KEYBOARD_STACK * 7 + 8;

/// Upper bound on [`crate::Screen::resync`] output for a screen of this size
/// (after clamping to the crate's dimension limits). Holds for any state:
/// when cell hyperlinks would exceed it, the redraw is generated without
/// them.
pub fn max_resync_len(columns: u16, lines: u16) -> usize {
    let cols = columns.clamp(crate::MIN_COLUMNS, crate::MAX_COLUMNS) as usize;
    let lines = lines.clamp(crate::MIN_LINES, crate::MAX_LINES) as usize;
    let screens = 2;
    let cells = screens * cols * lines * (CELL_MAX + POS_MAX);
    let rows = screens * lines * POS_MAX;
    let fixed = PROLOGUE.len()
        + 3 * CURSOR_MAX // saved cursors
        + CURSOR_MAX // final cursor
        + 2 * KB_MAX
        + 32 // 1049 switches
        + SETTABLE_COLORS * 32 + 32
        + (MAX_TITLE_STACK + 1) * (MAX_OSC_BYTES + 16) + MAX_TITLE_STACK * 5
        + 8 + cols * (POS_MAX + 2)
        + 16 // region
        + 2 * MAX_UNKNOWN_MODES * 10
        + 64 // REP character
        + crate::seq::MAX_PENDING // held sequence prefix
        + 256; // modes, cursor style, charsets, sync end
    cells + rows + fixed
}

/// The redraw, followed by `held` (the parser's partial sequence). Never
/// longer than [`max_resync_len`], and never allocates more than its own
/// length while being made: a first pass only counts bytes (deciding
/// whether per-cell hyperlinks fit within the bound), the second writes
/// into a buffer of exactly that size. A buffer grown by doubling instead
/// held up to 1.5x the bound during a reallocation (measured: 1.36 MB peak
/// for an 837 KB bound at 80x24), and building the redraw with links before
/// checking the bound held 33.7 MB at 120x40.
pub(crate) fn resync(term: &T, extra: &Extra, held: &[u8]) -> Vec<u8> {
    let max = max_resync_len(term.columns() as u16, term.screen_lines() as u16);
    let limit = max - crate::seq::MAX_PENDING;
    let count = |links| {
        let out = Redraw::new(links, Out::counter(limit)).run(term, extra);
        (!out.overflow).then_some(out.len)
    };
    let (links, len) = match count(true) {
        Some(n) => (true, n),
        // Without hyperlinks every part is within the bound by construction;
        // `None` would mean the bound is wrong.
        None => (false, count(false).expect("redraw without links within its bound")),
    };
    let out = Out::writer(len + held.len());
    let mut out = Redraw::new(links, out).run(term, extra).buf;
    debug_assert_eq!(out.len(), len, "both passes write the same bytes");
    out.extend_from_slice(held);
    out
}

/// Output of a redraw pass: counts bytes up to `limit` (a write that would
/// pass it sets `overflow`), and stores them when made by [`Out::writer`],
/// whose buffer is allocated once with the exact size.
struct Out {
    buf: Vec<u8>,
    store: bool,
    len: usize,
    limit: usize,
    overflow: bool,
}

impl Out {
    fn counter(limit: usize) -> Self {
        Out { buf: Vec::new(), store: false, len: 0, limit, overflow: false }
    }

    fn writer(capacity: usize) -> Self {
        Out { buf: Vec::with_capacity(capacity), store: true, len: 0, limit: usize::MAX, overflow: false }
    }

    fn extend_from_slice(&mut self, b: &[u8]) {
        if self.overflow {
            return;
        }
        if self.len + b.len() > self.limit {
            self.overflow = true;
            return;
        }
        self.len += b.len();
        if self.store {
            self.buf.extend_from_slice(b);
        }
    }

    fn push(&mut self, b: u8) {
        self.extend_from_slice(&[b]);
    }
}

impl Write for Out {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, PartialEq)]
struct Attrs {
    fg: Color,
    bg: Color,
    flags: Flags,
    underline: Option<Color>,
}

impl Attrs {
    fn of(cell: &Cell) -> Self {
        Attrs {
            fg: cell.fg,
            bg: cell.bg,
            flags: cell.flags & FLAGS_SGR,
            underline: cell.underline_color(),
        }
    }

    fn default() -> Self {
        Attrs::of(&Cell::default())
    }
}

struct Redraw {
    out: Out,
    /// End of the scroll region while origin mode positioning is in use.
    region_end: usize,
    attrs: Attrs,
    link: Option<Hyperlink>,
    cell_links: bool,
}

impl Redraw {
    fn new(cell_links: bool, out: Out) -> Self {
        Redraw { out, region_end: 0, attrs: Attrs::default(), link: None, cell_links }
    }

    fn run(mut self, term: &T, extra: &Extra) -> Out {
        let alt = term.mode().contains(TermMode::ALT_SCREEN);
        let active = term.grid();
        self.out.extend_from_slice(PROLOGUE);

        let main = if alt { extra.main_shadow.as_ref().expect("shadow while alt") } else { active };
        self.draw(main, &extra.tabs);
        if alt {
            // The switch below saves the primary cursor (xterm and
            // alacritty alike); 1049 is set while the cursor is the
            // primary screen's saved one.
            self.keyboard_stack(&extra.kb_inactive);
            let saved = &main.saved_cursor;
            self.place(saved, main);
            if wrap_cleared(main, saved) {
                // The slot 1049h is about to overwrite holds the cursor
                // while its row's wrap flag is set again (drawing with the
                // ASCII set; DECRC brings the cursor's back).
                self.out.extend_from_slice(b"\x1b7");
                self.charsets_ascii();
                self.out.push(0x0f);
                self.restore_wrap(saved, main);
                self.out.extend_from_slice(b"\x1b8");
                self.attrs = Attrs::of(&saved.template);
                self.link = saved.template.hyperlink();
            }
            self.out.extend_from_slice(b"\x1b[?1049h");
            // The alternate screen starts with the primary cursor's
            // charsets (alacritty copies the cursor; xterm keeps them).
            self.charsets_ascii();
            self.draw(active, &extra.tabs);
            self.save(&active.saved_cursor, active);
        } else {
            // The alternate screen's saved cursor and keyboard stack survive
            // while it is inactive; its contents do not (cleared on entry).
            // Leaving it restores the renditions current at entry: alacritty
            // keeps them in the primary grid's cursor, xterm restores the
            // cursor saved by 1049h.
            let (attrs, link) = (self.attrs.clone(), self.link.clone());
            self.out.extend_from_slice(b"\x1b[?1049h");
            self.keyboard_stack(&extra.kb_inactive);
            self.save(&extra.alt_saved, active);
            // REP repeats the last printed character. The alternate screen's
            // contents are discarded on entry, so it is printed there.
            if let (Some(c), false) = (extra.last_char, rewrites_last(active, &active.cursor)) {
                self.sgr(&Attrs::default());
                self.hyperlink(None);
                self.goto(0, 0);
                let mut buf = [0u8; 4];
                self.out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
            self.out.extend_from_slice(b"\x1b[?1049l");
            (self.attrs, self.link) = (attrs, link);
            self.save(&active.saved_cursor, active);
        }

        self.palette(term);
        self.titles(extra);
        self.tabs(&extra.tabs);
        self.keyboard_stack(&extra.kb_stack);
        self.final_state(term, extra);
        self.out.extend_from_slice(b"\x1b[?2026l");
        self.out
    }

    fn sgr(&mut self, a: &Attrs) {
        if *a == self.attrs {
            return;
        }
        self.out.extend_from_slice(b"\x1b[0");
        let f = a.flags;
        for (flag, code) in [
            (Flags::BOLD, ";1"),
            (Flags::DIM, ";2"),
            (Flags::ITALIC, ";3"),
            (Flags::UNDERLINE, ";4"),
            (Flags::DOUBLE_UNDERLINE, ";4:2"),
            (Flags::UNDERCURL, ";4:3"),
            (Flags::DOTTED_UNDERLINE, ";4:4"),
            (Flags::DASHED_UNDERLINE, ";4:5"),
            (Flags::INVERSE, ";7"),
            (Flags::HIDDEN, ";8"),
            (Flags::STRIKEOUT, ";9"),
        ] {
            if f.contains(flag) {
                self.out.extend_from_slice(code.as_bytes());
            }
        }
        color(&mut self.out, a.fg, 30, 90, 38);
        color(&mut self.out, a.bg, 40, 100, 48);
        if let Some(u) = a.underline {
            color(&mut self.out, u, 0, 0, 58);
        }
        self.out.push(b'm');
        self.attrs = a.clone();
    }

    fn hyperlink(&mut self, link: Option<Hyperlink>) {
        if link == self.link {
            return;
        }
        match &link {
            Some(l) => {
                let _ = write!(self.out, "\x1b]8;id={};{}\x1b\\", l.id(), l.uri());
            },
            None => self.out.extend_from_slice(b"\x1b]8;;\x1b\\"),
        }
        self.link = link;
    }

    fn put(&mut self, cell: &Cell) {
        self.sgr(&Attrs::of(cell));
        let link = if self.cell_links { cell.hyperlink() } else { None };
        self.hyperlink(link);
        let c = if cell.c == '\t' { ' ' } else { cell.c };
        let mut buf = [0u8; 4];
        self.out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        for z in cell.zerowidth().unwrap_or(&[]) {
            self.out.extend_from_slice(z.encode_utf8(&mut buf).as_bytes());
        }
    }

    /// Moves to an absolute position; in origin mode (`Some(region top)`)
    /// CUP counts from the region's top, and a line above it is reached
    /// with CUU, which alacritty applies as an absolute move that `goto`
    /// then offsets by the region top again (term/mod.rs:1156-1168,
    /// 1215-1221): from the top, `CUU n` lands on `2*top - n`. Lines below
    /// the region cannot be reached in origin mode (only DECRC puts the
    /// cursor there); see `Snapshot::cursor_reproducible`.
    fn goto_in(&mut self, origin: Option<usize>, line: usize, col: usize) {
        let Some(top) = origin else {
            return self.goto(line, col);
        };
        // In origin mode `goto` clamps to the region's last line; a line
        // below it is out of reach (`Snapshot::wrap_reproducible`), the
        // nearest one is used.
        let last = self.region_end.max(1) - 1;
        let line = line.min(last);
        if line >= top {
            return self.goto(line - top, col);
        }
        // CUP 1 lands on min(top, last); it is never above `line` here.
        self.goto(0, col);
        let p0 = top.min(last);
        if p0 > line {
            let _ = write!(self.out, "\x1b[{}A", p0 + top - line);
        }
    }

    fn goto(&mut self, line: usize, col: usize) {
        let _ = write!(self.out, "\x1b[{};{}H", line + 1, col + 1);
    }

    /// Clears the screen and draws every cell, top to bottom.
    fn draw(&mut self, g: &Grid<Cell>, _tabs: &[bool]) {
        self.sgr(&Attrs::default());
        self.hyperlink(None);
        self.out.extend_from_slice(b"\x1b[H\x1b[2J");
        let cols = g.columns();
        let lines = g.screen_lines();
        let blank = Cell::default();
        let last = lines - 1;
        let last_cell = &g[Line(last as i32)][Column(cols - 1)];
        let wide_end = last_cell.flags.intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER);
        let last_wraps = last_cell.flags.contains(Flags::WRAPLINE) && (cols >= 3 || !wide_end);
        let last_end = if !last_wraps {
            cols
        } else if last_cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
            cols - 2
        } else {
            cols - 1
        };
        let mut wrapped_in = false;
        let mut redo_start = false;
        let mut tab_cells = Vec::new();
        for l in 0..lines {
            let row = &g[Line(l as i32)];
            let wraps = row[Column(cols - 1)].flags.contains(Flags::WRAPLINE) && l + 1 < lines;
            // Last column that must be written: everything for a row that
            // wraps (the wrap happens by writing past its end), otherwise
            // up to the last cell that differs from a cleared one.
            let mut end = if wraps {
                cols
            } else {
                (0..cols).rev().find(|&c| !is_blank(&row[Column(c)], &blank)).map_or(0, |c| c + 1)
            };
            if l == last && last_wraps {
                end = end.min(last_end); // the end is written by wrap_last_row
            }
            if wrapped_in {
                end = end.max(1);
            }
            // A placeholder wide character landed in columns 0..2. It is
            // erased, not overwritten: overwriting a wide character in
            // columns 0..2 also removes the spacer that wrapped it
            // (term/mod.rs:1004-1008).
            let erase = redo_start;
            if erase {
                end = end.max(2);
            }
            if end == 0 {
                wrapped_in = false;
                redo_start = false;
                continue;
            }
            if !wrapped_in || erase {
                self.goto(l, 0);
            }
            if erase {
                self.out.extend_from_slice(b"\x1b[2X");
            }
            let leading = self.draw_span(row, l, cols, 0, end, wraps, 0, true);
            wrapped_in = wraps;
            redo_start = leading;
        }
        if last_wraps {
            self.wrap_last_row(g);
        }
        // A tab writes '\t' into the cell it starts from when that cell is
        // blank (alacritty term/mod.rs:1366-1380), spacers included;
        // reproduce it the same way, after everything else is drawn.
        for l in 0..lines {
            for c in 0..cols {
                if g[Line(l as i32)][Column(c)].c == '\t' {
                    tab_cells.push((l, c));
                }
            }
        }
        for (l, c) in tab_cells {
            self.goto(l, c);
            self.out.push(b'\t');
        }
    }

    /// Draws columns `start..end` of row `l` (cursor at column `pos0`, or
    /// `usize::MAX` if unknown); `fresh` when the rest of the row is still
    /// blank (a first drawing, not a repair after one); returns whether the row ends with a leading
    /// spacer whose placeholder wide character landed in the next row.
    #[allow(clippy::too_many_arguments)]
    fn draw_span(
        &mut self,
        row: &alacritty_terminal::grid::Row<Cell>,
        l: usize,
        cols: usize,
        start: usize,
        end: usize,
        wraps: bool,
        pos0: usize,
        fresh: bool,
    ) -> bool {
        let mut leading = false;
        // Cursor column on this row; usize::MAX once it left the row.
        let mut pos = pos0;
        let mut skip_to = 0;
        for c in start..end {
            let cell = &row[Column(c)];
            if c > start && c <= skip_to {
                continue; // made with the run of spacers before it
            }
            if cell.flags.contains(Flags::LEADING_WIDE_CHAR_SPACER) && wraps && c == cols - 1 {
                // A wide character that did not fit left this spacer and
                // wrapped (alacritty term/mod.rs:1107-1113). Any wide
                // character does the same; the one that lands at the
                // start of the next row is erased when it is drawn.
                self.at(l, c, &mut pos);
                self.placeholder(cell);
                leading = true;
                pos = usize::MAX;
                continue;
            }
            if cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
                if c > 0 && row[Column(c - 1)].flags.contains(Flags::WIDE_CHAR) {
                    continue; // written with its wide character
                }
                // A spacer without its wide character (left by insert
                // mode or by character deletion splitting a pair).
                // ECH, ICH and DCH move and clear cells without the
                // wide-character fix-ups that writing does
                // (term/mod.rs:993-1011), so a placeholder's spacer is
                // separated from it with them. When the row wraps from
                // this spacer, the wrap must start from it: a cursor
                // parked there with a pending wrap is saved first and
                // restored after (as for a wide character there, below).
                // A run of such spacers is made right to left, each
                // placeholder landing on cells already erased.
                let mut run_end = c;
                if c > 0 {
                    while run_end + 1 < end && row[Column(run_end + 1)].flags.contains(Flags::WIDE_CHAR_SPACER) {
                        run_end += 1;
                    }
                }
                let park = wraps && run_end == cols - 1;
                if park {
                    self.sgr(&Attrs::default());
                    self.hyperlink(None);
                    self.goto(l, c);
                    self.out.extend_from_slice(b" \x1b7");
                }
                if c == 0 && !fresh {
                    // DCH would shift the rest of a drawn row; not
                    // reproduced here (`Snapshot::layout_reproducible`).
                } else if c == 0 {
                    self.at(l, 0, &mut pos);
                    self.placeholder(cell);
                    self.goto(l, 0);
                    // DCH fills the end of the row with the current
                    // background; that cell is not drawn again if blank.
                    let mut fill = Attrs::default();
                    fill.bg = row[Column(cols - 1)].bg;
                    self.sgr(&fill);
                    self.out.extend_from_slice(b"\x1b[P");
                    // Combining characters on it: one written from
                    // column 1 attaches to column 0, skipping back over
                    // a spacer stops there (term/mod.rs:1070-1083).
                    if let Some(z) = cell.zerowidth().filter(|z| !z.is_empty()) {
                        self.goto(l, 1);
                        let mut buf = [0u8; 4];
                        for ch in z {
                            self.out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                    }
                } else {
                    for k in (c..=run_end).rev() {
                        // The placeholder is written over erased cells: over a
                        // wide pair or spacer it would trigger the fix-ups
                        // (which also drop a leading spacer above,
                        // term/mod.rs:993-1011). The pair is drawn again below.
                        let pair = k == c
                            && c >= 2
                            && row[Column(c - 1)].flags.contains(Flags::WIDE_CHAR_SPACER)
                            && row[Column(c - 2)].flags.contains(Flags::WIDE_CHAR);
                        if pair {
                            self.goto(l, k - 2);
                            self.out.extend_from_slice(b"\x1b[2X");
                        } else {
                            self.goto(l, k - 1);
                            self.out.extend_from_slice(b"\x1b[X");
                        }
                        self.goto(l, k - 1);
                        self.placeholder(&row[Column(k)]);
                        self.goto(l, k - 1);
                        self.out.extend_from_slice(b"\x1b[X");
                    }
                    skip_to = run_end;
                    let prev = &row[Column(c - 1)];
                    if c >= 2
                        && prev.flags.contains(Flags::WIDE_CHAR_SPACER)
                        && row[Column(c - 2)].flags.contains(Flags::WIDE_CHAR)
                    {
                        self.goto(l, c - 2);
                        self.put(&row[Column(c - 2)]);
                    } else {
                        self.put(prev);
                    }
                }
                pos = usize::MAX;
                if park {
                    self.out.extend_from_slice(b"\x1b8");
                    self.attrs = Attrs::default();
                    self.link = None;
                    self.charsets_ascii();
                }
                continue;
            }
            if cell.flags.contains(Flags::LEADING_WIDE_CHAR_SPACER) {
                // Not at the end of a wrapping row (handled above): a
                // blank left by a resize, drawn as one.
                self.at(l, c, &mut pos);
                // Combining characters on a spacer are not kept (snapshot.rs).
                let mut blank = Cell { c: cell.c, fg: cell.fg, bg: cell.bg, flags: cell.flags, extra: None };
                blank.flags.remove(Flags::LEADING_WIDE_CHAR_SPACER | Flags::WRAPLINE);
                blank.set_underline_color(cell.underline_color());
                blank.set_hyperlink(cell.hyperlink());
                self.put(&blank);
                pos = c + 1;
                continue;
            }
            if cell.flags.contains(Flags::WIDE_CHAR) && c == cols - 1 {
                // A wide character in the last column, without its
                // spacer (insert mode pushed it there, or a resize of
                // the alternate screen cut its spacer off). Written one
                // column left, then pushed right by ICH, which moves
                // cells without fix-ups; the cell it covered is drawn
                // again. If the row wraps, the wrap must start from
                // this cell, which can never be written in place: a
                // cursor parked there with a pending wrap is saved
                // first and restored after (DECSC/DECRC; the saved
                // cursors are set after drawing).
                if wraps {
                    self.sgr(&Attrs::default());
                    self.hyperlink(None);
                    self.goto(l, c);
                    self.out.extend_from_slice(b" \x1b7");
                }
                // The cells it is written over are erased first, so
                // writing it does not split a wide pair there (which
                // would also drop a leading spacer above,
                // term/mod.rs:993-1011).
                let pair = c >= 2
                    && row[Column(c - 1)].flags.contains(Flags::WIDE_CHAR_SPACER)
                    && row[Column(c - 2)].flags.contains(Flags::WIDE_CHAR);
                if pair {
                    self.goto(l, c - 2);
                    self.out.extend_from_slice(b"\x1b[2X");
                } else {
                    self.goto(l, c - 1);
                    self.out.extend_from_slice(b"\x1b[X");
                }
                self.goto(l, c - 1);
                self.put(cell);
                self.goto(l, c - 1);
                self.out.extend_from_slice(b"\x1b[@");
                let prev = &row[Column(c - 1)];
                if c >= 2
                    && prev.flags.contains(Flags::WIDE_CHAR_SPACER)
                    && row[Column(c - 2)].flags.contains(Flags::WIDE_CHAR)
                {
                    self.goto(l, c - 2);
                    self.put(&row[Column(c - 2)]);
                } else if prev.flags.contains(Flags::WIDE_CHAR_SPACER) && c >= 2 {
                    // An orphan spacer before it, made again the same
                    // way as above.
                    self.goto(l, c - 2);
                    self.placeholder(prev);
                    self.goto(l, c - 2);
                    self.out.extend_from_slice(b"\x1b[X");
                    self.put(&row[Column(c - 2)]);
                } else if !prev.flags.intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER) {
                    self.put(prev);
                }
                pos = usize::MAX;
                if wraps {
                    self.out.extend_from_slice(b"\x1b8");
                    self.attrs = Attrs::default();
                    self.link = None;
                    self.charsets_ascii();
                }
                continue;
            }
            self.at(l, c, &mut pos);
            self.put(cell);
            if cell.flags.contains(Flags::WIDE_CHAR) {
                pos = c + 2;
                if c + 1 < cols && !row[Column(c + 1)].flags.contains(Flags::WIDE_CHAR_SPACER) {
                    // A wide character without its spacer: the spacer
                    // writing it made is erased again.
                    let next = &row[Column(c + 1)];
                    let mut a = Attrs::default();
                    a.bg = next.bg;
                    self.sgr(&a);
                    self.goto(l, c + 1);
                    self.out.extend_from_slice(b"\x1b[X");
                    pos = c + 1;
                }
            } else {
                pos = c + 1;
                // A tab mark is set again at once: later passes may draw
                // this cell again (wrap restoration), which clears it. Not
                // on a wrapping row's last cell, whose pending wrap the next
                // row's first character needs; the final pass covers it.
                if cell.c == '\t' && !(wraps && c + 1 == cols) {
                    self.goto(l, c);
                    self.out.push(b'\t');
                    pos = usize::MAX;
                }
            }
        }
        leading
    }

    /// The bottom row can be marked as wrapped (a wrapped row moved down by
    /// reverse index), but wrapping there would scroll. With a scroll region
    /// below the screen (`CSI lines+1;lines+2 r` clamps to an empty region at
    /// the bottom, term/mod.rs:2155-2175) a wrap on the bottom row stays on
    /// it (`wrapline`, `linefeed`): the last cell is written, one more
    /// character sets the wrap flag and lands in column 0. Columns 0..2 are
    /// erased before and drawn again after: writing over a wide character
    /// there would remove the spacer of the row above (term/mod.rs:1004-1008).
    fn wrap_last_row(&mut self, g: &Grid<Cell>) {
        let cols = g.columns();
        let lines = g.screen_lines();
        let last = lines - 1;
        let row = &g[Line(last as i32)];
        let cell = &row[Column(cols - 1)];
        let _ = write!(self.out, "\x1b[{};{}r", lines + 1, lines + 2);
        self.goto(last, 0);
        let _ = write!(self.out, "\x1b[{}X", erase_width(row, cols));
        if cell.flags.contains(Flags::LEADING_WIDE_CHAR_SPACER) {
            self.goto(last, cols - 1);
            self.placeholder(cell);
        } else if cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
            let orphan = !row[Column(cols - 2)].flags.contains(Flags::WIDE_CHAR);
            self.goto(last, cols - 2);
            if orphan {
                // A spacer without its wide character: a placeholder's,
                // whose wide character is erased afterwards.
                self.placeholder(cell);
            } else {
                self.put(&row[Column(cols - 2)]);
            }
            self.out.push(b' ');
            if orphan {
                self.out.extend_from_slice(b"\x1b[r");
                self.goto(last, cols - 2);
                self.out.extend_from_slice(b"\x1b[X");
                self.draw_span(row, last, cols, cols - 2, cols - 1, false, cols - 2, false);
                let _ = write!(self.out, "\x1b[{};{}r", lines + 1, lines + 2);
            }
        } else {
            self.goto(last, cols - 1);
            self.put(cell);
            self.out.push(b' ');
        }
        self.out.extend_from_slice(b"\x1b[r");
        // Columns from here on were written above with the wrap flag.
        let limit = keep_end(row);
        self.goto(last, 0);
        let width = erase_width(row, limit);
        let _ = write!(self.out, "\x1b[{width}X");
        self.draw_span(row, last, cols, 0, width, false, 0, false);
    }

    /// Moves to column `c` of line `l` unless the cursor is already there.
    fn at(&mut self, l: usize, c: usize, pos: &mut usize) {
        if *pos != c {
            self.goto(l, c);
            *pos = c;
        }
    }

    /// Writes a wide character with `cell`'s renditions, to leave a spacer
    /// carrying them; the character itself is erased or overwritten later.
    fn placeholder(&mut self, cell: &Cell) {
        self.sgr(&Attrs::of(cell));
        let link = if self.cell_links { cell.hyperlink() } else { None };
        self.hyperlink(link);
        self.out.extend_from_slice("\u{4e2d}".as_bytes());
    }

    /// Moves to the cursor's position and gives the terminal that cursor's
    /// renditions, hyperlink, charsets and pending-wrap state.
    fn place(&mut self, cur: &Cursor<Cell>, g: &Grid<Cell>) {
        self.position(cur, 0, false, g);
        self.cursor_attrs(cur);
    }

    fn save(&mut self, cur: &Cursor<Cell>, g: &Grid<Cell>) {
        self.place(cur, g);
        self.out.extend_from_slice(b"\x1b7");
        self.charsets_ascii();
        self.restore_wrap(cur, g);
    }

    /// Recreating a pending wrap rewrote the last cell of the cursor's row,
    /// clearing a wrap flag it had (a cursor saved before its row wrapped).
    /// One more character wraps and sets the flag again; it lands at the
    /// start of the next row (of the same row on the bottom row, see
    /// [`Self::wrap_last_row`]), which is drawn again.
    fn restore_wrap(&mut self, cur: &Cursor<Cell>, g: &Grid<Cell>) {
        if !wrap_cleared(g, cur) {
            return;
        }
        let lines = g.screen_lines();
        let line = cur.point.line.0 as usize;
        {
            // Not when a wide character at the start of the next row
            // reaches that row's own wrapped last cell: drawing it again
            // would clear that flag instead (`Snapshot::wrap_reproducible`).
            let next = &g[Line((line + 1).min(lines - 1) as i32)];
            let span = erase_width(next, g.columns());
            let wide = (0..span).any(|c| next[Column(c)].flags.intersects(Flags::WIDE_CHAR | Flags::WIDE_CHAR_SPACER));
            if (wide && keep_end(next) < span) || next[Column(0)].flags.contains(Flags::WIDE_CHAR_SPACER) {
                return;
            }
        }
        let bottom = line + 1 == lines;
        let next = if bottom { line } else { line + 1 };
        // The slot holds this cursor (callers save it first), so the cursor
        // may move and come back with DECRC: the cells the extra character
        // lands on are erased first (writing over a wide character in
        // columns 0..2 would drop a leading spacer above, term/mod.rs:
        // 1004-1008), and for the bottom row the region that keeps the wrap
        // on its row is set (DECSTBM moves the cursor too).
        let row = &g[Line(next as i32)];
        let width = erase_width(row, keep_end(row));
        if bottom {
            let _ = write!(self.out, "\x1b[{};{}r", lines + 1, lines + 2);
        }
        self.goto(next, 0);
        let _ = write!(self.out, "\x1b[{width}X\x1b8");
        // DECRC brought back the cursor's renditions and charsets.
        self.attrs = Attrs::of(&cur.template);
        self.link = cur.template.hyperlink();
        self.out.push(b' ');
        if bottom {
            self.out.extend_from_slice(b"\x1b[r");
        }
        self.charsets_ascii();
        self.out.push(0x0f);
        self.goto(next, 0);
        let _ = write!(self.out, "\x1b[{width}X");
        self.draw_span(row, next, g.columns(), 0, width, false, 0, false);
    }

    fn charsets_ascii(&mut self) {
        self.out.extend_from_slice(b"\x1b(B\x1b)B\x1b*B\x1b+B");
    }

    /// Positions the cursor; a pending wrap is recreated by rewriting the
    /// last-column cell, which leaves the cursor there with the wrap pending.
    fn position(&mut self, cur: &Cursor<Cell>, top: usize, origin: bool, g: &Grid<Cell>) {
        self.position_rep(cur, top, origin, g, None)
    }

    /// Positions the cursor and recreates a pending wrap by writing the
    /// last cell of the row again, which leaves the cursor there with the
    /// wrap pending (a pending wrap exists only in the last column, see
    /// `track::settle_wrap`).
    ///
    /// When `rep` (the raw character the program printed last) is what the
    /// DEC line-drawing set turns into the rewritten glyph, it is printed
    /// through that set, so the terminal's REP character is `rep` as well.
    fn position_rep(
        &mut self,
        cur: &Cursor<Cell>,
        top: usize,
        origin: bool,
        g: &Grid<Cell>,
        rep: Option<char>,
    ) {
        let line = cur.point.line.0 as usize;
        let col = cur.point.column.0;
        let origin = origin.then_some(top);
        if !rewrites_last(g, cur) {
            // No pending wrap, or one `last_rewritable` cannot recreate
            // (`Snapshot::wrap_reproducible`).
            self.goto_in(origin, line, col);
            return;
        }
        let row = &g[Line(line as i32)];
        let mut c = g.columns() - 1;
        if row[Column(c)].flags.contains(Flags::WIDE_CHAR_SPACER) && c > 0 {
            c -= 1;
        }
        self.goto_in(origin, line, c);
        let cell = row[Column(c)].clone();
        if cell.flags.contains(Flags::WIDE_CHAR) {
            // Rewriting a wide character in place would also drop the
            // leading spacer of the row above (term/mod.rs:1004-1008);
            // erased first, it is written into plain cells.
            self.out.extend_from_slice(b"\x1b[2X");
        }
        match rep {
            Some(r) => self.reprint(&cell, r),
            None => self.put(&cell),
        }
    }

    fn cursor_attrs(&mut self, cur: &Cursor<Cell>) {
        self.sgr(&Attrs::of(&cur.template));
        self.hyperlink(cur.template.hyperlink());
        for (i, inter) in [(CharsetIndex::G0, b'('), (CharsetIndex::G1, b')'), (CharsetIndex::G2, b'*'), (CharsetIndex::G3, b'+')] {
            let set = match cur.charsets[i] {
                StandardCharset::Ascii => b'B',
                StandardCharset::SpecialCharacterAndLineDrawing => b'0',
            };
            self.out.extend_from_slice(&[0x1b, inter, set]);
        }
    }

    fn palette(&mut self, term: &T) {
        self.out.extend_from_slice(b"\x1b]104\x07\x1b]110\x07\x1b]111\x07\x1b]112\x07");
        let colors = term.colors();
        for i in 0..SETTABLE_COLORS {
            if let Some(c) = colors[i] {
                let (code, idx) = match i {
                    0..256 => ("4;", Some(i)),
                    256 => ("10", None),
                    257 => ("11", None),
                    _ => ("12", None),
                };
                let _ = match idx {
                    Some(i) => write!(self.out, "\x1b]{code}{i};rgb:{:02x}/{:02x}/{:02x}\x07", c.r, c.g, c.b),
                    None => write!(self.out, "\x1b]{code};rgb:{:02x}/{:02x}/{:02x}\x07", c.r, c.g, c.b),
                };
            }
        }
    }

    fn title(&mut self, title: &Option<String>) {
        if let Some(t) = title {
            let _ = write!(self.out, "\x1b]2;{t}\x07");
        }
    }

    fn titles(&mut self, extra: &Extra) {
        for _ in 0..MAX_TITLE_STACK {
            self.out.extend_from_slice(b"\x1b[23t");
        }
        for t in &extra.title_stack {
            self.title(t);
            self.out.extend_from_slice(b"\x1b[22t");
        }
        self.title(&extra.title);
    }

    fn tabs(&mut self, tabs: &[bool]) {
        self.out.extend_from_slice(b"\x1b[3g");
        for (c, &on) in tabs.iter().enumerate() {
            if on {
                let _ = write!(self.out, "\x1b[{}G\x1bH", c + 1);
            }
        }
    }

    fn keyboard_stack(&mut self, stack: &[KeyboardModes]) {
        let _ = write!(self.out, "\x1b[<{}u", MAX_KEYBOARD_STACK);
        for m in stack {
            let _ = write!(self.out, "\x1b[>{}u", m.bits());
        }
    }

    fn final_state(&mut self, term: &T, extra: &Extra) {
        let mode = *term.mode();
        let g = term.grid();
        let lines = g.screen_lines();
        // Region and origin mode move the cursor: before positioning.
        if (extra.scroll_top, extra.scroll_bottom) != (0, lines) {
            // alacritty clamps both margins to the screen after checking
            // top < bottom (term/mod.rs:2155-2175); a region clamped at the
            // bottom is reproduced by a bottom margin past the screen.
            let (top, bottom) = (extra.scroll_top, extra.scroll_bottom);
            let bottom = if bottom == lines { bottom.max(top + 2) } else { bottom };
            let _ = write!(self.out, "\x1b[{};{}r", top + 1, bottom);
        }
        // REP repeats the last printed character; with a pending wrap the
        // last print is the one recreating it (below), otherwise a print
        // that leaves no trace.
        let alt = mode.contains(TermMode::ALT_SCREEN);
        if let (Some(c), false, true) = (extra.last_char, rewrites_last(g, &g.cursor), alt) {
            let cell = |l: usize, x: usize| &g[Line(l as i32)][Column(x)];
            match rep_cell(g.screen_lines(), g.columns(), &cell, c) {
                Some((l, x)) => {
                    let cell = g[Line(l as i32)][Column(x)].clone();
                    self.goto(l, x);
                    self.reprint(&cell, c);
                },
                None => self.preceding_char(g, c),
            }
        }
        let origin = mode.contains(TermMode::ORIGIN);
        self.region_end = extra.scroll_bottom;
        if origin {
            self.out.extend_from_slice(b"\x1b[?6h");
        }
        self.position_rep(&g.cursor, extra.scroll_top, origin, g, extra.last_char);
        self.cursor_attrs(&g.cursor);
        self.out.push(if extra.active_charset == CharsetIndex::G1 { 0x0e } else { 0x0f });

        // Unknown modes first, so the modes alacritty implements, emitted
        // after them, win where they overlap on the client (xterm's mouse
        // modes 9 and 1001 are exclusive with 1000-1003).
        for (&n, &on) in &extra.unknown_private {
            let _ = write!(self.out, "\x1b[?{n}{}", if on { 'h' } else { 'l' });
        }
        for (&n, &on) in &extra.unknown_ansi {
            let _ = write!(self.out, "\x1b[{n}{}", if on { 'h' } else { 'l' });
        }

        let hl = |on: bool| if on { 'h' } else { 'l' };
        let _ = write!(self.out, "\x1b[?1{}", hl(mode.contains(TermMode::APP_CURSOR)));
        self.out.extend_from_slice(if mode.contains(TermMode::APP_KEYPAD) { b"\x1b=" } else { b"\x1b>" });
        self.out.extend_from_slice(b"\x1b[?1003l\x1b[?1002l\x1b[?1000l");
        if mode.contains(TermMode::MOUSE_REPORT_CLICK) {
            self.out.extend_from_slice(b"\x1b[?1000h");
        }
        if mode.contains(TermMode::MOUSE_DRAG) {
            self.out.extend_from_slice(b"\x1b[?1002h");
        }
        if mode.contains(TermMode::MOUSE_MOTION) {
            self.out.extend_from_slice(b"\x1b[?1003h");
        }
        self.out.extend_from_slice(b"\x1b[?1006l\x1b[?1005l");
        if mode.contains(TermMode::SGR_MOUSE) {
            self.out.extend_from_slice(b"\x1b[?1006h");
        }
        if mode.contains(TermMode::UTF8_MOUSE) {
            self.out.extend_from_slice(b"\x1b[?1005h");
        }
        for (flag, n) in [
            (TermMode::FOCUS_IN_OUT, 1004),
            (TermMode::ALTERNATE_SCROLL, 1007),
            (TermMode::URGENCY_HINTS, 1042),
            (TermMode::BRACKETED_PASTE, 2004),
            (TermMode::LINE_WRAP, 7),
        ] {
            let _ = write!(self.out, "\x1b[?{n}{}", hl(mode.contains(flag)));
        }
        let _ = write!(self.out, "\x1b[4{}\x1b[20{}", hl(mode.contains(TermMode::INSERT)), hl(mode.contains(TermMode::LINE_FEED_NEW_LINE)));
        let kitty = (mode & TermMode::KITTY_KEYBOARD_PROTOCOL).bits()
            >> TermMode::DISAMBIGUATE_ESC_CODES.bits().trailing_zeros();
        let _ = write!(self.out, "\x1b[={kitty};1u");
        match extra.modify_other_keys {
            0 => self.out.extend_from_slice(b"\x1b[>4;0m"),
            n => {
                let _ = write!(self.out, "\x1b[>4;{n}m");
            },
        }
        cursor_style(&mut self.out, extra.cursor_style);
        let _ = write!(self.out, "\x1b[?25{}", hl(mode.contains(TermMode::SHOW_CURSOR)));
    }
}

impl Redraw {
    /// Makes `c` the character REP repeats without leaving a trace: it is
    /// printed over blank cells, which are then erased (ECH with default
    /// renditions restores a blank cell exactly). A zero-width character is
    /// attached to the blank cell before the cursor. Needs a blank run of
    /// the character's width that does not touch the last column; a full
    /// screen without one keeps the client's previous REP character.
    /// Draws `cell` so that the last character printed is `r` when that is
    /// possible: `r` is the cell's glyph or its last combining character, or
    /// the DEC line-drawing set turns `r` into the glyph.
    fn reprint(&mut self, cell: &Cell, r: char) {
        let drawing = StandardCharset::SpecialCharacterAndLineDrawing;
        if r != cell.c && cell.zerowidth().is_none_or(<[char]>::is_empty) && drawing.map(r) == cell.c {
            self.sgr(&Attrs::of(cell));
            let link = if self.cell_links { cell.hyperlink() } else { None };
            self.hyperlink(link);
            let mut buf = [0u8; 4];
            self.out.extend_from_slice(b"\x1b(0");
            self.out.extend_from_slice(r.encode_utf8(&mut buf).as_bytes());
            self.out.extend_from_slice(b"\x1b(B");
        } else {
            self.put(cell);
        }
    }

    fn preceding_char(&mut self, g: &Grid<Cell>, c: char) {
        let cell = |l: usize, x: usize| &g[Line(l as i32)][Column(x)];
        let Some((l, start, bg)) = rep_slot(g.screen_lines(), g.columns(), &cell, c) else {
            return;
        };
        let width = c.width().unwrap_or(1);
        let mut attrs = Attrs::default();
        attrs.bg = bg;
        self.sgr(&attrs);
        self.hyperlink(None);
        let mut buf = [0u8; 4];
        let at = if width == 0 { start + 1 } else { start };
        self.goto(l, at);
        self.out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        self.goto(l, start);
        let _ = write!(self.out, "\x1b[{}X", width.max(1));
    }
}

/// Columns of a drawn row that may be erased and written again without
/// losing its wrap flag: all but the last cell (both halves of a wide one)
/// when the row wraps.
fn keep_end(row: &alacritty_terminal::grid::Row<Cell>) -> usize {
    let cols = row.len();
    let last = &row[Column(cols - 1)];
    if !last.flags.contains(Flags::WRAPLINE) {
        cols
    } else if last.flags.contains(Flags::WIDE_CHAR_SPACER) {
        cols.saturating_sub(2)
    } else {
        cols - 1
    }
}

/// How many cells from column 0 to erase before columns 0..2 of a drawn row
/// are written again: a wide character in columns 1..3 is erased whole,
/// since erasing only its first half leaves a spacer whose rewriting would
/// clear the character written before it (term/mod.rs:993-1002). Never
/// past `limit`.
fn erase_width(row: &alacritty_terminal::grid::Row<Cell>, limit: usize) -> usize {
    let wide_at_1 = row.len() > 1 && row[Column(1)].flags.contains(Flags::WIDE_CHAR);
    // A wide character in column 1 of a two-column row has no spacer and
    // cannot be written again in place; only column 0 is erased then.
    let width = match (wide_at_1, row.len()) {
        (true, 2) => 1,
        (true, _) => 3,
        (false, _) => 2,
    };
    width.min(limit)
}

/// Whether recreating `cur`'s pending wrap clears a wrap flag that
/// [`Redraw::restore_wrap`] must set again.
fn wrap_cleared(g: &Grid<Cell>, cur: &Cursor<Cell>) -> bool {
    let cols = g.columns();
    let wrapped = g[cur.point.line][Column(cols - 1)].flags.contains(Flags::WRAPLINE);
    rewrites_last(g, cur) && cur.point.column.0 + 1 == cols && wrapped
}

/// Whether recreating `cur`'s pending wrap writes the last cell of its row
/// again: not when there is none, nor when that cell is a wide character
/// without room for its spacer (it would wrap; see `position_rep`).
pub(crate) fn rewrites_last(g: &Grid<Cell>, cur: &Cursor<Cell>) -> bool {
    let row = &g[cur.point.line];
    let cols = g.columns();
    let prev = (cols >= 2).then(|| &row[Column(cols - 2)]);
    cur.input_needs_wrap && cur.point.column.0 + 1 == cols && last_rewritable(&row[Column(cols - 1)], prev)
}

/// Whether writing a row's last cell again (given the cell before it) both
/// reproduces the cell and leaves a pending wrap: not for a wide character
/// there (it does not fit and wraps), a leading spacer (only a wrap makes
/// one), a spacer whose wide character is missing (only writing that
/// wide character, one column left, makes one), or a cell a tab marked.
pub(crate) fn last_rewritable(last: &Cell, prev: Option<&Cell>) -> bool {
    if last.flags.intersects(Flags::WIDE_CHAR | Flags::LEADING_WIDE_CHAR_SPACER) {
        return false;
    }
    // A tab mark is set by a tab, which would end the pending wrap.
    if last.c == '\t' {
        return false;
    }
    if last.flags.contains(Flags::WIDE_CHAR_SPACER) {
        return prev.is_some_and(|p| p.flags.contains(Flags::WIDE_CHAR));
    }
    true
}

/// Whether drawing `cell` again can leave `r` as the last printed character.
pub(crate) fn reprints_as(cell: &Cell, r: char) -> bool {
    let drawing = StandardCharset::SpecialCharacterAndLineDrawing;
    match cell.zerowidth().and_then(<[char]>::last) {
        Some(&z) => z == r,
        None => r == cell.c || drawing.map(r) == cell.c,
    }
}

/// A visible cell that can be drawn again so that `r` is the last printed
/// character, not touching the last column (rewriting it there would clear
/// a wrap flag or leave a pending wrap).
pub(crate) fn rep_cell<'a>(
    lines: usize,
    cols: usize,
    cell: &dyn Fn(usize, usize) -> &'a Cell,
    r: char,
) -> Option<(usize, usize)> {
    for l in 0..lines {
        for x in 0..cols.saturating_sub(2) {
            let c = cell(l, x);
            if c.flags.intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER) {
                continue;
            }
            // Rewriting a wide character in columns 0..2 drops the spacer
            // of the row above (term/mod.rs:1004-1008).
            if x <= 1 && c.flags.contains(Flags::WIDE_CHAR) {
                continue;
            }
            // Nor a cell a tab marked: it is drawn as a blank and marked
            // again by a tab afterwards.
            if c.c == '\t' {
                continue;
            }
            // Nor a wide character whose spacer a tab marked.
            if c.flags.contains(Flags::WIDE_CHAR) && cell(l, x + 1).c == '\t' {
                continue;
            }
            // Nor a wide character without its spacer: writing it adds one.
            if c.flags.contains(Flags::WIDE_CHAR) && !cell(l, x + 1).flags.contains(Flags::WIDE_CHAR_SPACER) {
                continue;
            }
            if reprints_as(c, r) {
                return Some((l, x));
            }
        }
    }
    None
}

/// A run of blank cells where `c` can be printed and erased again without a
/// trace (ECH leaves a blank carrying only the renditions' background), not
/// touching the last column. Returns (line, column, background).
pub(crate) fn rep_slot<'a>(
    lines: usize,
    cols: usize,
    cell: &dyn Fn(usize, usize) -> &'a Cell,
    c: char,
) -> Option<(usize, usize, Color)> {
    let span = c.width().unwrap_or(1).max(1) + 1;
    let erased = |x: &Cell| *x == Cell { bg: x.bg, ..Cell::default() };
    for l in 0..lines {
        for start in 0..cols.saturating_sub(span) {
            let bg = cell(l, start).bg;
            if (start..start + span).all(|x| erased(cell(l, x)) && cell(l, x).bg == bg) {
                return Some((l, start, bg));
            }
        }
    }
    None
}

fn is_blank(cell: &Cell, blank: &Cell) -> bool {
    cell == blank
}

fn color(out: &mut Out, c: Color, base: u8, bright: u8, ext: u8) {
    match c {
        Color::Named(n) => {
            let n = n as usize;
            if n < 8 && base != 0 {
                let _ = write!(out, ";{}", base as usize + n);
            } else if n < 16 && base != 0 {
                let _ = write!(out, ";{}", bright as usize + n - 8);
            } else if n < 16 {
                let _ = write!(out, ";{ext};5;{n}");
            }
            // Foreground/Background: the default, already set by the reset.
            let _ = (NamedColor::Foreground, NamedColor::Background);
        },
        Color::Indexed(i) => {
            let _ = write!(out, ";{ext};5;{i}");
        },
        Color::Spec(rgb) => {
            let _ = write!(out, ";{ext};2;{};{};{}", rgb.r, rgb.g, rgb.b);
        },
    }
}

fn cursor_style(out: &mut Out, style: Option<CursorStyle>) {
    let code = match style {
        None => 0,
        Some(CursorStyle { shape, blinking }) => {
            let base = match shape {
                CursorShape::Underline => 3,
                CursorShape::Beam => 5,
                _ => 1,
            };
            if blinking { base } else { base + 1 }
        },
    };
    let _ = write!(out, "\x1b[{code} q");
}
