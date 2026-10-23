//! Server-side terminal emulator for the pty output lane (SPEC §5 "pty
//! lanes (hybrid, after mosh)").
//!
//! The server feeds every byte the program writes to the pty into a
//! [`Screen`]. When the lane's ring cannot take more bytes, the server keeps
//! reading the pty into the emulator only, and later appends
//! [`Screen::resync`] to the lane: a byte string that brings the client's
//! terminal — whatever state the bytes already delivered left it in, even in
//! the middle of an escape sequence — to the emulator's state.
//!
//! # Emulator choice (measured, not assumed)
//!
//! Two maintained crates were run on a recorded corpus (vim, nvim, less,
//! htop, top, mc with DEC line drawing, `ls --color`, a long scroll, plus
//! synthetic fixtures for SGR, wide characters, modes, origin mode, the
//! alternate screen and pending wrap), with tmux 3.7c as the reference:
//!
//! - `vt100` 0.18.1 disagreed with tmux on custom tab stops (it ignores
//!   HTS/TBC), DECAWM off, DECALN, and stores DEC line-drawing input as the
//!   raw letters `lqqk`.
//! - `alacritty_terminal` 0.26.0 agreed on every fixture; the remaining
//!   differences were representation only (tmux reports a pending wrap as
//!   column 80, alacritty as column 79 with a flag; tmux keeps ACS letters
//!   with an attribute, alacritty stores the Unicode box-drawing glyph).
//!
//! alacritty_terminal keeps part of its state private (scroll region, tab
//! stops, titles, the inactive screen, keyboard stacks); [`track`] mirrors it.
//!
//! # Bounded memory (SPEC O1)
//!
//! Three inputs a program can write make alacritty_terminal allocate
//! without limit or panic; all three were reproduced before being guarded:
//!
//! - an unterminated OSC string (vte's `std` parser buffers it: 64 MiB of
//!   payload grew the heap by 129 MiB) — cut at [`MAX_OSC_BYTES`] here;
//! - combining characters onto one cell (8 Mi marks: +34 MB) — cut at
//!   [`track::MAX_ZEROWIDTH`] per cell;
//! - the 4097th kitty keyboard push panics in
//!   alacritty_terminal term/mod.rs:1296 — dropped at the stack limit.
//!
//! Screen dimensions are clamped to [`MIN_COLUMNS`]..=[`MAX_COLUMNS`] ×
//! [`MIN_LINES`]..=[`MAX_LINES`]: a wide character on a 1-column screen
//! panics alacritty_terminal as well.

use std::time::Duration;

use alacritty_terminal::event::VoidListener;
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::vte::ansi::{Processor, Timeout};

mod resync;
mod seq;
mod snapshot;
mod track;

pub use resync::max_resync_len;
pub use snapshot::Snapshot;

/// OSC payload bytes passed to the parser per sequence; the rest of an
/// overlong OSC string is dropped (titles and hyperlink targets are cut).
pub const MAX_OSC_BYTES: usize = 4096;
/// A wide character on a 1-column screen makes alacritty_terminal write
/// its spacer past the row end and panic (`Term::input`, reproduced by
/// examples/one_col.rs before this limit); two columns always fit one.
pub const MIN_COLUMNS: u16 = 2;
pub const MAX_COLUMNS: u16 = 1024;
/// On a 1-line screen no DECSTBM is valid, so a region a program made
/// empty (`CSI 3;9 r` clamps to lines 1..1) could not be reset by a redraw.
pub const MIN_LINES: u16 = 2;
pub const MAX_LINES: u16 = 512;

/// Synchronized updates (mode 2026) are applied immediately: the server has
/// no display to keep consistent, and vte's buffering would hide bytes from
/// the emulator until the update ends or times out.
#[derive(Default)]
pub(crate) struct NoSync;

impl Timeout for NoSync {
    fn set_timeout(&mut self, _: Duration) {}
    fn clear_timeout(&mut self) {}
    fn pending_timeout(&self) -> bool {
        false
    }
}

struct Size {
    columns: usize,
    lines: usize,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.lines
    }
    fn screen_lines(&self) -> usize {
        self.lines
    }
    fn columns(&self) -> usize {
        self.columns
    }
}

fn clamp(columns: u16, lines: u16) -> Size {
    Size {
        columns: columns.clamp(MIN_COLUMNS, MAX_COLUMNS) as usize,
        lines: lines.clamp(MIN_LINES, MAX_LINES) as usize,
    }
}

/// Server-side model of one pty's terminal.
pub struct Screen {
    term: track::T,
    parser: Processor<NoSync>,
    extra: track::Extra,
    seq: seq::SeqTracker,
}

impl Screen {
    pub fn new(columns: u16, lines: u16) -> Self {
        let size = clamp(columns, lines);
        let config = Config { scrolling_history: 0, kitty_keyboard: true, ..Config::default() };
        let term = Term::new(config, &size, VoidListener);
        Self {
            term,
            parser: Processor::new(),
            extra: track::Extra::new(size.columns, size.lines),
            seq: seq::SeqTracker::default(),
        }
    }

    /// Feeds bytes the program wrote to the pty.
    pub fn feed(&mut self, bytes: &[u8]) {
        let mut handler = track::Tracked { term: &mut self.term, extra: &mut self.extra };
        let mut start = 0;
        for (i, &b) in bytes.iter().enumerate() {
            if !self.seq.step(b) {
                if start < i {
                    self.parser.advance(&mut handler, &bytes[start..i]);
                }
                start = i + 1;
            }
        }
        if start < bytes.len() {
            self.parser.advance(&mut handler, &bytes[start..]);
        }
    }

    /// Window size change (pty window-change).
    pub fn resize(&mut self, columns: u16, lines: u16) {
        let size = clamp(columns, lines);
        let old_columns = self.term.columns();
        if old_columns == size.columns && self.term.screen_lines() == size.lines {
            return;
        }
        // Term::resize (term/mod.rs:655-702): the inactive grid is resized
        // with reflow = is_alt; tabs are extended only when the width
        // changes; the scroll region is reset.
        self.term.resize(Size { columns: size.columns, lines: size.lines });
        let g = self.term.grid_mut();
        track::mark_occupied(g);
        track::strip_inert_all(g);
        track::settle_wrap(&mut g.cursor, size.columns);
        track::settle_wrap(&mut g.saved_cursor, size.columns);
        if let Some(main) = self.extra.main_shadow.as_mut() {
            main.resize(true, size.lines, size.columns);
            track::mark_occupied(main);
            track::strip_inert_all(main);
            track::settle_wrap(&mut main.cursor, size.columns);
            track::settle_wrap(&mut main.saved_cursor, size.columns);
        } else {
            // The inactive alternate grid's saved cursor is clamped like
            // any grid's (grid/resize.rs:93, 387); it is mirrored here.
            let saved = &mut self.extra.alt_saved.point;
            saved.line.0 = saved.line.0.min(size.lines as i32 - 1);
            saved.column.0 = saved.column.0.min(size.columns - 1);
            track::settle_wrap(&mut self.extra.alt_saved, size.columns);
        }
        if old_columns != size.columns {
            track::resize_tabs(&mut self.extra.tabs, size.columns);
        }
        self.extra.scroll_top = 0;
        self.extra.scroll_bottom = size.lines;
    }

    pub fn size(&self) -> (u16, u16) {
        (self.term.columns() as u16, self.term.screen_lines() as u16)
    }

    /// Bytes that bring a terminal in any state to this screen's state,
    /// including the parser's: when the emulator is inside an escape
    /// sequence or a UTF-8 character, the resync ends with the bytes of it
    /// seen so far. Never longer than [`max_resync_len`] for the current
    /// size.
    pub fn resync(&self) -> Vec<u8> {
        let mut out = resync::resync(&self.term, &self.extra);
        out.extend_from_slice(self.seq.held());
        out
    }

    /// Full comparable state, for verification.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot::of(&self.term, &self.extra)
    }

    pub fn alternate_screen(&self) -> bool {
        self.term.mode().contains(TermMode::ALT_SCREEN)
    }
}
