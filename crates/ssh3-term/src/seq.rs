//! Mirror of vte 0.15's parser state (src/lib.rs, `advance_*`; only the
//! transitions, no actions) for two purposes:
//!
//! - bound OSC strings: vte's `std` parser buffers an OSC payload without
//!   limit, so payload bytes beyond [`crate::MAX_OSC_BYTES`] are dropped
//!   before they reach it;
//! - know which bytes the parser holds when a resync is generated: a resync
//!   generated while the emulator is inside an escape sequence (or a UTF-8
//!   character) must leave the client inside the same sequence, otherwise
//!   the rest of it, which follows on the lane, is misread (measured: a cut
//!   after `ESC (` printed the `B` that completed it).
//!
//! The kept bytes are the ones that decide where the sequence goes next:
//! its introducer, parameters, intermediates and OSC payload. C0 controls
//! executed or ignored inside a sequence, and DCS/SOS/PM/APC content (which
//! alacritty ignores), are not kept: replaying them would execute them twice
//! or cost memory for nothing.

use crate::MAX_OSC_BYTES;

/// Longest held sequence prefix: an OSC introducer plus a full payload.
pub(crate) const MAX_PENDING: usize = MAX_OSC_BYTES + 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    Ground,
    Esc,
    EscInt,
    CsiEntry,
    CsiParam,
    CsiInt,
    CsiIgnore,
    DcsEntry,
    DcsParam,
    DcsInt,
    DcsPass,
    DcsIgnore,
    Osc,
    SosPmApc,
}

use St::*;

#[derive(Clone, Debug)]
pub(crate) struct SeqTracker {
    st: St,
    pending: Vec<u8>,
    osc_len: usize,
    utf8: Vec<u8>,
    utf8_need: u8,
}

impl Default for SeqTracker {
    fn default() -> Self {
        SeqTracker { st: Ground, pending: Vec::new(), osc_len: 0, utf8: Vec::new(), utf8_need: 0 }
    }
}

fn next_state(st: St, b: u8) -> St {
    match (st, b) {
        (Ground, 0x1b) => Esc,
        (Ground, _) => Ground,
        // anywhere(): CAN/SUB end every sequence, ESC starts a new one.
        (_, 0x18 | 0x1a) => Ground,
        (_, 0x1b) => Esc,

        (Esc, 0x20..=0x2f) => EscInt,
        (Esc, 0x50) => DcsEntry,
        (Esc, 0x58 | 0x5e | 0x5f) => SosPmApc,
        (Esc, 0x5b) => CsiEntry,
        (Esc, 0x5d) => Osc,
        (Esc, 0x30..=0x7e) => Ground,
        (Esc, _) => Esc,

        (EscInt, 0x30..=0x7e) => Ground,
        (EscInt, _) => EscInt,

        (CsiEntry, 0x20..=0x2f) => CsiInt,
        (CsiEntry, 0x30..=0x3f) => CsiParam,
        (CsiEntry, 0x40..=0x7e) => Ground,
        (CsiEntry, _) => CsiEntry,

        (CsiParam, 0x20..=0x2f) => CsiInt,
        (CsiParam, 0x3c..=0x3f) => CsiIgnore,
        (CsiParam, 0x40..=0x7e) => Ground,
        (CsiParam, _) => CsiParam,

        (CsiInt, 0x30..=0x3f) => CsiIgnore,
        (CsiInt, 0x40..=0x7e) => Ground,
        (CsiInt, _) => CsiInt,

        (CsiIgnore, 0x40..=0x7e) => Ground,
        (CsiIgnore, _) => CsiIgnore,

        (DcsEntry, 0x20..=0x2f) => DcsInt,
        (DcsEntry, 0x30..=0x3f) => DcsParam,
        (DcsEntry, 0x40..=0x7e) => DcsPass,
        (DcsEntry, _) => DcsEntry,

        (DcsParam, 0x20..=0x2f) => DcsInt,
        (DcsParam, 0x3c..=0x3f) => DcsIgnore,
        (DcsParam, 0x40..=0x7e) => DcsPass,
        (DcsParam, _) => DcsParam,

        (DcsInt, 0x30..=0x3f) => DcsIgnore,
        (DcsInt, 0x40..=0x7e) => DcsPass,
        (DcsInt, _) => DcsInt,

        (DcsPass, 0x9c) => Ground,
        (DcsPass, _) => DcsPass,
        (DcsIgnore, _) => DcsIgnore,

        (Osc, 0x07) => Ground,
        (Osc, _) => Osc,
        (SosPmApc, _) => SosPmApc,
    }
}

fn is_control(b: u8) -> bool {
    b < 0x20 || b == 0x7f
}

impl SeqTracker {
    /// Advances over one byte; returns whether the byte goes to the parser.
    pub(crate) fn step(&mut self, b: u8) -> bool {
        let prev = self.st;
        let next = next_state(prev, b);
        if prev == Ground && next == Ground {
            self.ground_utf8(b);
            return true;
        }
        if prev == Osc && next == Osc && !is_control(b) {
            if self.osc_len >= MAX_OSC_BYTES {
                return false;
            }
            self.osc_len += 1;
        }
        self.st = next;
        match next {
            Ground => self.pending.clear(),
            Esc if b == 0x1b => {
                self.utf8.clear();
                self.utf8_need = 0;
                self.pending.clear();
                self.pending.push(b);
            },
            _ => {
                if next == Osc && prev != Osc {
                    self.osc_len = 0;
                }
                let content = matches!(prev, DcsPass | DcsIgnore | SosPmApc);
                if !content && !is_control(b) && self.pending.len() < MAX_PENDING {
                    self.pending.push(b);
                }
            },
        }
        true
    }

    fn ground_utf8(&mut self, b: u8) {
        if b < 0x80 {
            self.utf8.clear();
            self.utf8_need = 0;
            return;
        }
        // Continuation ranges of well-formed UTF-8 (Unicode 15, table 3-7):
        // the second byte is restricted after E0, ED, F0 and F4; vte, using
        // `str::from_utf8`, rejects anything else at once.
        let continues = match (self.utf8.as_slice(), b) {
            ([0xe0], 0xa0..=0xbf) | ([0xed], 0x80..=0x9f) => true,
            ([0xf0], 0x90..=0xbf) | ([0xf4], 0x80..=0x8f) => true,
            ([0xe0 | 0xed | 0xf0 | 0xf4], _) => false,
            (_, 0x80..=0xbf) => true,
            _ => false,
        };
        if self.utf8_need > 0 && continues {
            self.utf8.push(b);
            self.utf8_need -= 1;
            if self.utf8_need == 0 {
                self.utf8.clear();
            }
            return;
        }
        self.utf8.clear();
        self.utf8_need = match b {
            0xc2..=0xdf => 1,
            0xe0..=0xef => 2,
            0xf0..=0xf4 => 3,
            _ => 0,
        };
        if self.utf8_need > 0 {
            self.utf8.push(b);
        }
    }

    /// Bytes that bring a parser from ground state to this parser's state.
    pub(crate) fn held(&self) -> &[u8] {
        if self.st == Ground { &self.utf8 } else { &self.pending }
    }
}
