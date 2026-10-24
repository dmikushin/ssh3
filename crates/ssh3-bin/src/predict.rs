//! Predictive local echo (SPEC §5.2), a port of mosh's `PredictionEngine`
//! (src/frontend/terminaloverlay.{h,cc} in mobile-shell/mosh; line numbers
//! below are from its master branch).
//!
//! The client keeps an [`ssh3_term::Screen`] fed with every byte of the
//! server's pty output, so it knows what the local terminal shows. Keystrokes
//! become predictions: overlay cells (printable characters, backspace) and a
//! predicted cursor (characters, arrows). Predictions belong to epochs; an
//! epoch is shown only once one of its predictions was confirmed by the
//! server's output, and every keystroke whose effect cannot be predicted
//! (Enter, control characters, escape sequences) starts a new epoch. So the
//! first keystroke after Enter — a password prompt, an editor command — is
//! never displayed before the server proved that it echoes.
//!
//! What differs from mosh, and why:
//! - mosh judges a prediction once the server acknowledged the frame that
//!   carried the keystroke plus 50 ms (`late_ack`, terminaloverlay.cc:88).
//!   There is no such ordered acknowledgement here (keystrokes and output
//!   travel on different streams), so a prediction that the mirror already
//!   shows is confirmed at once, and a mismatch counts only after
//!   `judge_after` (2·SRTT + 100 ms) from the keystroke.
//! - No predictions on the alternate screen or in any state the overlay
//!   cannot be removed from by repainting cells
//!   ([`ssh3_term::Screen::overlay_obstacle`]); none in the last column
//!   (mosh makes those tentative, terminaloverlay.cc:724-728, we skip them).
//! - Only mosh's Adaptive, Always and Never modes; no overwrite mode.

use std::time::{Duration, Instant};

use ssh3_term::{CellView, Paint, Screen};
use unicode_width::UnicodeWidthChar;

/// terminaloverlay.h:215-225.
const SRTT_TRIGGER_LOW: Duration = Duration::from_millis(20);
const SRTT_TRIGGER_HIGH: Duration = Duration::from_millis(30);
const FLAG_TRIGGER_LOW: Duration = Duration::from_millis(50);
const FLAG_TRIGGER_HIGH: Duration = Duration::from_millis(80);
const GLITCH_THRESHOLD: Duration = Duration::from_millis(250);
const GLITCH_REPAIR_COUNT: u32 = 10;
const GLITCH_REPAIR_MININTERVAL: Duration = Duration::from_millis(150);
const GLITCH_FLAG_THRESHOLD: Duration = Duration::from_millis(5000);
/// Slack for the remote program and the network beyond 2·SRTT before a
/// prediction the mirror contradicts counts as wrong.
const JUDGE_SLACK: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preference {
    Always,
    Never,
    Adaptive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Validity {
    Pending,
    Correct,
    CorrectNoCredit,
    IncorrectOrExpired,
    Inactive,
}

/// terminaloverlay.h:57-84.
#[derive(Clone, Debug)]
struct Conditional {
    /// Until then a mismatch is not yet wrong (mosh `expiration_frame`).
    judge_after: Instant,
    /// ... and not before the server was heard from after this (it then
    /// had the keystroke): a silent server keeps predictions pending, as
    /// mosh's missing frame ack does, so the glitch triggers fire.
    heard_after: Instant,
    col: u16,
    active: bool,
    tentative_until_epoch: u64,
    prediction_time: Instant,
}

impl Conditional {
    fn new(now: Instant, col: u16, tentative: u64) -> Self {
        Conditional { judge_after: now, heard_after: now, col, active: false, tentative_until_epoch: tentative, prediction_time: now }
    }
    fn tentative(&self, confirmed_epoch: u64) -> bool {
        self.tentative_until_epoch > confirmed_epoch
    }
    fn reset(&mut self) {
        self.tentative_until_epoch = u64::MAX;
        self.active = false;
    }
    fn expire(&mut self, judge: Judge, now: Instant) {
        self.judge_after = judge.after;
        self.heard_after = judge.heard_after;
        self.prediction_time = now;
    }
    fn late(&self, now: Instant, heard: Instant) -> bool {
        now >= self.judge_after && heard >= self.heard_after
    }
}

/// When a prediction made now may be judged wrong.
#[derive(Clone, Copy, Debug)]
struct Judge {
    after: Instant,
    heard_after: Instant,
}

#[derive(Clone, Debug)]
struct CursorMove {
    c: Conditional,
    row: u16,
}

impl CursorMove {
    /// terminaloverlay.cc:114-135.
    fn validity(&self, fb: &Screen, now: Instant, heard: Instant) -> Validity {
        if !self.c.active {
            return Validity::Inactive;
        }
        let (cols, rows) = fb.size();
        if self.row >= rows || self.c.col >= cols {
            return Validity::IncorrectOrExpired;
        }
        if fb.cursor() == (self.row, self.c.col) {
            return Validity::Correct;
        }
        if self.c.late(now, heard) { Validity::IncorrectOrExpired } else { Validity::Pending }
    }
}

#[derive(Clone, Debug)]
struct OverlayCell {
    c: Conditional,
    replacement: CellView,
    unknown: bool,
    /// No credit for predictions matching what was there (cc:100-110).
    original_contents: Vec<CellView>,
}

impl OverlayCell {
    fn reset(&mut self) {
        self.unknown = false;
        self.original_contents.clear();
        self.c.reset();
    }
    /// terminaloverlay.h:122-131.
    fn reset_with_orig(&mut self) {
        if !self.c.active || self.unknown {
            self.reset();
            return;
        }
        self.original_contents.push(self.replacement.clone());
        self.c.reset();
    }

    /// terminaloverlay.cc:72-112, with the mosh-specific wait replaced as in
    /// the module comment.
    fn validity(&self, fb: &Screen, row: u16, now: Instant, heard: Instant) -> Validity {
        if !self.c.active {
            return Validity::Inactive;
        }
        let (cols, rows) = fb.size();
        if row >= rows || self.c.col >= cols {
            return Validity::IncorrectOrExpired;
        }
        let late = self.c.late(now, heard);
        if self.unknown || self.replacement.is_blank() {
            return if late { Validity::CorrectNoCredit } else { Validity::Pending };
        }
        let current = fb.cell(row, self.c.col);
        if current.contents_match(&self.replacement) {
            if !self.original_contents.iter().any(|o| o.contents_match(&self.replacement)) {
                return Validity::Correct;
            }
            return if late { Validity::CorrectNoCredit } else { Validity::Pending };
        }
        if late { Validity::IncorrectOrExpired } else { Validity::Pending }
    }
}

#[derive(Clone, Debug)]
struct OverlayRow {
    row_num: u16,
    cells: Vec<OverlayCell>,
}

/// User keystrokes, classified as mosh's terminal parser does for
/// `new_user_byte` (cc:640-827).
#[derive(Debug, PartialEq)]
enum Action {
    Print(char),
    Execute(u8),
    EscDispatch,
    Csi(u8),
}

#[derive(Default)]
enum Lex {
    #[default]
    Ground,
    Esc,
    Csi,
    Utf8 { need: usize, acc: u32 },
}

#[derive(Default)]
struct Keys {
    state: Lex,
}

impl Keys {
    fn byte(&mut self, b: u8) -> Option<Action> {
        match std::mem::take(&mut self.state) {
            Lex::Ground => match b {
                0x1b => {
                    self.state = Lex::Esc;
                    None
                },
                0x00..=0x1f => Some(Action::Execute(b)),
                0x7f => Some(Action::Print('\x7f')),
                0x20..=0x7e => Some(Action::Print(b as char)),
                0xc0..=0xdf => self.start(1, b & 0x1f),
                0xe0..=0xef => self.start(2, b & 0x0f),
                0xf0..=0xf7 => self.start(3, b & 0x07),
                _ => Some(Action::Print(char::REPLACEMENT_CHARACTER)),
            },
            // ESC O x is application-mode cursor control: as CSI x
            // (cc:634-637).
            Lex::Esc if b == b'[' || b == b'O' => {
                self.state = Lex::Csi;
                None
            },
            Lex::Esc => Some(Action::EscDispatch),
            Lex::Csi => match b {
                0x20..=0x3f => {
                    self.state = Lex::Csi;
                    None
                },
                0x40..=0x7e => Some(Action::Csi(b)),
                0x1b => {
                    self.state = Lex::Esc;
                    None
                },
                _ => {
                    self.state = Lex::Csi;
                    Some(Action::Execute(b))
                },
            },
            Lex::Utf8 { need, acc } => {
                if b & 0xc0 != 0x80 {
                    return Some(Action::Print(char::REPLACEMENT_CHARACTER));
                }
                let acc = (acc << 6) | (b & 0x3f) as u32;
                if need == 1 {
                    Some(Action::Print(char::from_u32(acc).unwrap_or(char::REPLACEMENT_CHARACTER)))
                } else {
                    self.state = Lex::Utf8 { need: need - 1, acc };
                    None
                }
            },
        }
    }

    fn start(&mut self, need: usize, bits: u8) -> Option<Action> {
        self.state = Lex::Utf8 { need, acc: bits as u32 };
        None
    }
}

/// What the overlay shows now: cells and, if predicted, the cursor.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Frame {
    pub cells: Vec<(u16, u16, char, bool)>,
    pub cursor: Option<(u16, u16)>,
}

pub struct PredictionEngine {
    keys: Keys,
    overlays: Vec<OverlayRow>,
    cursors: Vec<CursorMove>,
    prediction_epoch: u64,
    confirmed_epoch: u64,
    flagging: bool,
    srtt_trigger: bool,
    glitch_trigger: u32,
    last_quick_confirmation: Option<Instant>,
    send_interval: Duration,
    srtt: Duration,
    judge_delay: Duration,
    /// When the server was last heard from (acks, probe replies).
    heard: Instant,
    last_size: (u16, u16),
    preference: Preference,
    /// The replacement renditions of predicted cells (kept per cell).
    renditions: std::collections::HashMap<(u16, u16), ssh3_term::Rendition>,
}

impl PredictionEngine {
    pub fn new(preference: Preference) -> Self {
        PredictionEngine {
            keys: Keys::default(),
            overlays: Vec::new(),
            cursors: Vec::new(),
            prediction_epoch: 1,
            confirmed_epoch: 0,
            flagging: false,
            srtt_trigger: false,
            glitch_trigger: 0,
            last_quick_confirmation: None,
            send_interval: Duration::from_millis(250),
            srtt: Duration::from_millis(500),
            judge_delay: Duration::from_millis(500),
            heard: Instant::now(),
            last_size: (0, 0),
            preference,
            renditions: Default::default(),
        }
    }

    /// From the carrier's smoothed RTT: mosh's send interval (SRTT/2 within
    /// 20..250 ms, transportsender-impl.h) drives the triggers, and a
    /// mismatch counts after 2·SRTT + slack.
    pub fn set_srtt(&mut self, srtt: Duration) {
        self.send_interval = (srtt / 2).clamp(Duration::from_millis(20), Duration::from_millis(250));
        self.judge_delay = srtt * 2 + JUDGE_SLACK;
        self.srtt = srtt;
    }

    pub fn set_heard(&mut self, at: Instant) {
        self.heard = at;
    }

    fn judge(&self, now: Instant) -> Judge {
        Judge { after: now + self.judge_delay, heard_after: now + self.srtt / 2 }
    }

    /// cc:877-892.
    pub fn active(&self) -> bool {
        !self.cursors.is_empty() || self.overlays.iter().any(|r| r.cells.iter().any(|c| c.c.active))
    }

    fn shown(&self) -> bool {
        self.preference != Preference::Never && (self.srtt_trigger || self.glitch_trigger > 0 || self.preference == Preference::Always)
    }

    /// When the timing triggers next need a look (h:283-305).
    pub fn wait_time(&self) -> Option<Duration> {
        let timing = !(self.glitch_trigger > 0 && self.flagging);
        (timing && self.active()).then_some(Duration::from_millis(50))
    }

    /// cc:393-400.
    pub fn reset(&mut self) {
        self.cursors.clear();
        self.overlays.clear();
        self.renditions.clear();
        self.become_tentative();
    }

    fn become_tentative(&mut self) {
        self.prediction_epoch += 1;
    }

    /// cc:367-391.
    fn kill_epoch(&mut self, epoch: u64, fb: &Screen, now: Instant) {
        self.cursors.retain(|c| !c.c.tentative(epoch - 1));
        let (row, col) = fb.cursor();
        let mut c = CursorMove { c: Conditional::new(now, col, self.prediction_epoch), row };
        c.c.expire(self.judge(now), now);
        c.c.active = true;
        self.cursors.push(c);
        for r in &mut self.overlays {
            for cell in &mut r.cells {
                if cell.c.tentative(epoch - 1) {
                    cell.reset();
                }
            }
        }
        self.become_tentative();
    }

    /// cc:402-417.
    fn init_cursor(&mut self, fb: &Screen, now: Instant) {
        let judge = self.judge(now);
        if self.cursors.is_empty() {
            let (row, col) = fb.cursor();
            let mut c = CursorMove { c: Conditional::new(now, col, self.prediction_epoch), row };
            c.c.expire(judge, now);
            c.c.active = true;
            self.cursors.push(c);
        } else if self.cursor().c.tentative_until_epoch != self.prediction_epoch {
            let (row, col) = (self.cursor().row, self.cursor().c.col);
            let mut c = CursorMove { c: Conditional::new(now, col, self.prediction_epoch), row };
            c.c.expire(judge, now);
            c.c.active = true;
            self.cursors.push(c);
        }
    }

    fn cursor(&mut self) -> &mut CursorMove {
        self.cursors.last_mut().expect("init_cursor first")
    }

    fn row_index(&mut self, row_num: u16, cols: u16, now: Instant) -> usize {
        if let Some(i) = self.overlays.iter().position(|r| r.row_num == row_num) {
            return i;
        }
        let epoch = self.prediction_epoch;
        let blank = CellView { ch: ' ', combining: false, wide: false, rendition: BLANK.with(|b| b.clone()) };
        let cells = (0..cols)
            .map(|i| OverlayCell { c: Conditional::new(now, i, epoch), replacement: blank.clone(), unknown: false, original_contents: Vec::new() })
            .collect();
        self.overlays.push(OverlayRow { row_num, cells });
        self.overlays.len() - 1
    }

    /// cc:419-595: judge predictions against the mirror.
    pub fn cull(&mut self, fb: &Screen, now: Instant) {
        if self.preference == Preference::Never {
            return;
        }
        if self.last_size != fb.size() {
            self.last_size = fb.size();
            self.reset();
        }
        if self.send_interval > SRTT_TRIGGER_HIGH {
            self.srtt_trigger = true;
        } else if self.srtt_trigger && self.send_interval <= SRTT_TRIGGER_LOW && !self.active() {
            self.srtt_trigger = false;
        }
        if self.send_interval > FLAG_TRIGGER_HIGH {
            self.flagging = true;
        } else if self.send_interval <= FLAG_TRIGGER_LOW {
            self.flagging = false;
        }
        if self.glitch_trigger > GLITCH_REPAIR_COUNT {
            self.flagging = true;
        }
        let (_, rows) = fb.size();
        self.overlays.retain(|r| r.row_num < rows);
        let mut i = 0;
        while i < self.overlays.len() {
            let row_num = self.overlays[i].row_num;
            for j in 0..self.overlays[i].cells.len() {
                let v = self.overlays[i].cells[j].validity(fb, row_num, now, self.heard);
                match v {
                    Validity::IncorrectOrExpired => {
                        let cell = &self.overlays[i].cells[j];
                        if cell.c.tentative(self.confirmed_epoch) {
                            let e = cell.c.tentative_until_epoch;
                            self.kill_epoch(e, fb, now);
                        } else {
                            self.reset();
                            return;
                        }
                    },
                    Validity::Correct | Validity::CorrectNoCredit => {
                        if v == Validity::Correct {
                            let cell = &self.overlays[i].cells[j];
                            if cell.c.tentative_until_epoch > self.confirmed_epoch {
                                self.confirmed_epoch = cell.c.tentative_until_epoch;
                            }
                            let quick = now.saturating_duration_since(cell.c.prediction_time) < GLITCH_THRESHOLD;
                            let spaced = self.last_quick_confirmation.is_none_or(|t| now.saturating_duration_since(t) >= GLITCH_REPAIR_MININTERVAL);
                            if quick && self.glitch_trigger > 0 && spaced {
                                self.glitch_trigger -= 1;
                                self.last_quick_confirmation = Some(now);
                            }
                            // Match the rest of the row to the actual
                            // renditions (cc:534-540).
                            let actual = fb.cell(row_num, self.overlays[i].cells[j].c.col).rendition;
                            for k in j..self.overlays[i].cells.len() {
                                self.overlays[i].cells[k].replacement.rendition = actual.clone();
                            }
                        }
                        self.overlays[i].cells[j].reset();
                    },
                    Validity::Pending => {
                        let age = now.saturating_duration_since(self.overlays[i].cells[j].c.prediction_time);
                        if age >= GLITCH_FLAG_THRESHOLD {
                            self.glitch_trigger = GLITCH_REPAIR_COUNT * 2;
                        } else if age >= GLITCH_THRESHOLD && self.glitch_trigger < GLITCH_REPAIR_COUNT {
                            self.glitch_trigger = GLITCH_REPAIR_COUNT;
                        }
                    },
                    Validity::Inactive => {},
                }
            }
            i += 1;
        }
        if let Some(last) = self.cursors.last()
            && last.validity(fb, now, self.heard) == Validity::IncorrectOrExpired
        {
            self.reset();
            return;
        }
        let heard = self.heard;
        self.cursors.retain(|c| c.validity(fb, now, heard) == Validity::Pending);
    }

    /// cc:621-828: a keystroke typed by the user.
    pub fn new_user_byte(&mut self, b: u8, fb: &Screen, now: Instant) {
        if self.preference == Preference::Never {
            return;
        }
        self.cull(fb, now);
        let Some(act) = self.keys.byte(b) else { return };
        // Nothing is predicted where the overlay could not be removed again.
        if fb.overlay_obstacle().is_some() {
            self.reset();
            return;
        }
        let judge = self.judge(now);
        let (cols, _) = fb.size();
        match act {
            Action::Print('\x7f') => {
                self.init_cursor(fb, now);
                let (row, col) = (self.cursor().row, self.cursor().c.col);
                let ri = self.row_index(row, cols, now);
                if col > 0 {
                    let col = col - 1;
                    self.cursor().c.col = col;
                    self.cursor().c.expire(judge, now);
                    for i in col..cols {
                        let next_active = (i + 2 < cols).then(|| {
                            let n = &self.overlays[ri].cells[i as usize + 1];
                            (n.c.active, n.unknown, n.replacement.clone())
                        });
                        let epoch = self.prediction_epoch;
                        let actual = fb.cell(row, i);
                        let next_actual = (i + 1 < cols).then(|| fb.cell(row, i + 1));
                        let cell = &mut self.overlays[ri].cells[i as usize];
                        cell.reset_with_orig();
                        cell.c.active = true;
                        cell.c.tentative_until_epoch = epoch;
                        cell.c.expire(judge, now);
                        cell.original_contents.push(actual);
                        match next_active {
                            Some((true, true, _)) => cell.unknown = true,
                            Some((true, false, rep)) => {
                                cell.unknown = false;
                                cell.replacement = rep;
                            },
                            Some((false, _, _)) => {
                                cell.unknown = false;
                                cell.replacement = next_actual.expect("i + 2 < cols");
                            },
                            None => cell.unknown = true,
                        }
                    }
                }
            },
            Action::Print(ch) if (ch as u32) < 0x20 || ch.width() != Some(1) => self.become_tentative(),
            Action::Print(ch) => {
                self.init_cursor(fb, now);
                let (row, col) = (self.cursor().row, self.cursor().c.col);
                if col + 1 >= cols {
                    // The last column is not predicted (module comment).
                    self.become_tentative();
                    return;
                }
                let ri = self.row_index(row, cols, now);
                let epoch = self.prediction_epoch;
                // The insert: cells right of the cursor shift (cc:730-756).
                for i in (col + 1..cols).rev() {
                    let prev = &self.overlays[ri].cells[i as usize - 1];
                    let (p_active, p_unknown, p_rep) = (prev.c.active, prev.unknown, prev.replacement.clone());
                    let actual = fb.cell(row, i);
                    let prev_actual = fb.cell(row, i - 1);
                    let cell = &mut self.overlays[ri].cells[i as usize];
                    cell.reset_with_orig();
                    cell.c.active = true;
                    cell.c.tentative_until_epoch = epoch;
                    cell.c.expire(judge, now);
                    cell.original_contents.push(actual);
                    if i == cols - 1 {
                        cell.unknown = true;
                    } else if p_active {
                        cell.unknown = p_unknown;
                        if !p_unknown {
                            cell.replacement = p_rep;
                        }
                    } else {
                        cell.unknown = false;
                        cell.replacement = prev_actual;
                    }
                }
                // Renditions: the pen, or those of the character to the
                // left (cc:763-774).
                let mut rendition = fb.pen();
                if col > 0 {
                    let prev = &self.overlays[ri].cells[col as usize - 1];
                    rendition = if prev.c.active && !prev.unknown { prev.replacement.rendition.clone() } else { fb.cell(row, col - 1).rendition };
                }
                let actual = fb.cell(row, col);
                let cell = &mut self.overlays[ri].cells[col as usize];
                cell.reset_with_orig();
                cell.c.active = true;
                cell.c.tentative_until_epoch = epoch;
                cell.c.expire(judge, now);
                cell.unknown = false;
                cell.replacement = CellView { ch, combining: false, wide: false, rendition };
                cell.original_contents.push(actual);
                self.cursor().c.expire(judge, now);
                self.cursor().c.col += 1;
            },
            Action::Execute(0x0d) => {
                self.become_tentative();
                self.newline_carriage_return(fb, now);
            },
            Action::Execute(_) | Action::EscDispatch => self.become_tentative(),
            Action::Csi(b'C') => {
                self.init_cursor(fb, now);
                if self.cursor().c.col + 1 < cols {
                    self.cursor().c.col += 1;
                    self.cursor().c.expire(judge, now);
                }
            },
            Action::Csi(b'D') => {
                self.init_cursor(fb, now);
                if self.cursor().c.col > 0 {
                    self.cursor().c.col -= 1;
                    self.cursor().c.expire(judge, now);
                }
            },
            Action::Csi(_) => self.become_tentative(),
        }
    }

    /// cc:830-863.
    fn newline_carriage_return(&mut self, fb: &Screen, now: Instant) {
        let judge = self.judge(now);
        self.init_cursor(fb, now);
        let (cols, rows) = fb.size();
        self.cursor().c.col = 0;
        let row = self.cursor().row;
        if row == rows - 1 {
            let ri = self.row_index(row, cols, now);
            let epoch = self.prediction_epoch;
            for cell in &mut self.overlays[ri].cells {
                cell.c.active = true;
                cell.c.tentative_until_epoch = epoch;
                cell.c.expire(judge, now);
                cell.replacement.ch = ' ';
            }
        } else {
            self.cursor().row += 1;
        }
    }

    /// cc:43-70, 137-153, 343-365: the overlay to show on top of the
    /// mirror. Cells equal to the mirror (and not flagged) are left out.
    pub fn frame(&self, fb: &Screen) -> Frame {
        let mut f = Frame::default();
        if !self.shown() {
            return f;
        }
        let (cols, rows) = fb.size();
        for c in &self.cursors {
            if c.c.active && !c.c.tentative(self.confirmed_epoch) && c.row < rows && c.c.col < cols {
                f.cursor = Some((c.row, c.c.col));
            }
        }
        for r in &self.overlays {
            if r.row_num >= rows {
                continue;
            }
            for cell in &r.cells {
                if !cell.c.active || cell.c.tentative(self.confirmed_epoch) || cell.c.col + 1 >= cols {
                    continue;
                }
                let actual = fb.cell(r.row_num, cell.c.col);
                if actual.wide {
                    continue;
                }
                let mut flag = self.flagging;
                if cell.replacement.is_blank() && actual.is_blank() {
                    flag = false;
                }
                if cell.unknown {
                    if flag && !actual.combining && !actual.wide {
                        f.cells.push((r.row_num, cell.c.col, actual.ch, true));
                    }
                    continue;
                }
                if actual != cell.replacement || flag {
                    f.cells.push((r.row_num, cell.c.col, cell.replacement.ch, flag));
                }
            }
        }
        f
    }

    /// The renditions a frame cell is painted with.
    pub fn paint_of(&self, fb: &Screen, cell: &(u16, u16, char, bool)) -> Paint {
        let (row, col, ch, underline) = *cell;
        let rendition = self
            .overlays
            .iter()
            .find(|r| r.row_num == row)
            .and_then(|r| r.cells.get(col as usize))
            .filter(|c| c.c.active && !c.unknown)
            .map_or_else(|| fb.cell(row, col).rendition, |c| c.replacement.rendition.clone());
        Paint::Glyph { ch, rendition, underline }
    }
}

thread_local! {
    /// Renditions of a default cell, for fresh overlay rows.
    static BLANK: ssh3_term::Rendition = Screen::new(2, 2).cell(0, 0).rendition;
}

/// The local terminal as seen by the overlay: the mirror plus whatever the
/// overlay painted on top. Every byte for the terminal goes through here.
pub struct Display {
    pub mirror: Screen,
    pub engine: PredictionEngine,
    /// Cells currently painted with a prediction, and whether the cursor is
    /// away from the mirror's.
    shown: Vec<(u16, u16)>,
    cursor_moved: bool,
    last: Frame,
}

impl Display {
    pub fn new(mirror: Screen, engine: PredictionEngine) -> Self {
        Display { mirror, engine, shown: Vec::new(), cursor_moved: false, last: Frame::default() }
    }

    /// Bytes that remove the overlay (the terminal then shows the mirror).
    fn unpaint(&mut self) -> Vec<u8> {
        if self.shown.is_empty() && !self.cursor_moved {
            return Vec::new();
        }
        let cells: Vec<_> = self.shown.drain(..).map(|(l, c)| (l, c, Paint::Mirror)).collect();
        self.cursor_moved = false;
        self.last = Frame::default();
        // The mirror has not changed since the paint (only server output
        // changes it, and that is fed after this), so the paint conditions
        // still hold.
        self.mirror.paint(&cells, self.mirror.cursor()).expect("overlay was painted in this same state")
    }

    /// Bytes that bring the terminal from its current overlay to the
    /// engine's current frame.
    fn repaint(&mut self) -> Vec<u8> {
        let frame = self.engine.frame(&self.mirror);
        if frame == self.last {
            return Vec::new();
        }
        let wanted: Vec<(u16, u16)> = frame.cells.iter().map(|c| (c.0, c.1)).collect();
        let cursor = frame.cursor.unwrap_or(self.mirror.cursor());
        let moved = cursor != self.mirror.cursor();
        let mut cells: Vec<(u16, u16, Paint)> = self.shown.iter().filter(|p| !wanted.contains(p)).map(|&(l, c)| (l, c, Paint::Mirror)).collect();
        cells.extend(frame.cells.iter().map(|c| (c.0, c.1, self.engine.paint_of(&self.mirror, c))));
        match self.mirror.paint(&cells, cursor) {
            Some(b) => {
                self.shown = wanted;
                self.cursor_moved = moved;
                self.last = frame;
                b
            },
            None => {
                // This state or a cell rules the overlay out: whatever is
                // still painted goes (the mirror is unchanged since it was
                // painted), and the predictions with it.
                self.engine.reset();
                self.unpaint()
            },
        }
    }

    /// Server output: bytes for the terminal.
    pub fn output(&mut self, bytes: &[u8], now: Instant) -> Vec<u8> {
        let mut out = self.unpaint();
        out.extend_from_slice(bytes);
        self.mirror.feed(bytes);
        self.engine.cull(&self.mirror, now);
        out.extend(self.repaint());
        out
    }

    /// Keystrokes (already sent to the server): bytes for the terminal.
    pub fn input(&mut self, bytes: &[u8], now: Instant) -> Vec<u8> {
        for &b in bytes {
            self.engine.new_user_byte(b, &self.mirror, now);
        }
        self.repaint()
    }

    /// Timers (glitch triggers, mismatches past their judging time).
    pub fn tick(&mut self, now: Instant) -> Vec<u8> {
        self.engine.cull(&self.mirror, now);
        self.repaint()
    }

    /// Local window size changed: the overlay goes, predictions reset.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Vec<u8> {
        let out = self.unpaint();
        self.mirror.resize(cols, rows);
        self.engine.reset();
        out
    }

    /// The session's output ended: the overlay goes.
    pub fn finish(&mut self) -> Vec<u8> {
        self.unpaint()
    }

    pub fn overlay_shown(&self) -> bool {
        !self.shown.is_empty() || self.cursor_moved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Display plus the client terminal it drives (another emulator fed
    /// every byte the Display emits), on a test clock.
    struct Rig {
        d: Display,
        term: Screen,
        now: Instant,
    }

    impl Rig {
        fn new(pref: Preference, srtt_ms: u64, prompt: &[u8]) -> Self {
            let mut mirror = Screen::new(80, 24);
            mirror.feed(prompt);
            let mut term = Screen::new(80, 24);
            term.feed(prompt);
            let mut e = PredictionEngine::new(pref);
            e.set_srtt(Duration::from_millis(srtt_ms));
            let now = Instant::now();
            e.set_heard(now);
            Rig { d: Display::new(mirror, e), term, now }
        }
        fn at(&mut self, ms: u64) {
            self.now += Duration::from_millis(ms);
        }
        /// The server is heard from now (acks of the keystrokes).
        fn heard(&mut self) {
            self.d.engine.set_heard(self.now);
        }
        fn key(&mut self, k: &[u8]) {
            let b = self.d.input(k, self.now);
            self.term.feed(&b);
        }
        fn out(&mut self, o: &[u8]) {
            self.heard();
            let b = self.d.output(o, self.now);
            self.term.feed(&b);
        }
        fn tick(&mut self) {
            let b = self.d.tick(self.now);
            self.term.feed(&b);
        }
        fn shows(&self, line: u16, col: u16) -> char {
            self.term.cell(line, col).ch
        }
        /// Without an overlay the terminal is exactly the mirror.
        fn assert_mirror(&self) {
            assert!(!self.d.overlay_shown(), "overlay still shown");
            let norm = |mut s: ssh3_term::Snapshot| {
                if s.unknown_private_modes.get(&2026) == Some(&false) {
                    s.unknown_private_modes.remove(&2026);
                }
                s
            };
            let diff = norm(self.d.mirror.snapshot()).diff_with(&norm(self.term.snapshot()), false);
            assert!(diff.is_empty(), "terminal differs from the mirror:\n{}", diff.join("\n"));
        }
        /// The first keystroke of an epoch is confirmed by the echo.
        fn confirm_first(&mut self, ch: u8) {
            self.key(&[ch]);
            assert!(!self.d.overlay_shown(), "first keystroke of an epoch shown before confirmation");
            self.at(200);
            self.out(&[ch]);
            self.assert_mirror();
        }
    }

    #[test]
    fn typed_text_is_shown_then_confirmed() {
        let mut r = Rig::new(Preference::Adaptive, 200, b"$ ");
        r.confirm_first(b'a');
        r.at(50);
        r.key(b"b");
        assert_eq!(r.shows(0, 3), 'b', "prediction not shown");
        r.key(b"c");
        assert_eq!(r.shows(0, 4), 'c');
        assert_eq!(r.term.cursor(), (0, 5), "predicted cursor");
        r.at(200);
        r.out(b"bc");
        r.assert_mirror();
        assert_eq!((r.shows(0, 3), r.shows(0, 4)), ('b', 'c'));
    }

    #[test]
    fn backspace_and_arrows_are_predicted() {
        let mut r = Rig::new(Preference::Adaptive, 200, b"$ ");
        r.confirm_first(b'a');
        r.key(b"xy");
        assert_eq!((r.shows(0, 3), r.shows(0, 4)), ('x', 'y'));
        r.key(b"\x7f");
        assert_eq!(r.shows(0, 4), ' ', "backspace not predicted");
        assert_eq!(r.term.cursor(), (0, 4));
        r.key(b"\x1b[D");
        assert_eq!(r.term.cursor(), (0, 3), "left arrow not predicted");
        r.key(b"\x1bOC");
        assert_eq!(r.term.cursor(), (0, 4), "application-mode right arrow not predicted");
        // The echo of a shell: x, y, backspace erase, cursor moves.
        r.at(200);
        r.out(b"xy\x08 \x08\x08\x1b[C");
        r.assert_mirror();
    }

    #[test]
    fn mismatch_is_undone_after_the_judging_time() {
        let mut r = Rig::new(Preference::Adaptive, 200, b"$ ");
        r.confirm_first(b'a');
        r.key(b"b");
        assert_eq!(r.shows(0, 3), 'b');
        // The program answers with something else.
        r.at(200);
        r.out(b"B");
        assert_eq!(r.shows(0, 3), 'b', "a mismatch before the judging time is still pending");
        r.at(400);
        r.heard();
        r.tick();
        r.assert_mirror();
        assert_eq!(r.shows(0, 3), 'B');
    }

    #[test]
    fn nothing_is_shown_at_a_password_prompt() {
        let mut r = Rig::new(Preference::Adaptive, 200, b"$ ");
        r.confirm_first(b's');
        r.key(b"\r");
        r.at(200);
        r.out(b"\r\nPassword: ");
        for &k in b"secret" {
            r.at(100);
            r.key(&[k]);
            assert!(!r.d.overlay_shown(), "password keystroke {:?} shown", k as char);
            r.heard();
            r.tick();
        }
        r.at(2000);
        r.heard();
        r.tick();
        r.assert_mirror();
        assert_eq!(r.term.cursor(), (1, 10));
    }

    #[test]
    fn editor_command_after_escape_is_not_shown() {
        let mut r = Rig::new(Preference::Adaptive, 200, b"$ ");
        r.confirm_first(b'i');
        r.key(b"\x1b");
        r.key(b"j");
        r.key(b"k");
        assert!(!r.d.overlay_shown(), "keystrokes after ESC shown");
    }

    #[test]
    fn alternate_screen_gets_no_predictions() {
        let mut r = Rig::new(Preference::Always, 200, b"$ ");
        r.out(b"\x1b[?1049h\x1b[H~\r\n~");
        r.key(b"a");
        r.at(200);
        r.out(b"a");
        r.key(b"bcd");
        assert!(!r.d.overlay_shown(), "prediction on the alternate screen");
        r.assert_mirror();
    }

    #[test]
    fn never_predicts_nothing() {
        let mut r = Rig::new(Preference::Never, 200, b"$ ");
        r.key(b"a");
        r.at(200);
        r.out(b"a");
        r.key(b"bcd");
        assert!(!r.d.overlay_shown());
        r.assert_mirror();
    }

    #[test]
    fn adaptive_with_a_fast_link_waits_for_a_glitch() {
        let mut r = Rig::new(Preference::Adaptive, 5, b"$ ");
        r.d.engine.cull(&r.d.mirror, r.now);
        r.key(b"a");
        r.at(10);
        r.out(b"a");
        r.key(b"b");
        assert!(!r.d.overlay_shown(), "shown on a 5 ms link");
        // The server goes silent: the prediction stays pending, and after
        // 250 ms the glitch trigger shows it (terminaloverlay.cc:548-555).
        r.at(300);
        r.tick();
        assert_eq!(r.shows(0, 3), 'b', "glitch trigger did not show the prediction");
        r.out(b"b");
        r.assert_mirror();
    }

    #[test]
    fn slow_links_underline_predictions() {
        let mut r = Rig::new(Preference::Adaptive, 200, b"$ ");
        r.confirm_first(b'a');
        r.key(b"b");
        let mut u = Screen::new(80, 24);
        u.feed(b"\x1b[4mb");
        assert_eq!(r.term.cell(0, 3), u.cell(0, 0), "prediction not underlined at 200 ms SRTT");
    }

    #[test]
    fn resize_removes_the_overlay() {
        let mut r = Rig::new(Preference::Adaptive, 200, b"$ ");
        r.confirm_first(b'a');
        r.key(b"bc");
        assert!(r.d.overlay_shown());
        let b = r.d.resize(80, 24);
        r.term.feed(&b);
        r.assert_mirror();
    }

    #[test]
    fn last_column_is_not_predicted() {
        let mut r = Rig::new(Preference::Adaptive, 200, b"\x1b[1;79H");
        r.confirm_first(b'a');
        r.key(b"b");
        assert!(!r.d.overlay_shown(), "prediction into the last column");
    }
}
