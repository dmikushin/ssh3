//! Differential round trip: the emulator that saw the program's output (A)
//! produces a resync; a second emulator (B) in some other state consumes it
//! and must end in A's state, cell by cell, including attributes, cursors,
//! modes, charsets, tabs, titles and keyboard stacks. Then both continue
//! with the rest of the recording and must stay equal.

mod common;

use common::{garbage, roundtrip, vt100_view, FIXTURES};
use ssh3_term::{Screen, Snapshot};

/// Cut points: 48 evenly spaced prefixes plus the whole recording.
fn cuts(len: usize) -> Vec<usize> {
    let mut v: Vec<usize> = (0..48).map(|i| i * len / 48).collect();
    v.push(len);
    v.dedup();
    v
}

#[test]
fn from_garbage_at_every_cut() {
    for &(name, bytes, cols, rows) in FIXTURES {
        for (i, k) in cuts(bytes.len()).into_iter().enumerate() {
            let tag = format!("{name}@{k}/garbage{}", i % 5);
            roundtrip(&tag, cols, rows, &bytes[..k], &garbage(i), &bytes[k..]);
        }
    }
}

/// What actually happens on the wire (SPEC §5): the client has received a
/// prefix of the same stream, possibly cut inside an escape sequence.
#[test]
fn from_earlier_prefix_of_the_same_stream() {
    for &(name, bytes, cols, rows) in FIXTURES {
        let c = cuts(bytes.len());
        for w in c.windows(2) {
            let (j, k) = (w[0], w[1]);
            let tag = format!("{name}: client at {j}, emulator at {k}");
            roundtrip(&tag, cols, rows, &bytes[..k], &bytes[..j], &bytes[k..]);
            // ... and with the client parser stuck in an unterminated OSC.
            let mut stuck = bytes[..j].to_vec();
            stuck.extend_from_slice(b"\x1b]0;");
            roundtrip(&format!("{tag} + ESC]0;"), cols, rows, &bytes[..k], &stuck, &bytes[k..]);
        }
    }
}

/// Byte cuts on both sides: the client stops in the middle of an escape
/// sequence, and the emulator generates the resync in the middle of one,
/// then both continue. `positions` picks the cut offsets.
fn byte_cuts(positions: impl Fn(&[u8]) -> Vec<usize>) {
    for &(name, bytes, cols, rows) in FIXTURES {
        for j in positions(bytes) {
            let tag = format!("{name}: client at byte {j}");
            roundtrip(&tag, cols, rows, bytes, &bytes[..j], b"");
            let tag = format!("{name}: emulator at byte {j}");
            roundtrip(&tag, cols, rows, &bytes[..j], &garbage(j), &bytes[j..]);
        }
    }
}

/// Every byte of fixtures up to 512 bytes; elsewhere every byte of eight
/// 16-byte windows spread over the recording (each window spans several
/// escape sequences in the recorded programs' output).
#[test]
fn byte_cuts_in_windows() {
    byte_cuts(|b| {
        if b.len() <= 512 {
            return (0..=b.len()).collect();
        }
        (0..8).flat_map(|w| {
            let start = w * (b.len() - 16) / 7;
            start..start + 16
        })
        .collect()
    });
}

/// Every byte of every fixture: ~36k cuts, ~35 s in release, ~5 min in a
/// debug build. Run on demand: `cargo test --release -p ssh3-term --test
/// roundtrip -- --ignored`.
#[test]
#[ignore = "exhaustive; byte_cuts_in_windows covers the same property"]
fn byte_cuts_exhaustive() {
    byte_cuts(|b| (0..=b.len()).collect());
}

fn text_and_cursor(s: &Snapshot) -> (Vec<String>, (u16, u16), bool) {
    use alacritty_terminal::term::cell::Flags;
    use alacritty_terminal::term::TermMode;
    let text = s
        .cells
        .iter()
        .map(|row| {
            let mut line = String::new();
            for cell in row {
                if cell.flags.intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER) {
                    if cell.flags.contains(Flags::LEADING_WIDE_CHAR_SPACER) {
                        line.push(' ');
                    }
                    continue;
                }
                line.push(if cell.c == '\t' { ' ' } else { cell.c });
                line.extend(cell.zerowidth().unwrap_or(&[]));
            }
            line.trim_end().to_owned()
        })
        .collect();
    let col = s.cursor.point.column.0 + s.cursor.input_needs_wrap as usize;
    let cursor = (s.cursor.point.line.0 as u16, col as u16);
    (text, cursor, s.mode.contains(TermMode::ALT_SCREEN))
}

/// vt100 0.18 ignores charset designation (measured against tmux, see the
/// crate docs), so where the redraw writes a raw character through the DEC
/// line-drawing set (to keep the REP character), vt100 shows the letter
/// and alacritty the glyph it stands for. Those cells are accepted.
fn same_view(want: &(Vec<String>, (u16, u16), bool), got: &(Vec<String>, (u16, u16), bool)) -> bool {
    use alacritty_terminal::vte::ansi::StandardCharset;
    let drawing = StandardCharset::SpecialCharacterAndLineDrawing;
    want.1 == got.1
        && want.2 == got.2
        && want.0.len() == got.0.len()
        && want.0.iter().zip(&got.0).all(|(a, b)| {
            a.chars().count() == b.chars().count()
                && a.chars().zip(b.chars()).all(|(x, y)| x == y || drawing.map(y) == x)
        })
}

/// External oracle: the resync, fed to the independent vt100 emulator,
/// shows the same text, cursor and screen as alacritty after the full
/// recording. vt100 does not implement origin mode positioning the same way
/// nor zero-width joiners identically, so text and cursor are compared, not
/// attributes.
#[test]
fn resync_through_independent_emulator() {
    let mut failures = Vec::new();
    for &(name, bytes, cols, rows) in FIXTURES {
        for k in cuts(bytes.len()) {
            let mut a = Screen::new(cols, rows);
            a.feed(&bytes[..k]);
            let want = text_and_cursor(&a.snapshot());
            let mut feed = garbage(k);
            feed.extend_from_slice(&a.resync());
            let got = vt100_view(&feed, cols, rows);
            if !same_view(&want, &got) {
                failures.push(format!("{name}@{k}:\n alacritty {want:?}\n vt100     {got:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{} mismatches:\n{}", failures.len(), failures.join("\n"));
}
