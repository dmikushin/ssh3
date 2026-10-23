#![allow(dead_code)]
//! Shared fixtures and the round-trip check.

use ssh3_term::{max_resync_len, Screen};

/// Recorded program output (tests/fixtures, made by record.py in a pty of
/// the given size) and synthetic sequences.
pub const FIXTURES: &[(&str, &[u8], u16, u16)] = &[
    ("vim", include_bytes!("../fixtures/vim.bin"), 100, 30),
    ("nvim", include_bytes!("../fixtures/nvim.bin"), 120, 35),
    ("less", include_bytes!("../fixtures/less.bin"), 80, 24),
    ("htop", include_bytes!("../fixtures/htop.bin"), 132, 40),
    ("top", include_bytes!("../fixtures/top.bin"), 100, 30),
    ("mc_acs", include_bytes!("../fixtures/mc_acs.bin"), 100, 30),
    ("ls_color", include_bytes!("../fixtures/ls_color.bin"), 100, 30),
    ("seq_scroll", include_bytes!("../fixtures/seq_scroll.bin"), 80, 24),
    ("sgr", include_bytes!("../fixtures/sgr.bin"), 80, 24),
    ("wide", include_bytes!("../fixtures/wide.bin"), 80, 24),
    ("modes", include_bytes!("../fixtures/modes.bin"), 80, 24),
    ("origin", include_bytes!("../fixtures/origin.bin"), 80, 24),
    ("altscreen", include_bytes!("../fixtures/altscreen.bin"), 80, 24),
    ("pending_wrap", include_bytes!("../fixtures/pending_wrap.bin"), 80, 24),
    ("sync_open", include_bytes!("../fixtures/sync_open.bin"), 80, 24),
];

/// A client terminal left in a hostile state: alternate screen, regions,
/// origin/insert mode, autowrap off, line-drawing charset shifted in, custom
/// tabs, changed palette, titles, kitty keyboard modes, an open hyperlink,
/// a saved cursor — and, last, an unterminated sequence of kind `tail`.
pub fn garbage(tail: usize) -> Vec<u8> {
    let mut g = Vec::new();
    g.extend_from_slice(b"junk on the main screen\r\n\x1b[?1049h\x1b[41;33;1mALT junk");
    g.extend_from_slice(b"\x1b[3;9r\x1b[?6h\x1b[4h\x1b[?7l\x1b(0\x1b)0\x0e\x1b[3g\x1b[1;3H\x1bH");
    g.extend_from_slice(b"\x1b]4;1;rgb:12/34/56\x07\x1b]11;rgb:01/02/03\x07\x1b]0;garbage title\x07");
    g.extend_from_slice(b"\x1b[22t\x1b]2;second\x07\x1b[22t\x1b[>3u\x1b[>1u\x1b[>4;2m\x1b[?5h");
    g.extend_from_slice(b"\x1b]8;id=x;http://garbage\x1b\\linked\x1b[2;2H\x1b7\x1b[?1003h\x1b[?1015h");
    g.extend_from_slice(b"\x1b[5 q\x1b[?25l\x1b[?1h\x1b=\x1b[?2004h\x1b[20h\x1b[38;2;1;2;3mXYZ");
    g.extend_from_slice(match tail % 5 {
        0 => b"\x1b]0;unterminated title".as_slice(),
        1 => b"\x1b[?10".as_slice(),
        2 => b"\x1bP1$q".as_slice(),
        3 => b"\xe6\xbc".as_slice(), // first two bytes of a 3-byte UTF-8 char
        _ => b"\x1b".as_slice(),
    });
    g
}

/// Feeds `a_bytes` to emulator A and `b_prefix` to emulator B, then B gets
/// A's resync. Panics with the differences if B does not end up in A's
/// state, or if the resync exceeds its documented bound. Then both get
/// `suffix` and are compared again: a mirror of hidden state that drifted
/// from alacritty's shows up as diverging screens.
pub fn roundtrip(name: &str, cols: u16, rows: u16, a_bytes: &[u8], b_prefix: &[u8], suffix: &[u8]) {
    let mut a = Screen::new(cols, rows);
    a.feed(a_bytes);
    let r = a.resync();
    let bound = max_resync_len(cols, rows);
    assert!(r.len() <= bound, "{name}: resync {} bytes > bound {bound}", r.len());
    let mut b = Screen::new(cols, rows);
    b.feed(b_prefix);
    b.feed(&r);
    let sa = a.snapshot();
    let rep = sa.rep_reproducible();
    let wrap = sa.wrap_reproducible();
    let d = sa.diff(&b.snapshot());
    assert!(d.is_empty(), "{name}: after resync:\n{}", d.join("\n"));
    // A pending wrap the redraw could not recreate makes the next
    // character land differently; nothing after it is comparable.
    if !suffix.is_empty() && wrap {
        a.feed(suffix);
        b.feed(suffix);
        let d = a.snapshot().diff_with(&b.snapshot(), rep);
        assert!(d.is_empty(), "{name}: continuation after resync:\n{}", d.join("\n"));
    }
}

/// Visible text, cursor (row, column with a pending wrap counted as one past
/// the last column) and alternate-screen flag, from the vt100 crate — an
/// emulator implementation independent of alacritty_terminal.
pub fn vt100_view(bytes: &[u8], cols: u16, rows: u16) -> (Vec<String>, (u16, u16), bool) {
    let mut p = vt100::Parser::new(rows.try_into().unwrap(), cols.try_into().unwrap(), 0);
    p.process(bytes);
    let s = p.screen();
    let text = (0..rows)
        .map(|r| {
            let mut line = String::new();
            for c in 0..cols {
                let cell = s.cell(r, c).unwrap();
                if cell.is_wide_continuation() {
                    continue;
                }
                let t = cell.contents();
                line.push_str(if t.is_empty() { " " } else { t });
            }
            line.trim_end().to_owned()
        })
        .collect();
    (text, s.cursor_position(), s.alternate_screen())
}
