//! Client overlays (predictive echo, SPEC §5.2): painting predicted cells on
//! a terminal that shows the emulator's state and painting them back with
//! `Paint::Mirror` must leave that terminal exactly in the emulator's state
//! — cells, renditions, cursor, pen, charsets, modes — and keep it there
//! when both continue with the rest of the stream (hidden-state drift).

mod common;

use common::FIXTURES;
use ssh3_term::{Paint, Screen, Snapshot};

/// A shell session in the primary screen, where overlays are used:
/// coloured prompts, typed commands, output that wraps and scrolls, erases.
fn shell_session() -> Vec<u8> {
    let mut s = Vec::new();
    for i in 0..60 {
        s.extend_from_slice(b"\x1b[1;32muser@host\x1b[0m:\x1b[1;34m~/dir\x1b[0m$ ");
        s.extend_from_slice(format!("echo line {i} with some words").as_bytes());
        s.extend_from_slice(b"\r\n");
        let out = format!("\x1b[33mline {i}\x1b[0m {}\r\n", "x".repeat(i * 3 % 170));
        s.extend_from_slice(out.as_bytes());
        if i % 7 == 0 {
            s.extend_from_slice(b"partial\x1b[K\r\x1b[2Kerased\r\n");
        }
        if i % 11 == 0 {
            s.extend_from_slice("unicode: \u{e9}\u{301} \u{4e2d}\u{6587}\r\n".as_bytes());
        }
    }
    s
}

/// Deterministic pseudo-random numbers (xorshift), so failures replay.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The overlay's DECSET 2026 bracket leaves mode 2026 recorded as reset on
/// the client; a program that never set it means the same thing.
fn normalized(mut s: Snapshot) -> Snapshot {
    if s.unknown_private_modes.get(&2026) == Some(&false) {
        s.unknown_private_modes.remove(&2026);
    }
    s
}

fn diff(a: &Screen, b: &Screen) -> Vec<String> {
    normalized(a.snapshot()).diff_with(&normalized(b.snapshot()), false)
}

/// Paints random predictions at `k` cut points of `bytes` and removes them.
/// Returns how many cut points carried an overlay.
fn check(name: &str, bytes: &[u8], cols: u16, rows: u16, points: usize, seed: u64) -> usize {
    let mut rng = Rng(seed);
    let mut checked = 0;
    let step = (bytes.len() / points).max(1);
    let mut k = 0;
    while k <= bytes.len() {
        let mut a = Screen::new(cols, rows);
        a.feed(&bytes[..k]);
        if a.overlay_obstacle().is_some() {
            k += step;
            continue;
        }
        let mut b = Screen::new(cols, rows);
        b.feed(&bytes[..k]);
        let (c, r) = a.size();
        let mut cells: Vec<(u16, u16, Paint)> = Vec::new();
        let mut want = Vec::new();
        for _ in 0..1 + rng.below(8) {
            let (l, x) = (rng.below(r as u64) as u16, rng.below(c as u64 - 1) as u16);
            if a.cell(l, x).wide || want.iter().any(|&(wl, wx, _)| (wl, wx) == (l, x)) {
                continue;
            }
            let ch = (b'a' + rng.below(26) as u8) as char;
            let like = a.cell(rng.below(r as u64) as u16, rng.below(c as u64) as u16).rendition;
            cells.push((l, x, Paint::Glyph { ch, rendition: like, underline: rng.below(2) == 0 }));
            want.push((l, x, ch));
        }
        let cursor = (rng.below(r as u64) as u16, rng.below(c as u64) as u16);
        let paint = a.paint(&cells, cursor).unwrap_or_else(|| panic!("{name}@{k}: paint refused in a state without obstacle"));
        b.feed(&paint);
        for &(l, x, ch) in &want {
            assert_eq!(b.cell(l, x).ch, ch, "{name}@{k}: predicted {ch:?} not shown at ({l},{x})");
        }
        assert_eq!(b.cursor(), cursor, "{name}@{k}: overlay cursor not placed");
        let back: Vec<_> = want.iter().map(|&(l, x, _)| (l, x, Paint::Mirror)).collect();
        let unpaint = a.paint(&back, a.cursor()).unwrap_or_else(|| panic!("{name}@{k}: unpaint refused"));
        b.feed(&unpaint);
        let d = diff(&a, &b);
        assert!(d.is_empty(), "{name}@{k}: after unpaint the client differs:\n{}", d.join("\n"));
        // Both continue: hidden state the overlay touched would show now.
        a.feed(&bytes[k..]);
        b.feed(&bytes[k..]);
        let d = diff(&a, &b);
        assert!(d.is_empty(), "{name}@{k}: after the rest of the stream the client differs:\n{}", d.join("\n"));
        checked += 1;
        k += step;
    }
    checked
}

#[test]
fn paint_then_unpaint_restores_the_emulator_state() {
    let shell = shell_session();
    let mut total = check("shell", &shell, 80, 24, 400, 0x9e37_79b9_7f4a_7c15);
    total += check("shell-narrow", &shell, 33, 7, 300, 0x1234_5678_9abc_def1);
    for (i, &(name, bytes, cols, rows)) in FIXTURES.iter().enumerate() {
        total += check(name, bytes, cols, rows, 120, 0xdead_beef ^ i as u64);
    }
    // Non-vacuity: most cut points of the primary-screen streams carry an
    // overlay.
    assert!(total > 800, "only {total} cut points were checked");
}

#[test]
fn obstacles_refuse_painting() {
    for (setup, why) in [
        (&b"\x1b[?1049h"[..], "alternate screen"),
        (b"\x1b[?6h", "origin mode"),
        (b"\x1b[4h", "insert mode"),
        (b"\x1b(0", "line-drawing charset"),
        (b"\x1b]8;;http://x\x1b\\", "hyperlink pen"),
        (b"\x1b[31", "parser inside a sequence"),
        (b"\x1b[1;80Hx", "pending wrap"),
    ] {
        let mut s = Screen::new(80, 24);
        s.feed(setup);
        assert_eq!(s.overlay_obstacle(), Some(why), "{setup:?}");
        assert!(s.paint(&[(0, 0, Paint::Mirror)], (0, 0)).is_none(), "{setup:?} painted");
    }
    let s = Screen::new(80, 24);
    assert!(s.paint(&[(0, 79, Paint::Mirror)], (0, 0)).is_none(), "last column painted");
}
