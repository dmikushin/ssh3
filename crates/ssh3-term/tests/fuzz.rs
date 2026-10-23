//! Property tests: random programs built from the escape sequences the
//! emulator implements (and some it does not), random screen sizes and
//! resizes, random cut points and client states.

mod common;

use common::garbage;
use proptest::prelude::*;
use ssh3_term::{max_resync_len, Screen};

fn frag() -> impl Strategy<Value = Vec<u8>> {
    let n = || 0u16..40;
    prop_oneof![
        "[ -~]{1,12}".prop_map(|s| s.into_bytes()),
        prop::sample::select(vec!["漢字", "🎉x", "e\u{301}", "a\u{308}\u{323}", "\u{200b}", "ｗｉｄｅ"])
            .prop_map(|s| s.as_bytes().to_vec()),
        (n(), n(), prop::sample::select(b"ABCDHfGdJKXP@LMSTbIZEF`aerg".to_vec()))
            .prop_map(|(a, b, f)| format!("\x1b[{a};{b}{}", f as char).into_bytes()),
        (n(), prop::sample::select(b"ABCDJKXP@LMSTbIZ".to_vec()))
            .prop_map(|(a, f)| format!("\x1b[{a}{}", f as char).into_bytes()),
        (
            prop::sample::select(vec![
                1u16, 3, 5, 6, 7, 9, 12, 25, 47, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1015,
                1042, 1047, 1048, 1049, 2004, 2026
            ]),
            any::<bool>()
        )
            .prop_map(|(m, on)| format!("\x1b[?{m}{}", if on { 'h' } else { 'l' }).into_bytes()),
        (prop::sample::select(vec![2u16, 4, 12, 20, 34]), any::<bool>())
            .prop_map(|(m, on)| format!("\x1b[{m}{}", if on { 'h' } else { 'l' }).into_bytes()),
        prop::collection::vec(
            prop::sample::select(vec![
                "0", "1", "2", "3", "4", "4:3", "4:0", "5", "7", "8", "9", "21", "22", "24", "27", "31", "42",
                "93", "104", "38;5;123", "48;5;17", "38;2;1;2;3", "48;2;250;0;9", "58;5;200", "58:2::9:8:7",
                "59", "39", "49",
            ]),
            1..5
        )
        .prop_map(|v| format!("\x1b[{}m", v.join(";")).into_bytes()),
        prop::sample::select(vec![
            "\x1b7", "\x1b8", "\x1bD", "\x1bE", "\x1bM", "\x1bc", "\x1b#8", "\x1b(0", "\x1b(B", "\x1b)0",
            "\x1b)B", "\x0e", "\x0f", "\t", "\x1bH", "\x1b[g", "\x1b[3g", "\r", "\n", "\x08", "\x1b=", "\x1b>",
            "\x1b[22t", "\x1b[23t", "\x1b[22;0t", "\x1b[>1u", "\x1b[>5u", "\x1b[<1u", "\x1b[<3u",
            "\x1b[=3;1u", "\x1b[=1;2u", "\x1b[=1;3u", "\x1b[>4;1m", "\x1b[>4;2m", "\x1b[>4;0m",
            "\x1b[1 q", "\x1b[4 q", "\x1b[6 q", "\x1b[0 q", "\x1b]104\x07", "\x1b]110\x07",
            "\x1b]8;;\x1b\\", "\x1b[!p", "\x1bP1$qm\x1b\\", "\x1b_apc\x1b\\", "\x1b[?u",
        ])
        .prop_map(|s| s.as_bytes().to_vec()),
        ("[a-z ]{0,10}", 0u8..3).prop_map(|(t, k)| {
            match k {
                0 => format!("\x1b]0;{t}\x07"),
                1 => format!("\x1b]2;{t}\x1b\\"),
                _ => format!("\x1b]8;id={t};http://h/{t}\x1b\\"),
            }
            .into_bytes()
        }),
        (0u16..300, any::<(u8, u8, u8)>())
            .prop_map(|(i, (r, g, b))| match i {
                0..256 => format!("\x1b]4;{i};rgb:{r:02x}/{g:02x}/{b:02x}\x07"),
                256..270 => format!("\x1b]10;rgb:{r:02x}/{g:02x}/{b:02x}\x07"),
                _ => format!("\x1b]11;#{r:02x}{g:02x}{b:02x}\x07"),
            }
            .into_bytes()),
        prop::collection::vec(any::<u8>(), 0..8),
    ]
}

/// Starts with a printed character: before the first one, REP has nothing
/// to repeat in the emulator, while the client repeats whatever the redraw
/// printed last — a difference no redraw can remove, and no program meets.
fn program() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(frag(), 0..60).prop_map(|v| [b"x".to_vec(), v.concat()].concat())
}

/// Program parts, each followed by an optional resize.
type Parts = [(Vec<u8>, Option<(u16, u16)>)];

fn check(cols: u16, rows: u16, a: &Parts, b_prefix: &[u8], suffix: &[u8]) {
    let mut sa = Screen::new(cols, rows);
    for (bytes, resize) in a {
        sa.feed(bytes);
        if let Some((c, r)) = resize {
            sa.resize(*c, *r);
        }
    }
    let (c, r) = sa.size();
    let rs = sa.resync();
    assert!(rs.len() <= max_resync_len(c, r));
    let mut sb = Screen::new(c, r);
    sb.feed(b_prefix);
    sb.feed(&rs);
    let snap = sa.snapshot();
    let rep = snap.rep_reproducible();
    let wrap = snap.wrap_reproducible();
    let d = snap.diff(&sb.snapshot());
    assert!(d.is_empty(), "after resync:\n{}", d.join("\n"));
    if !wrap {
        return;
    }
    sa.feed(suffix);
    sb.feed(suffix);
    let d = sa.snapshot().diff_with(&sb.snapshot(), rep);
    assert!(d.is_empty(), "continuation:\n{}", d.join("\n"));
}

/// Fixed seed, so a plain `cargo test` is deterministic; set
/// PROPTEST_RNG_SEED (and PROPTEST_CASES) to explore further.
fn config() -> ProptestConfig {
    let base = ProptestConfig { cases: 384, ..ProptestConfig::default() };
    if std::env::var_os("PROPTEST_RNG_SEED").is_some() {
        base
    } else {
        ProptestConfig { rng_seed: proptest::test_runner::RngSeed::Fixed(0x5533_7e2a), ..base }
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn random_program_from_garbage(
        cols in 1u16..40, rows in 1u16..20,
        a in program(), suffix in program(), g in 0usize..5,
    ) {
        check(cols, rows, &[(a, None)], &garbage(g), &suffix);
    }

    #[test]
    fn random_program_from_earlier_prefix(
        cols in 1u16..40, rows in 1u16..20,
        a in program(), cut in any::<prop::sample::Index>(), suffix in program(),
    ) {
        let j = cut.index(a.len() + 1);
        let mut b = a[..j].to_vec();
        b.extend_from_slice(b"\x1b]0;");
        check(cols, rows, &[(a, None)], &b, &suffix);
    }

    #[test]
    fn random_program_with_resizes(
        cols in 1u16..40, rows in 1u16..20,
        parts in prop::collection::vec((program(), (1u16..40, 1u16..20)), 1..4),
        suffix in program(), g in 0usize..5,
    ) {
        let a: Vec<_> = parts.into_iter().map(|(p, s)| (p, Some(s))).collect();
        check(cols, rows, &a, &garbage(g), &suffix);
    }
}
