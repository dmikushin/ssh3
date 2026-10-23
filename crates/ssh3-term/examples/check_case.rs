//! Runs one round trip and prints the differences.
//! Usage: check_case COLS ROWS B_BYTES SUFFIX_BYTES (A_BYTES [RESIZE])...
//! Byte arguments are comma-separated decimal lists (proptest's output);
//! RESIZE is `cols:rows` applied after the preceding A part, or `-`.
#[path = "../tests/common/mod.rs"]
mod common;

/// `gN` stands for the tests' `garbage(N)`.
fn bytes(s: &str) -> Vec<u8> {
    if let Some(n) = s.strip_prefix('g') {
        return common::garbage(n.parse().unwrap());
    }
    s.split(',').filter(|x| !x.trim().is_empty()).map(|x| x.trim().parse().unwrap()).collect()
}
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (c, r): (u16, u16) = (a[1].parse().unwrap(), a[2].parse().unwrap());
    let (bb, sb) = (bytes(&a[3]), bytes(&a[4]));
    let mut sa = ssh3_term::Screen::new(c, r);
    let mut shown = Vec::new();
    for part in a[5..].chunks(2) {
        let ab = bytes(&part[0]);
        sa.feed(&ab);
        shown.extend_from_slice(&ab);
        if let Some((rc, rr)) = part.get(1).and_then(|s| s.split_once(':')) {
            sa.resize(rc.parse().unwrap(), rr.parse().unwrap());
        }
    }
    let (c, r) = sa.size();
    let rs = sa.resync();
    let mut s2 = ssh3_term::Screen::new(c, r);
    s2.feed(&bb);
    s2.feed(&rs);
    let snap = sa.snapshot();
    let vis = String::from_utf8_lossy(&rs).replace('\x1b', "⎋").replace("⎋[23t", "");
    println!("A: {:?}\nresync: {vis:?}", String::from_utf8_lossy(&shown).replace('\x1b', "⎋"));
    println!("A cursor {:?} wrap {} alt {} rep_ok {} saved {:?} cells {:?}", snap.cursor.point, snap.cursor.input_needs_wrap, sa.alternate_screen(), snap.rep_reproducible(), (snap.saved_cursor.point, snap.saved_cursor.input_needs_wrap), snap.cells.iter().map(|r| r.iter().map(|c| c.c).collect::<String>()).collect::<Vec<_>>());
    println!("after resync: {:#?}", snap.diff(&s2.snapshot()));
    sa.feed(&sb);
    s2.feed(&sb);
    println!("continuation: {:#?}", sa.snapshot().diff_with(&s2.snapshot(), snap.rep_reproducible()));
}
