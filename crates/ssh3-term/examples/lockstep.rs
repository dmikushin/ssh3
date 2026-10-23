//! Round trip, then feeds the suffix to both emulators byte by byte and
//! prints the first byte after which they differ.
//! Usage: lockstep COLS ROWS B_BYTES SUFFIX_BYTES (A_BYTES [RESIZE])...
#[path = "../tests/common/mod.rs"]
mod common;

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
    for part in a[5..].chunks(2) {
        sa.feed(&bytes(&part[0]));
        if let Some((rc, rr)) = part.get(1).and_then(|s| s.split_once(':')) {
            sa.resize(rc.parse().unwrap(), rr.parse().unwrap());
        }
    }
    let (c, r) = sa.size();
    let mut b = ssh3_term::Screen::new(c, r);
    b.feed(&bb);
    b.feed(&sa.resync());
    for (i, x) in sb.iter().enumerate() {
        let (pa, pb) = (sa.snapshot(), b.snapshot());
        sa.feed(&[*x]);
        b.feed(&[*x]);
        let d = sa.snapshot().diff(&b.snapshot());
        if !d.is_empty() {
            println!("after suffix byte {i} ({:?}):", *x as char);
            println!(" before: A cursor {:?}{} B cursor {:?}{}", pa.cursor.point, pa.cursor.input_needs_wrap, pb.cursor.point, pb.cursor.input_needs_wrap);
            println!(" before: A saved {:?}{} B saved {:?}{}", pa.saved_cursor.point, pa.saved_cursor.input_needs_wrap, pb.saved_cursor.point, pb.saved_cursor.input_needs_wrap);
            for l in d.iter().take(4) { println!(" {}", &l[..l.len().min(300)]); }
            return;
        }
    }
    println!("no difference");
}
