//! Feeds A's resync to a fresh emulator byte by byte and prints one row
//! (and the cursor) whenever it changes.
//! Usage: trace_row COLS ROWS ROW (A_BYTES [RESIZE cols:rows])...
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (c, r, row): (u16, u16, usize) = (a[1].parse().unwrap(), a[2].parse().unwrap(), a[3].parse().unwrap());
    let mut sa = ssh3_term::Screen::new(c, r);
    for part in a[4..].chunks(2) {
        let ab: Vec<u8> = part[0].split(',').filter(|x| !x.is_empty()).map(|x| x.trim().parse().unwrap()).collect();
        sa.feed(&ab);
        if let Some((rc, rr)) = part.get(1).and_then(|s| s.split_once(':')) {
            sa.resize(rc.parse().unwrap(), rr.parse().unwrap());
        }
    }
    let (c, r) = sa.size();
    let rs = sa.resync();
    let mut b = ssh3_term::Screen::new(c, r);
    let mut last = String::new();
    for (i, byte) in rs.iter().enumerate() {
        b.feed(&[*byte]);
        let s = b.snapshot();
        let cells = s.cells[row].iter().map(|x| format!("{}{:x}", x.c, x.flags.bits())).collect::<Vec<_>>().join("|");
        let cur = format!("{cells} @{},{}{}", s.cursor.point.line.0, s.cursor.point.column.0, if s.cursor.input_needs_wrap { "w" } else { "" });
        if cur != last {
            let ctx = String::from_utf8_lossy(&rs[i.saturating_sub(14)..=i]).replace('\x1b', "⎋");
            println!("{i:5} {cur}   after {ctx:?}");
            last = cur;
        }
    }
}
