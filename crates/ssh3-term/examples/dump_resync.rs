//! Prints the resync for a byte file, with control bytes made visible.
//! Usage: dump_resync FILE COLS ROWS
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let bytes = std::fs::read(&a[1]).unwrap();
    let mut s = ssh3_term::Screen::new(a[2].parse().unwrap(), a[3].parse().unwrap());
    s.feed(&bytes);
    let r = s.resync();
    let vis: String = String::from_utf8_lossy(&r).replace('\x1b', "⎋").replace('\x07', "␇").replace('\x18', "␘").replace('\x0f', "␏").replace('\x0e', "␎");
    println!("{} bytes\n{vis}", r.len());
}
