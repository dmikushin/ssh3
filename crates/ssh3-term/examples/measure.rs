//! Resync size and time on full screens (vim and htop mid-recording), and
//! RSS per screen. Usage: measure (run with --release)
fn rss() -> usize {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    s.lines().find(|l| l.starts_with("VmRSS:")).unwrap().split_whitespace().nth(1).unwrap().parse::<usize>().unwrap() * 1024
}
fn main() {
    for (name, bytes, cols, rows) in [
        ("vim", &include_bytes!("../tests/fixtures/vim.bin")[..], 100u16, 30u16),
        ("htop", &include_bytes!("../tests/fixtures/htop.bin")[..], 132, 40),
        ("nvim", &include_bytes!("../tests/fixtures/nvim.bin")[..], 120, 35),
    ] {
        let mut s = ssh3_term::Screen::new(cols, rows);
        s.feed(&bytes[..bytes.len() * 6 / 10]);
        let t = std::time::Instant::now();
        let n = 200;
        let mut len = 0;
        for _ in 0..n {
            len = s.resync().len();
        }
        println!("{name} {cols}x{rows} at 60%: resync {len} B, {:?} each, bound {}", t.elapsed() / n, ssh3_term::max_resync_len(cols, rows));
    }
    for (cols, rows) in [(80u16, 24u16), (300, 100)] {
        let before = rss();
        let v: Vec<_> = (0..200).map(|_| { let mut s = ssh3_term::Screen::new(cols, rows); s.feed(b"x"); s }).collect();
        println!("{cols}x{rows}: RSS {} B/screen", (rss() - before) / v.len());
    }
}
