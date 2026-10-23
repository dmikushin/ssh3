//! Reproduces: a wide character on a 1-column screen.
fn main() {
    let mut s = ssh3_term::Screen::new(1, 1);
    s.feed("漢".as_bytes());
    println!("survived");
}
