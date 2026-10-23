//! What a program writing to the pty can make the emulator allocate, and
//! what the redraw costs. Heap is measured with a counting allocator; the
//! test binary holds one test so nothing else allocates concurrently.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Instant;

use ssh3_term::{max_resync_len, Screen};

struct Counting;
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

fn grew(by: isize) {
    let now = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        grew(l.size() as isize);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        // A moving realloc holds both blocks for a moment.
        grew(n as isize);
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Counting = Counting;

fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

/// Heap growth while feeding `prefix` once and then `chunk` `times` times,
/// all into the same screen.
fn growth(prefix: &[u8], chunk: &[u8], times: usize) -> isize {
    let mut s = Screen::new(80, 24);
    s.feed(b"a");
    s.feed(prefix);
    let before = live();
    for _ in 0..times {
        s.feed(chunk);
    }
    let grown = live() - before;
    drop(s);
    grown
}

/// Highest heap use above the level before `f`, while `f` runs.
fn peak_during<R>(f: impl FnOnce() -> R) -> (R, isize) {
    let before = live();
    PEAK.store(before, Ordering::Relaxed);
    let r = f();
    (r, PEAK.load(Ordering::Relaxed) - before)
}

#[test]
fn hostile_output_is_bounded() {
    // Unterminated OSC: alacritty's parser would buffer 64 MiB (measured
    // 129 MiB of heap without the guard).
    let osc = growth(b"\x1b]0;", &[b'A'; 1 << 20], 64);
    assert!(osc < 1 << 20, "64 MiB of OSC payload grew the heap by {osc} bytes");

    // Combining marks onto one cell (measured +34 MB for 8 Mi without the
    // guard).
    let marks = "\u{301}".repeat(1 << 16);
    let zw = growth(b"", marks.as_bytes(), 128);
    assert!(zw < 1 << 16, "8 Mi combining marks grew the heap by {zw} bytes");

    // Kitty keyboard pushes: alacritty panics on the 4097th.
    let mut s = Screen::new(80, 24);
    s.feed(&b"\x1b[>1u".repeat(5000));
    assert_eq!(s.snapshot().keyboard_stack.len(), 4096);

    // A wide character on a 1-column window: alacritty panics.
    let mut s = Screen::new(1, 1);
    s.feed("漢字".as_bytes());
    assert_eq!(s.size(), (ssh3_term::MIN_COLUMNS, ssh3_term::MIN_LINES));

    // Absurd window sizes are clamped.
    let mut s = Screen::new(u16::MAX, u16::MAX);
    assert_eq!(s.size(), (ssh3_term::MAX_COLUMNS, ssh3_term::MAX_LINES));
    s.resize(0, 0);
    assert_eq!(s.size(), (ssh3_term::MIN_COLUMNS, ssh3_term::MIN_LINES));

    // Title stack and unknown modes are capped.
    let mut s = Screen::new(80, 24);
    for i in 0..1000 {
        s.feed(format!("\x1b]2;{i}\x07\x1b[22t\x1b[?{}h", 3000 + i).as_bytes());
    }
    let snap = s.snapshot();
    assert_eq!(snap.title_stack.len(), 16);
    assert_eq!(snap.unknown_private_modes.len(), 64);

    // Hyperlinks on every cell, each with a long target: the redraw with
    // them would be ~19 MiB at 120x40; it is abandoned at the bound and made
    // without them, and nothing in between allocates past the bound
    // (measured before the capped buffer: 33.7 MB peak at 120x40).
    for (cols, rows) in [(80u16, 24u16), (120, 40)] {
        let mut s = Screen::new(cols, rows);
        for i in 0..(cols as usize * rows as usize) {
            let uri = format!("http://h/{i}/{}", "x".repeat(4000));
            s.feed(format!("\x1b]8;id={i};{uri}\x1b\\#").as_bytes());
        }
        let bound = max_resync_len(cols, rows);
        let (r, peak) = peak_during(|| s.resync());
        assert!(r.len() <= bound, "{cols}x{rows}: {} > {bound}", r.len());
        assert!(peak <= bound as isize + 65536, "{cols}x{rows}: peak {peak} > bound {bound}");
        println!("hyperlink flood {cols}x{rows}: resync {} B, peak {peak} B, bound {bound}", r.len());
    }

    // Memory per screen (heap; the parser reserves a 2 MiB synchronized-
    // update buffer that is never written, see crate docs) and redraw cost.
    for (cols, rows) in [(80u16, 24u16), (300, 100)] {
        let before = live();
        let screens: Vec<Screen> = (0..32).map(|_| Screen::new(cols, rows)).collect();
        let per = (live() - before) / 32;
        drop(screens);
        let mut s = Screen::new(cols, rows);
        s.feed(include_bytes!("fixtures/htop.bin"));
        s.feed(b"\x1b[?1049h");
        s.feed(include_bytes!("fixtures/nvim.bin"));
        let t = Instant::now();
        let n = 50;
        let mut len = 0;
        for _ in 0..n {
            len = s.resync().len();
        }
        let each = t.elapsed() / n;
        println!(
            "{cols}x{rows}: heap {per} B/screen, resync {len} B in {each:?}, bound {}",
            max_resync_len(cols, rows)
        );
    }
}
