// jemalloc with background_thread returns freed memory to the OS between
// load peaks (SPEC §1, X3: glibc kept 3.45 GB after a 3.3 GB peak).
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// tikv-jemallocator builds jemalloc with the `_rjem_` symbol prefix, so
// jemalloc reads `_rjem_malloc_conf` (a `const char *`); the unprefixed
// `malloc_conf` this file exported before was ignored — stats_print showed
// opt.background_thread: false in every earlier build.
// narenas:1: jemalloc defaults to 4 arenas per CPU and every arena a thread
// touches keeps its first extents resident; on THP=always hosts those are
// 2 MiB huge pages: 531 MB idle RSS on 88 CPUs, 14 MB with one arena
// (~/scratch/ssh-udp/mem-idle-cause.log). Thread caches stay per thread.
#[used]
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static MALLOC_CONF: &[u8; 33] = b"background_thread:true,narenas:1\0";

fn main() -> std::process::ExitCode {
    ssh3_bin::server::main()
}
