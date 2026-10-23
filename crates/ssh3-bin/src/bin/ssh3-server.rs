// jemalloc with background_thread returns freed memory to the OS between
// load peaks (SPEC §1, X3: glibc kept 3.45 GB after a 3.3 GB peak). Pattern
// verified on oracle under static musl by ~/scratch/ssh-udp/static-probe.
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static malloc_conf: &[u8] = b"background_thread:true\0";

fn main() -> std::process::ExitCode {
    ssh3_bin::server::main()
}
