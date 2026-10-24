//! The ssh3-rs programs: the `ssh3` client and `ssh3-server`. Both binaries
//! are thin `main`s over the modules here, so the configuration handling is
//! unit-testable and the end-to-end tests drive the real executables.

pub mod client;
pub mod duration;
pub mod predict;
pub mod server;
pub mod server_config;
pub mod stats;
pub mod tty;
