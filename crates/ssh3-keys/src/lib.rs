//! Identity and authentication primitives for ssh3-rs (SPEC.md §2).
//!
//! - [`host`]: server identity — an OpenSSH host key presented as a
//!   self-signed X.509 certificate (§2.1).
//! - [`known_hosts`] + [`verifier`]: client-side check of that certificate
//!   against OpenSSH `known_hosts` (§2.1).
//! - [`signer`]: user keys from a private key file or from ssh-agent (§2.2).
//! - [`auth`]: the exact signed auth blob (§2.2).
//! - [`authorized_keys`]: server-side lookup with OpenSSH options (§2.2).

pub mod auth;
pub mod authorized_keys;
pub mod error;
pub mod host;
pub mod known_hosts;
pub mod signer;
pub mod spki;
pub mod verifier;

pub use error::{Error, Result};
pub use ssh_key::{PublicKey, Signature};
