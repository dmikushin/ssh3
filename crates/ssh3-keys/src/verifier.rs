//! rustls server-certificate verifier that trusts OpenSSH `known_hosts`
//! instead of a PKI (SPEC §2.1).
//!
//! One verifier is built per connection target (`host`, `port`): QUIC/TLS
//! `ServerName` is not used for the decision because the client may dial an
//! IP or an alias while known_hosts is keyed by the name the user typed.
//!
//! Decision table (OpenSSH `check_host_key`, with the deviations noted):
//! - presented key listed under `@revoked` for any host → reject;
//! - presented key known for this host → accept;
//! - other key(s) of the **same** type known → hard failure naming each
//!   file:line (no StrictHostKeyChecking mode overrides this; OpenSSH `no`
//!   would connect with degraded features — we refuse);
//! - only keys of **other** types known → treated as unknown but reported
//!   (`UnknownHost::other_keys`); `accept-new` refuses in this case (it only
//!   accepts hosts with no keys at all);
//! - unknown host → `yes`: reject, `accept-new`/`no`: accept and append,
//!   `ask`: the prompt callback decides, accepted keys are appended.
//!
//! `@cert-authority` lines are ignored for matching: the TLS certificate is
//! not an OpenSSH certificate, so a CA line can never vouch for it.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use ssh_key::{HashAlg, PublicKey};

use crate::known_hosts::{self, KnownHosts, Marker};
use crate::spki::{public_key_from_cert, same_key};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrictHostKeyChecking {
    Yes,
    No,
    AcceptNew,
    Ask,
}

/// What the prompt sees for an unknown host.
#[derive(Clone, Debug)]
pub struct UnknownHost {
    pub host: String,
    pub port: u16,
    pub key: PublicKey,
    pub fingerprint: String,
    /// Keys of other types already known for this host, with file:line.
    pub other_keys: Vec<(String, String)>,
}

pub type Prompt = dyn Fn(&UnknownHost) -> bool + Send + Sync;

pub struct KnownHostsVerifier {
    host: String,
    port: u16,
    files: Vec<PathBuf>,
    append_to: Option<PathBuf>,
    hash_known_hosts: bool,
    mode: StrictHostKeyChecking,
    prompt: Option<Arc<Prompt>>,
    algs: WebPkiSupportedAlgorithms,
    verified: Mutex<Option<PublicKey>>,
}

impl std::fmt::Debug for KnownHostsVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnownHostsVerifier")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("files", &self.files)
            .field("mode", &self.mode)
            .finish()
    }
}

impl KnownHostsVerifier {
    /// `files`: UserKnownHostsFile entries followed by global files; new keys
    /// are appended to the first of them.
    pub fn new(host: &str, port: u16, files: Vec<PathBuf>, mode: StrictHostKeyChecking) -> Self {
        let append_to = files.first().cloned();
        Self {
            host: host.to_ascii_lowercase(),
            port,
            files,
            append_to,
            hash_known_hosts: false,
            mode,
            prompt: None,
            algs: rustls::crypto::ring::default_provider().signature_verification_algorithms,
            verified: Mutex::new(None),
        }
    }

    pub fn hash_known_hosts(mut self, on: bool) -> Self {
        self.hash_known_hosts = on;
        self
    }

    pub fn with_prompt(mut self, prompt: Arc<Prompt>) -> Self {
        self.prompt = Some(prompt);
        self
    }

    /// The host key accepted by the last successful handshake.
    pub fn verified_key(&self) -> Option<PublicKey> {
        self.verified.lock().unwrap().clone()
    }

    /// The decision on a presented key, independent of TLS.
    pub fn check_key(&self, key: &PublicKey) -> Result<(), String> {
        let kh = KnownHosts::load(&self.files).map_err(|e| e.to_string())?;
        let fp = key.fingerprint(HashAlg::Sha256).to_string();

        if let Some(r) = kh
            .entries
            .iter()
            .find(|e| e.marker == Marker::Revoked && same_key(&e.key, key))
        {
            return Err(format!(
                "host key {fp} for {} is marked @revoked at {}",
                known_hosts::lookup_name(&self.host, self.port),
                r.location()
            ));
        }

        let entries: Vec<_> = kh
            .lookup(&self.host, self.port)
            .into_iter()
            .filter(|e| e.marker == Marker::None)
            .collect();
        if entries.iter().any(|e| same_key(&e.key, key)) {
            return Ok(());
        }
        let same_type: Vec<String> = entries
            .iter()
            .filter(|e| e.key.algorithm() == key.algorithm())
            .map(|e| e.location())
            .collect();
        if !same_type.is_empty() {
            return Err(format!(
                "HOST KEY MISMATCH for {}: server presented {} {fp}, but known_hosts has a different {} key at {}",
                known_hosts::lookup_name(&self.host, self.port),
                key.algorithm(),
                key.algorithm(),
                same_type.join(", ")
            ));
        }
        let other_keys: Vec<(String, String)> = entries
            .iter()
            .map(|e| (e.key.algorithm().to_string(), e.location()))
            .collect();

        let accept = match self.mode {
            StrictHostKeyChecking::Yes => false,
            StrictHostKeyChecking::No => true,
            StrictHostKeyChecking::AcceptNew => other_keys.is_empty(),
            StrictHostKeyChecking::Ask => match &self.prompt {
                Some(p) => p(&UnknownHost {
                    host: self.host.clone(),
                    port: self.port,
                    key: key.clone(),
                    fingerprint: fp.clone(),
                    other_keys: other_keys.clone(),
                }),
                None => false,
            },
        };
        if !accept {
            let known = if other_keys.is_empty() {
                String::new()
            } else {
                format!(
                    "; keys of other types are known at {}",
                    other_keys.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>().join(", ")
                )
            };
            return Err(format!(
                "host {} is not in known_hosts ({}) and StrictHostKeyChecking={:?} refused {} {fp}{known}",
                known_hosts::lookup_name(&self.host, self.port),
                self.files.iter().map(|f| f.display().to_string()).collect::<Vec<_>>().join(", "),
                self.mode,
                key.algorithm()
            ));
        }
        if let Some(f) = &self.append_to {
            known_hosts::append(f, &self.host, self.port, key, self.hash_known_hosts).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

impl ServerCertVerifier for KnownHostsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let key = public_key_from_cert(end_entity).map_err(|e| rustls::Error::General(e.to_string()))?;
        self.check_key(&key).map_err(rustls::Error::General)?;
        *self.verified.lock().unwrap() = Some(key);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("ssh3-rs requires TLS 1.3 (QUIC)".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}
