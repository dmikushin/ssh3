//! Server identity (SPEC §2.1): an OpenSSH host key presented to TLS as a
//! self-signed certificate whose SubjectPublicKeyInfo is that key.

use std::path::Path;
use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PKCS_RSA_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use ssh_key::{PrivateKey, PublicKey};

use crate::spki::{KeyKind, keypair_to_pkcs8};
use crate::{Error, Result};

/// A host key ready to be served over TLS.
pub struct HostIdentity {
    public: PublicKey,
    kind: KeyKind,
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
}

impl HostIdentity {
    /// Load an unencrypted OpenSSH host private key (e.g.
    /// `/etc/ssh/ssh_host_ed25519_key`).
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        let key = PrivateKey::from_openssh(&text).map_err(|source| Error::KeyParse {
            path: path.into(),
            source,
        })?;
        if key.is_encrypted() {
            return Err(Error::EncryptedKey { path: path.into() });
        }
        Self::from_private_key(&key)
    }

    pub fn from_private_key(key: &PrivateKey) -> Result<Self> {
        let (kind, pkcs8) = keypair_to_pkcs8(key.key_data())?;
        let key_der = PrivatePkcs8KeyDer::from(pkcs8);
        let alg = match kind {
            KeyKind::Ed25519 => &PKCS_ED25519,
            KeyKind::EcdsaP256 => &PKCS_ECDSA_P256_SHA256,
            KeyKind::EcdsaP384 => &PKCS_ECDSA_P384_SHA384,
            KeyKind::Rsa => &PKCS_RSA_SHA256,
        };
        let kp = KeyPair::from_pkcs8_der_and_sign_algo(&key_der, alg)?;
        // The certificate carries no name the client checks: the verifier
        // matches the key against known_hosts only (§2.1).
        let params = CertificateParams::new(vec!["ssh3-rs".to_string()])?;
        let cert = params.self_signed(&kp)?;
        let mut public = key.public_key().clone();
        public.set_comment("");
        Ok(Self {
            public,
            kind,
            cert_der: cert.der().clone(),
            key_der,
        })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn kind(&self) -> KeyKind {
        self.kind
    }

    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    pub fn private_key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key_der.clone_key())
    }

    /// A rustls `CertifiedKey` using the ring provider.
    pub fn certified_key(&self) -> Result<Arc<CertifiedKey>> {
        let signing = rustls::crypto::ring::sign::any_supported_type(&self.private_key_der())
            .map_err(|e| Error::Pkcs8(format!("rustls rejected host key: {e}")))?;
        Ok(Arc::new(CertifiedKey::new(vec![self.cert_der.clone()], signing)))
    }
}
