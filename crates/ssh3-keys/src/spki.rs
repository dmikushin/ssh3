//! Conversions between OpenSSH keys and X.509/PKCS#8 encodings.

use pkcs8::{DecodePublicKey, EncodePrivateKey};
use ssh_key::private::KeypairData;
use ssh_key::public::{EcdsaPublicKey, KeyData};
use ssh_key::{EcdsaCurve, PublicKey};

use crate::{Error, Result};

/// The signature algorithm a key signs X.509 certificates / TLS with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa,
}

/// Convert an OpenSSH private keypair into PKCS#8 DER.
pub fn keypair_to_pkcs8(kp: &KeypairData) -> Result<(KeyKind, Vec<u8>)> {
    let p8 = |e: pkcs8::Error| Error::Pkcs8(e.to_string());
    match kp {
        KeypairData::Ed25519(k) => {
            let sk = ed25519_dalek::SigningKey::try_from(k).map_err(|e| Error::Pkcs8(e.to_string()))?;
            Ok((KeyKind::Ed25519, sk.to_pkcs8_der().map_err(p8)?.as_bytes().to_vec()))
        }
        KeypairData::Ecdsa(k) => match k.curve() {
            EcdsaCurve::NistP256 => {
                let sk = p256::SecretKey::from_slice(k.private_key_bytes())
                    .map_err(|e| Error::Pkcs8(e.to_string()))?;
                Ok((KeyKind::EcdsaP256, sk.to_pkcs8_der().map_err(p8)?.as_bytes().to_vec()))
            }
            EcdsaCurve::NistP384 => {
                let sk = p384::SecretKey::from_slice(k.private_key_bytes())
                    .map_err(|e| Error::Pkcs8(e.to_string()))?;
                Ok((KeyKind::EcdsaP384, sk.to_pkcs8_der().map_err(p8)?.as_bytes().to_vec()))
            }
            other => Err(Error::UnsupportedAlgorithm(format!("ecdsa {other}"))),
        },
        KeypairData::Rsa(k) => {
            let sk = rsa_private_key(k)?;
            Ok((KeyKind::Rsa, sk.to_pkcs8_der().map_err(p8)?.as_bytes().to_vec()))
        }
        KeypairData::Encrypted(_) => Err(Error::Pkcs8("key is encrypted".into())),
        other => Err(Error::UnsupportedAlgorithm(
            other.algorithm().map(|a| a.to_string()).unwrap_or_else(|_| "unknown".into()),
        )),
    }
}

/// OpenSSH RSA keypair → `rsa::RsaPrivateKey`.
///
/// Not `rsa::RsaPrivateKey::try_from(&RsaKeypair)`: ssh-key 0.6.7
/// (`private/rsa.rs:197-200`) passes `p` twice instead of `[p, q]` as the
/// primes, so `from_components` rejects every real key ("cryptographic
/// error"). This builds the key from n, e, d, p, q directly.
pub fn rsa_private_key(k: &ssh_key::private::RsaKeypair) -> Result<rsa::RsaPrivateKey> {
    let big = |m: &ssh_key::Mpint, what: &str| {
        m.as_positive_bytes()
            .map(rsa::BigUint::from_bytes_be)
            .ok_or_else(|| Error::Pkcs8(format!("RSA {what} is not a positive integer")))
    };
    let key = rsa::RsaPrivateKey::from_components(
        big(&k.public.n, "n")?,
        big(&k.public.e, "e")?,
        big(&k.private.d, "d")?,
        vec![big(&k.private.p, "p")?, big(&k.private.q, "q")?],
    )
    .map_err(|e| Error::Pkcs8(format!("RSA components: {e}")))?;
    key.validate().map_err(|e| Error::Pkcs8(format!("RSA key invalid: {e}")))?;
    Ok(key)
}

/// Build an OpenSSH `KeypairData::Rsa` from an `rsa::RsaPrivateKey` loaded
/// from a PEM PKCS#1 / PKCS#8 file.
///
/// ssh-key's own `RsaKeypair::try_from(&rsa::RsaPrivateKey)` goes through the
/// same broken conversion noted on `rsa_private_key` (it mishandles the
/// primes), so this constructs the `RsaKeypair` field by field from the
/// validated components: public (n, e) and private (d, iqmp, p, q), where
/// iqmp = q^-1 mod p is the CRT coefficient the OpenSSH format stores.
pub fn rsa_to_keypair(sk: &rsa::RsaPrivateKey) -> Result<KeypairData> {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    use ssh_key::Mpint;
    use ssh_key::private::{RsaKeypair, RsaPrivateKey};
    use ssh_key::public::RsaPublicKey;

    sk.validate().map_err(|e| Error::Pkcs8(format!("RSA key invalid: {e}")))?;
    let primes = sk.primes();
    if primes.len() != 2 {
        return Err(Error::Pkcs8(format!(
            "RSA key has {} prime factors; only 2-prime RSA is supported",
            primes.len()
        )));
    }
    let iqmp = sk
        .crt_coefficient()
        .ok_or_else(|| Error::Pkcs8("RSA key lacks a CRT coefficient (iqmp)".into()))?;
    let mp = |b: rsa::BigUint, what: &str| {
        Mpint::from_positive_bytes(&b.to_bytes_be()).map_err(|e| Error::Pkcs8(format!("RSA {what}: {e}")))
    };
    let public = RsaPublicKey {
        e: mp(sk.e().clone(), "e")?,
        n: mp(sk.n().clone(), "n")?,
    };
    let private = RsaPrivateKey {
        d: mp(sk.d().clone(), "d")?,
        iqmp: mp(iqmp, "iqmp")?,
        p: mp(primes[0].clone(), "p")?,
        q: mp(primes[1].clone(), "q")?,
    };
    let kp = RsaKeypair { public, private };
    Ok(KeypairData::Rsa(kp))
}

/// Convert a DER SubjectPublicKeyInfo into an OpenSSH public key.
pub fn public_key_from_spki(spki_der: &[u8]) -> Result<PublicKey> {
    let data = if let Ok(k) = ed25519_dalek::VerifyingKey::from_public_key_der(spki_der) {
        KeyData::Ed25519((&k).into())
    } else if let Ok(k) = p256::PublicKey::from_public_key_der(spki_der) {
        let point = k.to_sec1_bytes();
        KeyData::Ecdsa(EcdsaPublicKey::from_sec1_bytes(&point).map_err(|e| Error::Spki(e.to_string()))?)
    } else if let Ok(k) = p384::PublicKey::from_public_key_der(spki_der) {
        let point = k.to_sec1_bytes();
        KeyData::Ecdsa(EcdsaPublicKey::from_sec1_bytes(&point).map_err(|e| Error::Spki(e.to_string()))?)
    } else if let Ok(k) = rsa::RsaPublicKey::from_public_key_der(spki_der) {
        KeyData::Rsa((&k).try_into().map_err(|e: ssh_key::Error| Error::Spki(e.to_string()))?)
    } else {
        return Err(Error::Spki(
            "SubjectPublicKeyInfo is not ed25519, ecdsa-p256, ecdsa-p384 or rsa".into(),
        ));
    };
    Ok(PublicKey::new(data, ""))
}

/// Extract the OpenSSH public key from an X.509 certificate (DER).
pub fn public_key_from_cert(cert_der: &[u8]) -> Result<PublicKey> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| Error::Spki(format!("X.509 parse: {e}")))?;
    public_key_from_spki(cert.public_key().raw)
}

/// Key equality on key material only (comments ignored).
pub fn same_key(a: &PublicKey, b: &PublicKey) -> bool {
    a.key_data() == b.key_data()
}
