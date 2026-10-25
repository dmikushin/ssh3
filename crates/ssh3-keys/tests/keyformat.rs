//! Private-key file-format support (migration blocker: the mounted user key is
//! unencrypted PKCS#1 PEM, `BEGIN RSA PRIVATE KEY`, which the old
//! `PrivateKey::from_openssh`-only loader rejected with a Base64 error).
//!
//! All fixtures are SYNTHETIC and generated in-process into a tempdir with the
//! same tools the existing keys suite uses (ssh-keygen, openssl). No env var,
//! no user keys, no committed key material — every test executes under the
//! default `cargo test -p ssh3-keys`. If a required tool is missing the test
//! FAILS (it does not silently skip).

use std::path::{Path, PathBuf};
use std::process::Command;

use ssh3_keys::auth::{EXPORTER_LEN, Intent, pubkey_blob, sign_auth, verify_auth};
use ssh3_keys::signer::{FileSigner, Signer};
use ssh3_keys::spki::{rsa_to_keypair, same_key};
use ssh3_keys::{Error, PublicKey};

fn scratch() -> tempfile::TempDir {
    let base = PathBuf::from(std::env::var_os("HOME").expect("HOME")).join("scratch/ssh-udp/keyfmt-test");
    std::fs::create_dir_all(&base).unwrap();
    tempfile::Builder::new().prefix("kf-").tempdir_in(base).unwrap()
}

fn run(cmd: &str, args: &[&str]) -> std::process::Output {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("required tool `{cmd}` could not run: {e}"));
    out
}

fn must(cmd: &str, args: &[&str]) {
    let out = run(cmd, args);
    assert!(out.status.success(), "{cmd} {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
}

/// Generate an unencrypted PKCS#1 RSA key (`BEGIN RSA PRIVATE KEY`).
fn gen_pkcs1(dir: &Path) -> PathBuf {
    let p = dir.join("rsa_pkcs1.pem");
    // `-traditional` forces the PKCS#1 label on OpenSSL 3.x.
    let out = run("openssl", &["genrsa", "-traditional", "-out", p.to_str().unwrap(), "2048"]);
    assert!(out.status.success(), "openssl genrsa: {}", String::from_utf8_lossy(&out.stderr));
    let head = std::fs::read_to_string(&p).unwrap();
    assert!(head.starts_with("-----BEGIN RSA PRIVATE KEY-----"), "fixture is not PKCS#1: {}", &head[..40.min(head.len())]);
    p
}

fn to_pkcs8(dir: &Path, pkcs1: &Path) -> PathBuf {
    let p = dir.join("rsa_pkcs8.pem");
    must("openssl", &["pkcs8", "-topk8", "-nocrypt", "-in", pkcs1.to_str().unwrap(), "-out", p.to_str().unwrap()]);
    p
}

fn to_pkcs8_encrypted(dir: &Path, pkcs1: &Path) -> PathBuf {
    let p = dir.join("rsa_pkcs8_enc.pem");
    must("openssl", &["pkcs8", "-topk8", "-in", pkcs1.to_str().unwrap(), "-out", p.to_str().unwrap(), "-passout", "pass:testpass"]);
    p
}

/// Legacy OpenSSL encrypted PKCS#1 (`Proc-Type: 4,ENCRYPTED` / `DEK-Info`).
fn to_pkcs1_encrypted(dir: &Path, pkcs1: &Path) -> PathBuf {
    let p = dir.join("rsa_pkcs1_enc.pem");
    must("openssl", &["rsa", "-in", pkcs1.to_str().unwrap(), "-out", p.to_str().unwrap(), "-aes128", "-passout", "pass:testpass", "-traditional"]);
    let text = std::fs::read_to_string(&p).unwrap();
    assert!(text.contains("Proc-Type:") && text.contains("ENCRYPTED"), "legacy PKCS#1 encryption header missing");
    p
}

fn gen_openssh(dir: &Path) -> PathBuf {
    let p = dir.join("openssh_rsa");
    must("ssh-keygen", &["-t", "rsa", "-b", "2048", "-N", "", "-q", "-f", p.to_str().unwrap()]);
    p
}

/// OpenSSH public key that ssh-keygen derives from a private key file.
fn ssh_keygen_pub(src: &Path) -> PublicKey {
    let out = run("ssh-keygen", &["-y", "-f", src.to_str().unwrap()]);
    assert!(out.status.success(), "ssh-keygen -y: {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).unwrap();
    PublicKey::from_openssh(text.trim()).expect("parse ssh-keygen pub")
}

/// REPRO: the old loader (OpenSSH armor only) FAILS on a PKCS#1 PEM.
#[test]
fn old_openssh_only_loader_fails_on_pkcs1() {
    let dir = scratch();
    let pkcs1 = gen_pkcs1(dir.path());
    let text = std::fs::read_to_string(&pkcs1).unwrap();
    assert!(ssh_key::PrivateKey::from_openssh(&text).is_err(), "old OpenSSH-only parse accepted PKCS#1 PEM");
}

/// NEW: PKCS#1 loads, its public key equals ssh-keygen's view of the same
/// file, and an auth blob round-trips through verify_auth.
#[test]
fn pkcs1_loads_signs_and_verifies() {
    let dir = scratch();
    let pkcs1 = gen_pkcs1(dir.path());
    let signer = FileSigner::load(&pkcs1).expect("PKCS#1 load");
    let ref_pub = ssh_keygen_pub(&pkcs1);
    assert!(same_key(signer.public_key(), &ref_pub), "PKCS#1 public key != ssh-keygen-derived");
    let exporter = [7u8; EXPORTER_LEN];
    let sig = sign_auth(&signer, &exporter, "tester", Intent::New).expect("sign_auth");
    let blob = pubkey_blob(signer.public_key()).expect("pubkey_blob");
    let verified = verify_auth(&exporter, "tester", &blob, Intent::New, &sig).expect("verify_auth");
    assert!(same_key(&verified, signer.public_key()), "verified key != signer key");
}

/// PKCS#8 (unencrypted) of the SAME key yields the same public key as PKCS#1
/// and also signs+verifies.
#[test]
fn pkcs8_matches_pkcs1_public_key() {
    let dir = scratch();
    let pkcs1 = gen_pkcs1(dir.path());
    let pkcs8 = to_pkcs8(dir.path(), &pkcs1);
    let p1 = FileSigner::load(&pkcs1).expect("PKCS#1 load");
    let p8 = FileSigner::load(&pkcs8).expect("PKCS#8 load");
    assert!(same_key(p1.public_key(), p8.public_key()), "PKCS#8 public key differs from PKCS#1");
    let exporter = [9u8; EXPORTER_LEN];
    let sig = sign_auth(&p8, &exporter, "tester", Intent::Resume).expect("sign");
    let blob = pubkey_blob(p8.public_key()).unwrap();
    verify_auth(&exporter, "tester", &blob, Intent::Resume, &sig).expect("verify");
}

/// OpenSSH RSA control: the retained OpenSSH path still loads and verifies.
#[test]
fn openssh_rsa_control_still_works() {
    let dir = scratch();
    let key = gen_openssh(dir.path());
    let s = FileSigner::load(&key).expect("OpenSSH load");
    let exporter = [3u8; EXPORTER_LEN];
    let sig = sign_auth(&s, &exporter, "tester", Intent::New).expect("sign");
    let blob = pubkey_blob(s.public_key()).unwrap();
    verify_auth(&exporter, "tester", &blob, Intent::New, &sig).expect("verify");
}

/// Encrypted PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`) is rejected explicitly.
#[test]
fn encrypted_pkcs8_is_rejected() {
    let dir = scratch();
    let pkcs1 = gen_pkcs1(dir.path());
    let enc = to_pkcs8_encrypted(dir.path(), &pkcs1);
    match FileSigner::load(&enc) {
        Err(Error::EncryptedKey { .. }) => {}
        Err(other) => panic!("expected EncryptedKey, got {other:?}"),
        Ok(_) => panic!("encrypted PKCS#8 was accepted"),
    }
}

/// CONTROL (acc0): legacy OpenSSL encrypted PKCS#1 (`BEGIN RSA PRIVATE KEY`
/// with `Proc-Type: 4,ENCRYPTED`) is rejected as EncryptedKey, not fed to the
/// PKCS#1 decoder as an opaque Base64 error.
#[test]
fn encrypted_legacy_pkcs1_is_rejected() {
    let dir = scratch();
    let pkcs1 = gen_pkcs1(dir.path());
    let enc = to_pkcs1_encrypted(dir.path(), &pkcs1);
    match FileSigner::load(&enc) {
        Err(Error::EncryptedKey { .. }) => {}
        Err(other) => panic!("expected EncryptedKey for legacy encrypted PKCS#1, got {other:?}"),
        Ok(_) => panic!("encrypted legacy PKCS#1 was accepted"),
    }
}

/// Malformed PKCS#1 produces a clear parse error, never EncryptedKey, never Ok.
#[test]
fn malformed_pkcs1_errors_cleanly() {
    let dir = scratch();
    let pkcs1 = gen_pkcs1(dir.path());
    let text = std::fs::read_to_string(&pkcs1).unwrap();
    let malformed = dir.path().join("rsa_malformed.pem");
    // Keep the label, corrupt the body.
    let mut lines: Vec<&str> = text.lines().collect();
    lines.truncate(3);
    std::fs::write(&malformed, lines.join("\n")).unwrap();
    match FileSigner::load(&malformed) {
        Err(Error::EncryptedKey { .. }) => panic!("malformed misclassified as encrypted"),
        Err(_) => {}
        Ok(_) => panic!("malformed PKCS#1 was accepted"),
    }
}

/// DIRECT CRT GUARD (acc0): the sign path reconstructs RSA from n/e/d/p/q and
/// may not exercise the STORED iqmp. Call `rsa_to_keypair` directly and assert
/// the stored OpenSSH iqmp satisfies the CRT identity `q * iqmp mod p == 1`,
/// and that p < q is NOT assumed wrongly (iqmp is q^-1 mod p). Also assert the
/// rebuilt keypair's public key matches ssh-keygen's, binding the stored
/// material to an external tool.
#[test]
fn stored_iqmp_satisfies_crt_identity() {
    use rsa::BigUint;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use ssh_key::private::KeypairData;

    let dir = scratch();
    let pkcs1 = gen_pkcs1(dir.path());
    let text = std::fs::read_to_string(&pkcs1).unwrap();
    let sk = rsa::RsaPrivateKey::from_pkcs1_pem(&text).expect("decode PKCS#1");
    let kp = rsa_to_keypair(&sk).expect("rsa_to_keypair");
    let KeypairData::Rsa(rsa_kp) = kp else { panic!("not an RSA keypair") };

    // Pull the STORED OpenSSH components (not the ones the sign path rebuilds).
    let pos = |m: &ssh_key::Mpint| BigUint::from_bytes_be(m.as_positive_bytes().expect("positive mpint"));
    let p = pos(&rsa_kp.private.p);
    let q = pos(&rsa_kp.private.q);
    let iqmp = pos(&rsa_kp.private.iqmp);

    // OpenSSH stores iqmp = q^{-1} mod p, so (q * iqmp) mod p == 1.
    let one = BigUint::from(1u8);
    assert_eq!((&q * &iqmp) % &p, one, "stored iqmp is not q^-1 mod p (CRT identity broken)");

    // Bind the rebuilt keypair's public key to ssh-keygen's view of the file.
    let ref_pub = ssh_keygen_pub(&pkcs1);
    let rebuilt_pub = ssh_key::PrivateKey::new(KeypairData::Rsa(rsa_kp), "")
        .expect("PrivateKey::new")
        .public_key()
        .clone();
    assert!(same_key(&rebuilt_pub, &ref_pub), "rebuilt public key != ssh-keygen-derived");
}
