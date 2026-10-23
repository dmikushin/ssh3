//! Integration tests against real OpenSSH tools (ssh-keygen, ssh-agent,
//! ssh-add) and a real rustls TLS 1.3 handshake in memory.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use ssh3_keys::auth::{Intent, sign_auth, verify_auth, pubkey_blob};
use ssh3_keys::authorized_keys::AuthorizedKeys;
use ssh3_keys::host::HostIdentity;
use ssh3_keys::known_hosts::{self, KnownHosts};
use ssh3_keys::signer::{AgentClient, AgentSigner, FileSigner, Signer, read_public_key, resolve_identity};
use ssh3_keys::spki::public_key_from_cert;
use ssh3_keys::verifier::{KnownHostsVerifier, StrictHostKeyChecking};
use ssh3_keys::{Error, PublicKey};

const ALGS: &[(&str, &[&str])] = &[
    ("ed25519", &["-t", "ed25519"]),
    ("ecdsa256", &["-t", "ecdsa", "-b", "256"]),
    ("ecdsa384", &["-t", "ecdsa", "-b", "384"]),
    ("rsa3072", &["-t", "rsa", "-b", "3072"]),
];

fn scratch() -> tempfile::TempDir {
    let base = dirs_home().join("scratch/ssh-udp/keys-test");
    std::fs::create_dir_all(&base).unwrap();
    tempfile::Builder::new().prefix("t-").tempdir_in(base).unwrap()
}

fn dirs_home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("HOME"))
}

fn keygen(dir: &Path, name: &str, args: &[&str], passphrase: &str) -> PathBuf {
    let path = dir.join(name);
    let out = Command::new("ssh-keygen")
        .args(args)
        .args(["-q", "-N", passphrase, "-C", name, "-f"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success(), "ssh-keygen {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    path
}

fn pub_of(path: &Path) -> PublicKey {
    let mut p = path.as_os_str().to_owned();
    p.push(".pub");
    read_public_key(Path::new(&p)).unwrap()
}

fn kh_line(host: &str, key: &PublicKey) -> String {
    let mut k = key.clone();
    k.set_comment("");
    format!("{host} {}\n", k.to_openssh().unwrap())
}

/// Run a TLS 1.3 handshake fully in memory; Ok on success, the first error
/// otherwise.
fn handshake(server_id: &HostIdentity, verifier: Arc<KnownHostsVerifier>) -> Result<(), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let scfg = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![server_id.cert_der().clone()], server_id.private_key_der())
        .map_err(|e| format!("server config: {e}"))?;
    let ccfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let mut c = ClientConnection::new(Arc::new(ccfg), ServerName::try_from("ssh3-target").unwrap()).unwrap();
    let mut s = ServerConnection::new(Arc::new(scfg)).unwrap();
    for _ in 0..20 {
        if !c.is_handshaking() && !s.is_handshaking() {
            return Ok(());
        }
        let mut buf = Vec::new();
        while c.wants_write() {
            c.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            s.read_tls(&mut buf.as_slice()).unwrap();
            s.process_new_packets().map_err(|e| format!("server: {e}"))?;
        }
        let mut buf = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            c.read_tls(&mut buf.as_slice()).unwrap();
            c.process_new_packets().map_err(|e| format!("client: {e}"))?;
        }
    }
    Err("handshake did not complete in 20 flights".into())
}

#[test]
fn host_identity_cert_carries_the_host_key_for_every_algorithm() {
    let d = scratch();
    for (name, args) in ALGS {
        let path = keygen(d.path(), &format!("host_{name}"), args, "");
        let id = HostIdentity::load(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
        let from_cert = public_key_from_cert(id.cert_der()).unwrap();
        assert_eq!(from_cert.key_data(), pub_of(&path).key_data(), "{name}: SPKI != host key");
        id.certified_key().unwrap_or_else(|e| panic!("{name}: rustls signing key: {e}"));
    }
}

#[test]
fn tls_handshake_accepts_known_key_and_rejects_others() {
    let d = scratch();
    for (name, args) in ALGS {
        let host = keygen(d.path(), &format!("srv_{name}"), args, "");
        let other = keygen(d.path(), &format!("oth_{name}"), args, "");
        let id = HostIdentity::load(&host).unwrap();

        // Known key → accepted.
        let kh = d.path().join(format!("kh_ok_{name}"));
        std::fs::write(&kh, kh_line("target.example", &pub_of(&host))).unwrap();
        let v = Arc::new(KnownHostsVerifier::new("target.example", 22, vec![kh], StrictHostKeyChecking::Yes));
        handshake(&id, v.clone()).unwrap_or_else(|e| panic!("{name}: known key refused: {e}"));
        assert_eq!(v.verified_key().unwrap().key_data(), pub_of(&host).key_data());

        // Different key of the same type at line 2 → mismatch naming file:line.
        let kh = d.path().join(format!("kh_bad_{name}"));
        std::fs::write(&kh, format!("# comment\n{}", kh_line("target.example", &pub_of(&other)))).unwrap();
        for mode in [StrictHostKeyChecking::Yes, StrictHostKeyChecking::No, StrictHostKeyChecking::AcceptNew] {
            let v = Arc::new(KnownHostsVerifier::new("target.example", 22, vec![kh.clone()], mode));
            let err = handshake(&id, v).expect_err("mismatch accepted");
            assert!(err.contains("HOST KEY MISMATCH"), "{name}: {err}");
            assert!(err.contains(&format!("{}:2", kh.display())), "{name}: no file:line in {err}");
        }
    }
}

#[test]
fn unknown_host_modes_and_append() {
    let d = scratch();
    let host = keygen(d.path(), "srv", &["-t", "ed25519"], "");
    let id = HostIdentity::load(&host).unwrap();
    let kh = d.path().join("known_hosts");

    let v = Arc::new(KnownHostsVerifier::new("new.example", 2222, vec![kh.clone()], StrictHostKeyChecking::Yes));
    let err = handshake(&id, v).unwrap_err();
    assert!(err.contains("not in known_hosts"), "{err}");
    assert!(!kh.exists());

    // ask → prompt refuses
    let v = KnownHostsVerifier::new("new.example", 2222, vec![kh.clone()], StrictHostKeyChecking::Ask)
        .with_prompt(Arc::new(|u| {
            assert_eq!(u.port, 2222);
            false
        }));
    assert!(handshake(&id, Arc::new(v)).is_err());

    // accept-new with hashing → appended hashed line; OpenSSH finds it.
    let v = KnownHostsVerifier::new("new.example", 2222, vec![kh.clone()], StrictHostKeyChecking::AcceptNew)
        .hash_known_hosts(true);
    handshake(&id, Arc::new(v)).unwrap();
    let text = std::fs::read_to_string(&kh).unwrap();
    assert!(text.starts_with("|1|"), "{text}");
    let out = Command::new("ssh-keygen").args(["-F", "[new.example]:2222", "-f"]).arg(&kh).output().unwrap();
    assert!(out.status.success(), "ssh-keygen -F did not find our hashed entry: {text}");

    // Now known: strict yes accepts.
    let v = Arc::new(KnownHostsVerifier::new("new.example", 2222, vec![kh.clone()], StrictHostKeyChecking::Yes));
    handshake(&id, v).unwrap();
    // Port 22 is a different lookup name.
    let v = Arc::new(KnownHostsVerifier::new("new.example", 22, vec![kh.clone()], StrictHostKeyChecking::Yes));
    assert!(handshake(&id, v).is_err());
}

#[test]
fn accept_new_refuses_when_other_key_types_are_known() {
    let d = scratch();
    let host = keygen(d.path(), "srv", &["-t", "ed25519"], "");
    let rsa = keygen(d.path(), "srv_rsa", &["-t", "rsa", "-b", "2048"], "");
    let kh = d.path().join("known_hosts");
    std::fs::write(&kh, kh_line("h.example", &pub_of(&rsa))).unwrap();
    let id = HostIdentity::load(&host).unwrap();
    let v = Arc::new(KnownHostsVerifier::new("h.example", 22, vec![kh.clone()], StrictHostKeyChecking::AcceptNew));
    let err = handshake(&id, v).unwrap_err();
    assert!(err.contains("keys of other types are known") && err.contains(&format!("{}:1", kh.display())), "{err}");
}

#[test]
fn revoked_and_cert_authority_markers() {
    let d = scratch();
    let host = keygen(d.path(), "srv", &["-t", "ed25519"], "");
    let id = HostIdentity::load(&host).unwrap();
    let kh = d.path().join("known_hosts");
    let k = kh_line("*", &pub_of(&host));
    std::fs::write(&kh, format!("{}@revoked {k}", kh_line("h.example", &pub_of(&host)))).unwrap();
    let v = Arc::new(KnownHostsVerifier::new("h.example", 22, vec![kh.clone()], StrictHostKeyChecking::No));
    let err = handshake(&id, v).unwrap_err();
    assert!(err.contains("@revoked") && err.contains(&format!("{}:2", kh.display())), "{err}");

    // A CA line for the host's own key does not vouch for it.
    std::fs::write(&kh, format!("@cert-authority {k}")).unwrap();
    let v = Arc::new(KnownHostsVerifier::new("h.example", 22, vec![kh], StrictHostKeyChecking::Yes));
    assert!(handshake(&id, v).unwrap_err().contains("not in known_hosts"));
}

#[test]
fn hashed_entries_produced_by_ssh_keygen_are_found() {
    let d = scratch();
    let a = pub_of(&keygen(d.path(), "a", &["-t", "ed25519"], ""));
    let b = pub_of(&keygen(d.path(), "b", &["-t", "ecdsa"], ""));
    let kh = d.path().join("known_hosts");
    std::fs::write(&kh, format!("{}{}", kh_line("host1.example", &a), kh_line("[host2.example]:2222", &b))).unwrap();
    let out = Command::new("ssh-keygen").arg("-H").arg("-f").arg(&kh).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = std::fs::read_to_string(&kh).unwrap();
    assert!(text.lines().all(|l| l.starts_with("|1|")), "{text}");

    let parsed = KnownHosts::parse(&kh, &text);
    assert!(parsed.bad_lines.is_empty(), "{:?}", parsed.bad_lines);
    let h1 = parsed.lookup("host1.example", 22);
    assert_eq!(h1.len(), 1);
    assert_eq!(h1[0].key.key_data(), a.key_data());
    let h2 = parsed.lookup("HOST2.example", 2222);
    assert_eq!(h2.len(), 1);
    assert_eq!(h2[0].key.key_data(), b.key_data());
    assert!(parsed.lookup("host2.example", 22).is_empty());
    assert!(parsed.lookup("host3.example", 22).is_empty());
}

#[test]
fn plain_patterns_comma_lists_and_negation() {
    let d = scratch();
    let a = pub_of(&keygen(d.path(), "a", &["-t", "ed25519"], ""));
    let kh = d.path().join("known_hosts");
    std::fs::write(&kh, kh_line("alias,*.corp.example,!bad.corp.example,[10.0.0.1]:2200", &a)).unwrap();
    let p = KnownHosts::load(&[kh]).unwrap();
    assert_eq!(p.lookup("alias", 22).len(), 1);
    assert_eq!(p.lookup("x.corp.example", 22).len(), 1);
    assert!(p.lookup("bad.corp.example", 22).is_empty());
    assert_eq!(p.lookup("10.0.0.1", 2200).len(), 1);
    assert!(p.lookup("10.0.0.1", 22).is_empty());
}

#[test]
fn append_plain_entry_is_found_by_ssh_keygen() {
    let d = scratch();
    let a = pub_of(&keygen(d.path(), "a", &["-t", "ed25519"], ""));
    let kh = d.path().join("sub/known_hosts");
    known_hosts::append(&kh, "plain.example", 22, &a, false).unwrap();
    let out = Command::new("ssh-keygen").args(["-F", "plain.example", "-f"]).arg(&kh).output().unwrap();
    assert!(out.status.success());
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&kh).unwrap().permissions().mode() & 0o777, 0o600);
}

struct Agent {
    child: Child,
    sock: PathBuf,
}

impl Agent {
    fn start(dir: &Path) -> Self {
        let sock = dir.join("agent.sock");
        let mut child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // ssh-agent -D binds the socket before serving; wait for it to appear
        // by connecting (bounded: 200 × 5 ms).
        for _ in 0..200 {
            if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
                return Self { child, sock };
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("ssh-agent did not create {}", sock.display());
    }

    fn add(&self, key: &Path) {
        let out = Command::new("ssh-add").env("SSH_AUTH_SOCK", &self.sock).arg(key).output().unwrap();
        assert!(out.status.success(), "ssh-add: {}", String::from_utf8_lossy(&out.stderr));
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        // Kill exactly the agent this test started, by its own PID.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn agent_and_file_signers_produce_verifiable_auth_signatures() {
    let d = scratch();
    let agent = Agent::start(d.path());
    let client = AgentClient::new(&agent.sock);
    let exporter = [7u8; 32];
    for (name, args) in ALGS {
        let key = keygen(d.path(), &format!("user_{name}"), args, "");
        agent.add(&key);
        let pubk = pub_of(&key);

        let agent_signer = AgentSigner::for_pub_file(client.clone(), &d.path().join(format!("user_{name}.pub"))).unwrap();
        let file_signer = FileSigner::load(&key).unwrap();
        let signers: [(&str, &dyn Signer); 2] = [("agent", &agent_signer), ("file", &file_signer)];
        for (kind, s) in signers {
            let sig = sign_auth(s, &exporter, "alice", Intent::New).unwrap_or_else(|e| panic!("{name}/{kind}: {e}"));
            let blob = pubkey_blob(&pubk).unwrap();
            let k = verify_auth(&exporter, "alice", &blob, Intent::New, &sig).unwrap_or_else(|e| panic!("{name}/{kind}: {e}"));
            assert_eq!(k.key_data(), pubk.key_data());
            // Any change to the bound context breaks the signature.
            assert!(verify_auth(&[8u8; 32], "alice", &blob, Intent::New, &sig).is_err(), "{name}/{kind}: exporter");
            assert!(verify_auth(&exporter, "alicf", &blob, Intent::New, &sig).is_err(), "{name}/{kind}: user");
            assert!(verify_auth(&exporter, "alice", &blob, Intent::Resume, &sig).is_err(), "{name}/{kind}: intent");
        }
        if *name == "rsa3072" {
            let s256 = AgentSigner::new(client.clone(), pubk.clone()).rsa_hash(ssh_key::HashAlg::Sha256);
            let sig = sign_auth(&s256, &exporter, "alice", Intent::New).unwrap();
            verify_auth(&exporter, "alice", &pubkey_blob(&pubk).unwrap(), Intent::New, &sig).expect("rsa-sha2-256");
        }
    }
}

#[test]
fn resolve_identity_follows_openssh_rules() {
    let d = scratch();
    let agent = Agent::start(d.path());
    let client = AgentClient::new(&agent.sock);
    let in_agent = keygen(d.path(), "in_agent", &["-t", "ed25519"], "");
    let not_in_agent = keygen(d.path(), "not_in_agent", &["-t", "ed25519"], "");
    agent.add(&in_agent);

    // .pub held by the agent → agent signer (works even with the private file gone).
    std::fs::remove_file(&in_agent).unwrap();
    let s = resolve_identity(&d.path().join("in_agent.pub"), Some(&client)).unwrap();
    assert_eq!(s.public_key().key_data(), pub_of(&in_agent).key_data());
    s.sign(b"x").unwrap();

    // Private path whose key is not in the agent → file signer.
    let s = resolve_identity(&not_in_agent, Some(&client)).unwrap();
    s.sign(b"x").unwrap();

    // .pub not held by the agent → explicit error, no fallback.
    match resolve_identity(&d.path().join("not_in_agent.pub"), Some(&client)) {
        Err(Error::AgentKeyMissing { .. }) => {}
        Err(e) => panic!("wrong error: {e}"),
        Ok(_) => panic!("accepted .pub not held by agent"),
    }
    // .pub without an agent at all.
    assert!(matches!(resolve_identity(&d.path().join("in_agent.pub"), None), Err(Error::NoAgent)));
}

#[test]
fn encrypted_private_key_is_reported() {
    let d = scratch();
    let k = keygen(d.path(), "enc", &["-t", "ed25519"], "secret-passphrase");
    match FileSigner::load(&k) {
        Err(Error::EncryptedKey { path }) => assert_eq!(path, k),
        Err(e) => panic!("wrong error: {e}"),
        Ok(_) => panic!("encrypted key loaded"),
    }
    assert!(matches!(HostIdentity::load(&k), Err(Error::EncryptedKey { .. })));
}

#[test]
fn authorized_keys_options() {
    let d = scratch();
    let a = pub_of(&keygen(d.path(), "a", &["-t", "ed25519"], ""));
    let b = pub_of(&keygen(d.path(), "b", &["-t", "ecdsa"], ""));
    let c = pub_of(&keygen(d.path(), "c", &["-t", "ed25519"], ""));
    let line = |opts: &str, k: &PublicKey| format!("{opts} {}", k.to_openssh().unwrap());
    let text = [
        "# comment".to_string(),
        line(r#"from="10.0.0.0/8,!10.9.9.9,192.168.1.*",command="echo \"hi, there\"",no-pty,permitopen="host:22",permitopen="[::1]:80""#, &a),
        line("restrict,port-forwarding,permitlisten=\"localhost:8080\"", &a),
        line("expiry-time=\"20300101\"", &b),
        b.to_openssh().unwrap(),
        "garbage line".to_string(),
        line("restrict", &c),
    ]
    .join("\n");
    let f = d.path().join("authorized_keys");
    std::fs::write(&f, &text).unwrap();
    let ak = AuthorizedKeys::load(&f).unwrap();
    assert_eq!(ak.keys.len(), 5);
    assert_eq!(ak.bad_lines.len(), 1);
    assert_eq!(ak.bad_lines[0].1, 6);

    let first = &ak.keys[0].options;
    assert_eq!(first.command.as_deref(), Some("echo \"hi, there\""));
    assert_eq!(first.permitopen, vec!["host:22", "[::1]:80"]);
    assert!(!first.pty_allowed() && first.port_forwarding_allowed());

    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    // 10.1.2.3 admitted by line 2.
    assert_eq!(ak.authorize(&a, ip("10.1.2.3")).unwrap().line, 2);
    assert_eq!(ak.authorize(&a, ip("::ffff:192.168.1.7")).unwrap().line, 2);
    // 10.9.9.9 negated on line 2 → falls through to line 3 (restrict + port-forwarding).
    let l3 = ak.authorize(&a, ip("10.9.9.9")).unwrap();
    assert_eq!(l3.line, 3);
    assert!(l3.options.port_forwarding_allowed() && !l3.options.pty_allowed() && !l3.options.agent_forwarding_allowed());
    assert_eq!(l3.options.permitlisten, vec!["localhost:8080"]);

    // Unsupported option on line 4 refuses that line; plain line 5 admits.
    let lb = ak.authorize(&b, ip("1.2.3.4")).unwrap();
    assert_eq!(lb.line, 5);
    assert_eq!(ak.keys[2].options.unsupported, vec![("expiry-time".to_string(), Some("20300101".to_string()))]);

    let lc = ak.authorize(&c, ip("1.2.3.4")).unwrap();
    assert!(!lc.options.port_forwarding_allowed());

    let unknown = pub_of(&keygen(d.path(), "u", &["-t", "ed25519"], ""));
    assert!(ak.authorize(&unknown, ip("1.2.3.4")).is_err());
}

#[test]
fn authorized_keys_unsupported_only_line_is_refused_with_reason() {
    let d = scratch();
    let a = pub_of(&keygen(d.path(), "a", &["-t", "ed25519"], ""));
    let f = d.path().join("ak");
    std::fs::write(&f, format!("cert-authority,principals=\"x\" {}\n", a.to_openssh().unwrap())).unwrap();
    let ak = AuthorizedKeys::load(&f).unwrap();
    let err = ak.authorize(&a, "127.0.0.1".parse().unwrap()).unwrap_err();
    assert!(err.contains("cert-authority,principals") && err.contains(&format!("{}:1", f.display())), "{err}");
}
