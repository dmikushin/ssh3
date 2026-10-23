//! Behaviour specific to ssh3 (no `ssh -G` counterpart): UDP forwards and
//! the unknown-keyword deviation.

use ssh3_config::{Connect, Listen, LocalEnv, resolve_args};

fn cfg_dir(name: &str, config: &str) -> String {
    let home = std::env::var("HOME").unwrap();
    let dir = format!("{home}/scratch/ssh-udp/config-test/ssh3-only/{name}");
    std::fs::create_dir_all(&dir).unwrap();
    let path = format!("{dir}/config");
    std::fs::write(&path, config).unwrap();
    path
}

#[test]
fn udp_forward_flags_and_keywords() {
    let env = LocalEnv::from_system(443).unwrap();
    let cfg = cfg_dir(
        "udp",
        "LocalUDPForward 5353 10.0.0.1:53\nRemoteUDPForward 64443 172.17.0.1:443\n",
    );
    let c = resolve_args(
        &[
            "-F",
            &cfg,
            "-U",
            "127.0.0.1:5000:dns:53",
            "-u",
            "6000:[::1]:7000",
            "h",
        ],
        &env,
    )
    .unwrap();
    assert_eq!(c.port, 443, "ssh3 default port comes from LocalEnv");
    let l: Vec<String> = c
        .local_udp_forwards
        .iter()
        .map(|f| format!("{} {}", f.listen, f.connect))
        .collect();
    assert_eq!(l, ["[127.0.0.1]:5000 [dns]:53", "5353 [10.0.0.1]:53"]);
    let r: Vec<String> = c
        .remote_udp_forwards
        .iter()
        .map(|f| format!("{} {}", f.listen, f.connect))
        .collect();
    assert_eq!(r, ["6000 [::1]:7000", "64443 [172.17.0.1]:443"]);
    assert!(c.local_forwards.is_empty() && c.remote_forwards.is_empty());
}

#[test]
fn udp_forward_rejects_paths_and_dynamic() {
    let env = LocalEnv::from_system(443).unwrap();
    assert!(resolve_args(&["-F", "none", "-U", "/tmp/s:h:53", "h"], &env).is_err());
    assert!(resolve_args(&["-F", "none", "-u", "6000", "h"], &env).is_err());
    let cfg = cfg_dir("udp-bad", "RemoteUDPForward 6000\n");
    assert!(resolve_args(&["-F", &cfg, "h"], &env).is_err());
}

#[test]
fn unknown_keyword_kept_with_warning() {
    let env = LocalEnv::from_system(22).unwrap();
    let cfg = cfg_dir("unknown", "Host h\n  FutureKeyword a b\nPort 2200\n");
    let c = resolve_args(&["-F", &cfg, "h"], &env).unwrap();
    assert_eq!(c.port, 2200);
    assert_eq!(c.unknown.len(), 1);
    assert_eq!(c.unknown[0].keyword, "futurekeyword");
    assert_eq!(c.unknown[0].args, ["a", "b"]);
    assert_eq!(c.unknown[0].line, 2);
    assert!(c.warnings.iter().any(|w| w.contains("futurekeyword")));
}

#[test]
fn dynamic_and_local_split() {
    let env = LocalEnv::from_system(22).unwrap();
    let c = resolve_args(
        &["-F", "none", "-D", "1080", "-L", "8080:/run/x.sock", "h"],
        &env,
    )
    .unwrap();
    assert_eq!(c.dynamic_forwards.len(), 1);
    assert_eq!(
        c.dynamic_forwards[0].listen,
        Listen::Port {
            host: None,
            port: 1080
        }
    );
    assert_eq!(c.local_forwards.len(), 1);
    assert_eq!(
        c.local_forwards[0].connect,
        Connect::Path("/run/x.sock".into())
    );
}

#[test]
fn identity_pub_kept_and_expanded() {
    let env = LocalEnv::from_system(22).unwrap();
    let cfg = cfg_dir("idpub", "IdentityFile ~/.ssh/id_%h.pub\n");
    let c = resolve_args(&["-F", &cfg, "box"], &env).unwrap();
    assert_eq!(c.identity_files[0].raw, "~/.ssh/id_%h.pub");
    assert_eq!(
        c.identity_files[0].path.as_deref(),
        Some(format!("{}/.ssh/id_box.pub", env.home).as_str())
    );
}
