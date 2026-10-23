//! Regressions found by the architecture review of 6f133ef
//! (~/scratch/ssh-udp/review-config/tests/review.rs).

use std::path::PathBuf;
use std::process::{Command, Stdio};

use ssh3_config::{LocalEnv, resolve_args};

fn root(name: &str) -> PathBuf {
    let root = PathBuf::from(std::env::var("HOME").unwrap())
        .join("scratch/ssh-udp/config-test/review")
        .join(name);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn write(p: &std::path::Path, s: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(p, s).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn ssh_g(cfg: &std::path::Path) -> String {
    let out = Command::new("ssh")
        .args(["-G", "-F"])
        .arg(cfg)
        .arg("target")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn ours(cfg: &std::path::Path) -> ssh3_config::ClientConfig {
    let env = LocalEnv::from_system(22).unwrap();
    resolve_args(&["-F", cfg.to_str().unwrap(), "target"], &env).unwrap()
}

/// OpenSSH globs Include with POSIX glob(3) (GLOB_TILDE only): `**` is a
/// plain `*` and does not recurse.
#[test]
fn include_double_star_matches_posix_glob() {
    let r = root("double-star");
    std::fs::create_dir_all(r.join("conf/a/b")).unwrap();
    write(&r.join("conf/a/b/extra.conf"), "Port 2222\n");
    let cfg = r.join("config");
    write(
        &cfg,
        &format!("Include {}/conf/**/extra.conf\n", r.display()),
    );
    let ssh_port: u16 = ssh_g(&cfg)
        .lines()
        .find_map(|l| l.strip_prefix("port "))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(ours(&cfg).port, ssh_port);
}

/// A keyword ssh3 acts on must reach the typed configuration.
#[test]
fn gateway_ports_keyword_reaches_resolved_api() {
    let r = root("gatewayports");
    let cfg = r.join("config");
    write(&cfg, "GatewayPorts yes\n");
    assert!(ssh_g(&cfg).lines().any(|l| l == "gatewayports yes"));
    assert!(
        ours(&cfg).gateway_ports,
        "GatewayPorts yes ignored by typed configuration"
    );
}
