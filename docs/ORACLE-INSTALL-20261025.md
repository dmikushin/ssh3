# Oracle SSH3 Rust installation — 2026-10-25

## Installed endpoint

- Source: `57bd5d5da1f94e8d4afca4e5aed05db9908bb6e7`.
- Host: `oracle` / `glazomer.io`, IPv4 `152.67.87.200`, UDP `60900`.
- Account: `marcusmae`; additive deployment, serving this account only.
- Server: `/home/marcusmae/.local/opt/ssh3-rs-57bd5d5/ssh3-server`.
- Configuration: same directory, `server.toml`; endpoint state and dedicated host key also in this private directory.
- SHA256 server: `8c6f7e1d79d3ce6c49760fab78234d7d94724a9ba36c25afa825b1e1d40462b1`.
- Unit: `/home/marcusmae/.config/systemd/user/ssh3-rs.service`.
- Verified after linger authorization: `Linger=yes`, `UnitFileState=enabled`, `ActiveState=active`, `SubState=running`, PID `5426`.
- Unit restarts failures; `KillMode=process` preserves detached child semantics. No reboot was performed to test boot startup.

## Installed client on gambetta

- Executable: `/home/marcusmae/.local/bin/ssh3-rs`.
- SHA256: `d455dfda32d402972fc28951d1a17835eecb92f31c74f40fba9822dfaab7146d`.
- Configuration: `/home/marcusmae/.config/ssh3-rs/config`, alias `oracle-rs`.
- Strict host pin: `/home/marcusmae/.config/ssh3-rs/known_hosts`.
- Existing public IdentityFile `~/.ssh/keys/id_rsa.oracle.pub` selects the private key in ssh-agent; no private key copied.
- Explicit `PredictiveEcho always` enables immediate local echo on this route.

Self-tested command:

```sh
~/.local/bin/ssh3-rs -F ~/.config/ssh3-rs/config oracle-rs
```

The same executable/config ran `printf 'permanent-client-route-ok\n'; hostname` and returned `permanent-client-route-ok`, `glazomer.io`, exit 0.

## Actual interactive acceptance

QA drove the installed server with the exact release client, strict pin and real PTY, without bulk load:

- Always: five key-to-visible-cell samples, median **0.575 ms** (0.372–0.807 ms).
- Never: five samples, median **6.922 ms** (6.722–37.686 ms).
- First output: 687.479 ms always, 262.149 ms never; prediction does not establish faster connection startup.
- Remote received `abcdefg` exactly; remote resize `24x80` to `30x100`; raw mode during attach and termios restoration on exit verified; both sessions exit 0.
- Separate adaptive/reconnect session: client idle timeout 3 s, SIGSTOP 5 s, SIGCONT; session `d7d51ce6911f9e7a4c3da70b3b5804d6` resumed at epoch 2; remote shell PID **5754** unchanged; `ACK:abcdefghijk PID=5754` exact; resize, terminal restoration and orderly exit 0.
- Adaptive median key-to-PTY-output **6.869 ms**, not a measurement of SRTT or proof of prediction activation.
- Local focused acceptance: 15 core controls + 3 PTY checks + 1 delayed-relay echo test passed.
- Final server snapshot: RSS 5040 KiB, HWM 8528 KiB, 4 threads. RSS varies with paging; HWM is not a total allocation bound.

Local evidence: `~/scratch/ssh-udp/{acceptance-57bd-results.json,canary-57bd-interactive.log,canary-57bd-adaptive.log,canary-adaptive-transcript.bin}`. Build log: `~/scratch/ssh-udp/rollout-build-20261025/build.log`. Evidence logs contain environment details and are not published in this commit.

## Safety, limits and rollback

Existing Go service on UDP 443, TCP SSH fallback on 2221, reverse tunnels and live mosh users were left unchanged. No firewall modifications, reboot, swap changes or load generators on Oracle.

Oracle has 952 MiB RAM and heavy existing memory/swap pressure. The new service uses two workers and limits: sessions 16, unauthenticated connections 4, channels 16, lane send and credit budgets 1 MiB each, connection-window budget 2 MiB, reassembly budget 256 KiB, UDP flows 16. These are component budgets, not a hard process-RSS ceiling.

Rollback only the newly installed service:

```sh
ssh oracle 'systemctl --user disable --now ssh3-rs.service'
```

The old Go endpoint, old client and SSH fallback remain available. No removal of binaries, private identity material or old service configuration is necessary for rollback. Linger was explicitly authorized and enabled; do not disable it without checking whether other user services rely on it.

## Not claimed

- No reboot-based startup test.
- No replacement of Go UDP 443 or existing multi-host tunnel/container deployment.
- No proof of IPv4 LTE/CGNAT traversal across independent networks.
- No claim that the original 1000-flow storage-shortfall trigger is fixed. The published change fixes proven receive-commit atomicity and rollback; that field trigger remains unresolved.
- No full production-security clearance is implied by the focused tests.
