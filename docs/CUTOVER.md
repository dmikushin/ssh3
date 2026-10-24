# Cut-over plan: Go ssh3 → ssh3-rs (oracle, gambetta, corentin)

Author: consultant agent acc0c9a35e4c366c9 (plan only), recorded by the
coordinator. Nothing here has been executed. Every step that touches a host
needs Dmitry's go-ahead.

Historical topology (from the Go-era transcript; must be re-inventoried before
use): oracle Go ssh3-server on UDP 443 + reverse-UDP 64443; gambetta Go
ssh3-server on UDP 443; autossh-ssh3 container reverse target 172.17.0.1:443;
corentin reaches gambetta via ProxyJump through oracle (UDP 64443).

## Hard constraints
- oracle (952 MB production VPS): artifacts and bounded /proc / cgroup reads
  only. No builds, Python, load generation or profiling there.
- Go and Rust speak different protocols: clients and servers move together per
  test path; Rust cannot resume Go sessions.
- Never `--network=host`; never SSH3_INSECURE (pinned host keys instead).

## 1. Inventory (bounded reads)
Exact ExecStart/unit/container definitions, namespaces, port owners, keys and
pins, versions, live forward owners on all three hosts. Back up binaries and
configs; write the exact rollback commands before changing anything. Check
ssh3-rs flags/config against the current code, not memory.

## 2. Build and test on gambetta only
`scripts/build-release.sh` static musl for oracle's architecture; artifact has
no INTERP/NEEDED; record sha256. Full workspace and e2e suites, plus the `mem`
scale test, locally.

## 3. Side by side on test ports
Choose unused UDP test ports after the inventory (e.g. 4443 on oracle and
gambetta — examples, not reservations). Separate service names, config, state,
pins, and a cgroup memory budget leaving measured headroom for production. Go
443/64443, the running container and corentin's default config stay untouched.

## 4. Order
oracle Rust server first → gambetta Rust server + Rust tunnel container to
oracle's test port (its -R / reverse UDP aimed at the gambetta Rust socket, not
Go 443) → Rust client on corentin as a separate binary with an explicit test
config. Exercise the real chain corentin → oracle → gambetta: shell, -L/-R/-D,
reverse UDP, peer auth, clean SessionEnd.

## 5. Gates (event-based, no fixed soak)
- Memory: cgroup memory.current/events, process RSS/PSS at baseline, peak and
  after quiescence; fds/tasks; ServerStats session/channel/flow/ring counters.
  Churn connections and UDP sources from gambetta; counters must return to
  baseline and the peak must stay within the budget.
- Behaviour: container restart, client restart, offline → resume, network
  change incl. IPv4-only NAT, relay loss, direct-path loss and fallback; byte
  hashes, order and half-close for TCP forwards.
- Optional longer low-rate observation with an explicit end and lightweight
  sampling.

## 6. Cut-over (only after all gates pass)
Announced maintenance (Go sessions cannot be resumed by Rust). Stop the
identified, authorised owners of 443/64443, bind Rust, run the real corentin
command immediately. Rollback stays ready.

## 7. Rollback
Stop only the Rust services/container; restore saved Go binaries, configs,
pins and original port owners; restart the original tunnel; run the old
corentin command and forward checks. Keep logs. Do not delete Go until the
rollback gate is retired.

## 8. Removing workarounds — by subtraction tests
Built-in resume may make autossh reconnect, tunnel-watchdog and ssh-shim
unnecessary; process supervision at boot and container restart stay. Remove a
piece only after showing what breaks without it is covered. SSH3_INSECURE is
replaced by verified pins. Relay / reverse UDP stays for hard NATs.
