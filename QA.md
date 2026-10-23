# ssh3-rs acceptance QA

Owner: the release/QA agent. This plan is derived from `SPEC.md` §0 (objectives)
and §8 (robustness invariants) and from nothing else: every test below names the
objective or invariant it falsifies if it fails. Tests are black-box — they drive
`ssh3` / `ssh3-server` binaries and read `--stats` (I6) — so they stay valid
across internal rewrites.

## Rules this suite obeys

- **Loopback first.** Every test in §1–§6 runs on one host over `127.0.0.1` /
  `[::1]` with freshly generated keys in a temp `$HOME`. Real hosts (oracle,
  gambetta, corentin) appear only in §7, and only for what loopback physically
  cannot show (NAT, real RTT, real loss).
- **No waiting as a substitute for a result.** No test sleeps for a protocol
  timer. Every timer a test depends on (`SessionLinger`, `max_idle_timeout`,
  keep-alive, `LoginGraceTime`, lane ack interval, scheduler hysteresis) must be
  settable from configuration, and the test sets it to the smallest value that
  still exercises the logic. **This is a requirement on the implementation, not
  a convenience:** a hard-coded 12 h linger or 30 s idle timeout makes O2
  untestable and will be reported as a defect.
- **Event-driven synchronisation.** Tests wait on observable events — a line on
  stdout, a counter crossing a value in `--stats`, a socket accept — never on a
  fixed duration. A test that cannot express its precondition as an event is a
  sign the server lacks an introspection counter (I6); that too is reported.
- **Every test states its own falsification.** For each case: what passing
  proves, and what the failure looks like. A test whose failure mode is "it
  hangs" is rewritten until it fails loudly.
- **Logs are kept.** Each run tees to `~/scratch/ssh-udp/qa-<case>.log`; a
  failure is reported to the coordinator with that log, not with a paraphrase.

## 0. Build gate (done, proven)

| id | check | status |
|----|-------|--------|
| B1 | `scripts/build-release.sh` produces x86_64 musl binaries with **no INTERP segment and no DT_NEEDED** | mechanism verified on `~/scratch/ssh-udp/static-probe`; enforced by the script itself, which exits non-zero otherwise |
| B2 | artifact executes on oracle (Ubuntu 20.04, glibc 2.31, no musl loader) | verified 2026-10-23: default musl static-PIE fails there with exit 127 (`No such file or directory`, INTERP `/lib/ld-musl-x86_64.so.1` absent); `-C relocation-model=static` runs |
| B3 | jemalloc with `background_thread:true` (SPEC §1) initialises and purges under static musl on oracle | verified on oracle with the probe |
| B4 | byte-reproducible: two builds in different target dirs give equal sha256 | verified (`--repro`, equal hashes incl. across an unrelated earlier build) |
| B5 | release profile keeps `panic = "unwind"` (I2) | asserted in `Cargo.toml` with the reason inline |

B1–B4 are re-run against the real workspace the moment a binary crate lands; the
status column above records what has been proven on the *toolchain*, which is the
part that could be wrong independently of our code.

## 1. O1 Bounded memory

| id | case | procedure | pass criterion | failure means |
|----|------|-----------|----------------|---------------|
| M1 | idle connection cost | open N=200 authenticated sessions, no channels; read RSS and `--stats` | RSS − baseline ≤ N × (floor windows + fixed overhead) as computed from config, with a stated margin; `--stats` connection count = N | per-connection state is not bounded by config (O1) |
| M2 | stalled reader does not pin memory | 50 connections × 50 channels, peer never reads its lane | RSS bounded by Σ(2 × `LaneBuffer`) over open lanes + floor windows; sender stops reading its source (observable: local pipe fills) | lane windows (§4) are not enforced; this is Go bug class "4.5 h stall" / E4's 64 MiB-per-connection |
| M3 | budget is global, not per-connection | set budget B, drive 10 connections at window-limited rate | Σ granted windows ≤ B + Σ floors at all times, read from `--stats` | the scheduler (§1) over-commits |
| M4 | shrink debt is charged | raise a connection to the ceiling, lower it, immediately ask for a raise elsewhere | the second raise is refused until the debt is read (X6(b) accounting rule) | budget is double-spent: the quinn `receive_window_shrink_debt` hazard is unhandled |
| M5 | drain returns memory | after M2, close everything | RSS returns to within a stated bound of baseline | allocator/leak regression; X3 is the known open item and the bound must be stated, not assumed |
| M6 | channel caps never queue | exceed `MaxChannels` per connection and server-wide | `Fail{ResourceLimit}` per §4, promptly, and no RSS growth | unbounded queueing (Go: 71k leaked registry entries) |
| M7 | UDP flow table bounded | `forwarded-udp` from 10k distinct sources | flow count ≤ cap, LRU/idle eviction visible in `--stats` | Go bug class 4 (1.4 GB growth) reproduced |
| M8 | fragment reassembly bounded | send fragment groups that are never completed | in-flight group count ≤ cap, oldest evicted (§6) | peer-controlled growth |

## 2. O1 pre-auth limits (§2.3, Go bug classes 1 and 3)

| id | case | pass criterion |
|----|------|----------------|
| A1 | second stream before auth | connection closed with a named error |
| A2 | datagram before auth | connection closed |
| A3 | control frame > 16 KiB before auth | closed **before** allocation (I1): RSS does not move with the claimed length — test with a 4 GiB length prefix |
| A4 | auth never completes | closed at `LoginGraceTime` (set small) |
| A5 | more than `MaxStartups` unauthenticated connections | excess refused at accept, no per-connection allocation beyond quinn's |
| A6 | `MaxAuthTries` exceeded | closed |
| A7 | post-auth frame > 64 KiB claim | closed before allocation (I1) |

## 3. O2 Roaming

| id | case | procedure | pass criterion |
|----|------|-----------|----------------|
| R1 | migration, short outage | client rebinds its socket mid-transfer (E2 path) | transfer continues; recovery observed in ms, not seconds; byte stream intact end to end (sha256 of a pseudorandom payload) |
| R2 | resume across address change | kill the carrier, reconnect from a different loopback source address/family | `Resumed` with offsets; payload sha256 intact; **an open `-L` forward still carries bytes afterwards** |
| R3 | resume across long outage | kill carrier, wait past idle timeout (both set small), reconnect | as R2 |
| R4 | resume is key-bound | resume the session with a *different* key that is also in `authorized_keys` | `Fail` (§5); the session stays owned by the creating key |
| R5 | lane stream before `Resumed` | open a lane stream on the new carrier before the reply | connection closed (extension of I4) |
| R6 | bad received offset | resume claiming an offset outside `[acked, sent]` | protocol error, connection closed |
| R7 | superseding attach | attach a second carrier to one session | the older carrier is closed, data continues on the new one |
| R8 | no loss at the ring boundary | kill the carrier exactly while bytes are in quinn but not yet in the receive ring (forced by a stalled reader) | no byte is lost or duplicated: §5 `received_offset` semantics |
| R9 | server restart | restart the server with a persisted `reset_key` | client learns immediately via stateless reset (X5) and resumes, rather than waiting for idle timeout |
| R10 | dual-stack rebind | rebind v4 → dual-stack and back, per §5.1 | no "unrecognized peer" drop (X1 regression guard) |

## 4. O1+O2 isolation

| id | case | pass criterion |
|----|------|----------------|
| S1 | stalled channel does not block others | with one lane's sink stalled, a second channel on the same connection keeps transferring at full rate, and control-stream acks keep flowing (§4 "resume-ack deadlock") |
| S2 | stalled channel does not block resume | with a lane stalled, kill and resume the carrier; `Resumed` is exchanged without waiting for the stalled sink |
| S3 | slow datagram consumer | datagrams to a full channel queue are dropped **and counted** in `--stats`; the connection reader never stalls (§6) |

## 5. O4 OpenSSH parity

| id | case | pass criterion |
|----|------|----------------|
| P1 | `-L` | TCP payload round-trips, sha256 equal; `permitopen=` denial produces `Fail{reason}`, not a silent hang |
| P2 | `-R` | as P1 with `permitlisten=`; listener released immediately on SIGTERM (I5) |
| P3 | `-D` | SOCKS5 CONNECT and UDP ASSOCIATE both carry payload |
| P4 | `-J` | loopback gateway relay path works end to end; inner cert verified against the **target's** `known_hosts` (§7.2) — test that a gateway substituting its own key fails |
| P5 | exec / shell / subsystem | exit status and exit signal propagate; stderr arrives on lane 1 |
| P6 | pty | `window-change` resizes (observed via `stty size` in the remote shell); signals delivered |
| P7 | `~/.ssh/config` | `Host`, `Match host/originalhost/user/exec`, `Include`, `IdentityFile` (incl. `.pub` selecting an agent key), `ProxyJump`, `*Forward`, `User`, `Port`, `StrictHostKeyChecking` — each asserted by a case where the option changes the outcome |
| P8 | `known_hosts` | unknown → TOFU per `StrictHostKeyChecking`; mismatch → hard failure **naming file:line** (§2.1); hashed hostnames and `[host]:port` both resolved |
| P9 | `authorized_keys` options | `from=`, `no-port-forwarding`, `permitopen=`, `permitlisten=`, `command=` each enforced, each with a negative case |
| P10 | agent and agent forwarding | signing via `SSH_AUTH_SOCK`; forwarded agent usable on the remote side |
| P11 | key types | ed25519, ecdsa-nistp256/384, rsa-sha2-256/512 all authenticate |
| P12 | **differential against OpenSSH** | for P1–P3 and P7, run the identical scenario with `ssh` and with `ssh3` and require the same observable outcome (exit code, payload, which option won). Divergence is a parity defect even when ssh3's behaviour looks reasonable |

## 6. §8 invariants, directly

| id | invariant | how it is falsified |
|----|-----------|---------------------|
| I1 | no peer-sized allocation | A3, A7, M8 |
| I2 | panic kills one task only | inject a panic (debug-only fault point or a malformed peer that reaches one) on connection 1 of 2; connection 2 survives, the panic is logged **with the peer identity**, server stays up |
| I3 | accept loop never awaits per-connection work | point a channel open at a blackholed address; during the dial timeout, new connections are still accepted and authenticated without delay |
| I4 | session registered before auth ack | immediately after the `Auth` reply, open a channel and send a datagram with no gap; neither is seen for an unregistered session |
| I5 | clean shutdown | SIGTERM/SIGINT: client sends CONNECTION_CLOSE with a reason; server's `-R` listener port is bindable immediately afterwards |
| I6 | introspection | every counter this suite depends on exists in `--stats` and is correct against an independently computed value |

## 7. Real-host stage (coordinated, never unattended)

Only after §1–§6 pass on loopback, and only with the coordinator's go-ahead.
Deployed services are not touched: probes run from an unprivileged account on
ports of their own.

| id | case | what loopback cannot show |
|----|------|---------------------------|
| N1 | hole punching oracle ↔ gambetta ↔ corentin | X4: real NAT mapping behaviour |
| N2 | direct-path upgrade and fallback | that loss of the direct path falls back to relay without breaking the inner connection (§7.3) |
| N3 | throughput at real RTT and real loss | X2/X7: BBR and the window scheduler on a path with a bottleneck queue, not i.i.d. loss |
| N4 | roaming across real networks | O2 on Wi-Fi ↔ mobile ↔ suspend |
| N5 | soak | memory flat over a long run; X3's residual RSS quantified rather than assumed |

## Reporting

A failure report to the coordinator names: the case id, the objective or
invariant it falsifies, the exact command, the log path, and the smallest
reproduction found. No report asserts a cause that was not shown by an
experiment.
