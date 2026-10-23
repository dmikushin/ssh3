# ssh3-rs protocol (draft 0)

Secure shell over QUIC, rewritten in Rust. This document is the protocol and
the design invariants. Wire compatibility with Go ssh3 / draft-michel-ssh3 is
**not** a goal.

## 0. Objectives (every design choice below traces to one of these)

- **O1 Bounded memory.** A server with hundreds of connections stays within a
  budget fixed by configuration. No peer, authenticated or not, can grow
  server state beyond a configured cap.
- **O2 Roaming.** A session survives client network changes and long outages
  (suspend, tunnel, Wi-Fi ↔ mobile), including open TCP forwards.
- **O3 NAT traversal.** Two peers behind NAT get a direct path via a
  rendezvous server, with simultaneous open; relay is the fallback, not the
  only path.
- **O4 OpenSSH parity for advanced users.** `-L/-R/-D/-J`, `~/.ssh/config`
  (incl. `Match`), `authorized_keys`, `known_hosts`, ssh-agent and agent
  forwarding, pty sessions, exec, subsystems.

Evidence base: `~/scratch/ssh-udp/quic-probe` (quinn 0.11.12 experiments
E1–E4) and the bug history of Go ssh3 (branch `quic-migration`, `SPEC.md`).

## 1. Transport

- Plain QUIC v1 (quinn), ALPN `ssh3-rs/0`. No HTTP/3. *(Go ssh3 bug classes
  from the H3 layer — hijack/ack ordering, H3 datagram layer eating raw
  datagrams — disappear with it.)*
- Default UDP port 443 (configurable).
- `EndpointConfig::grease_quic_bit(false)` on every endpoint: required so the
  fixed bit can demultiplex QUIC from punch/relay packets on one socket (E3c:
  with greasing on, QUIC packets were misrouted and the handshake failed).
- **Congestion control: BBR** (`congestion::BbrConfig`). X2: with 0.1 %
  random loss cubic collapses to 2–10 Mbit/s at any window; BBR reaches
  124 Mbit/s at 150 ms RTT with a 4 MiB window.
- **Global memory budget (O1).** Static per-connection windows cannot serve
  both objectives: X2 showed a tight window (256 KiB) gives 3.4 Mbit/s at
  150 ms RTT, while 4 MiB is needed for ≥100 Mbit/s; E4 showed quinn
  defaults (`receive_window` unlimited) let a stalled reader pin 64 MiB per
  connection. Therefore:
  - Every connection starts at a floor (`receive_window` = `send_window`
    = 256 KiB). `stream_receive_window` is static and set to the ceiling
    (8 MiB): X6(c) showed a raised connection window has no effect when the
    stream window is smaller (stayed 13–14 Mbit/s), and that a large static
    stream window costs nothing while the connection window is at the floor
    (+302 KiB/conn vs +305 KiB/conn for 64 KiB, 50×50 stalled readers).
  - X6(a): raising 256 KiB → 4 MiB at 150 ms RTT takes effect within ~1 RTT
    (12–14 → 83 → 205 Mbit/s in 250 ms steps).
  - **Accounting rule.** X6(b): lowering a window does not revoke credit
    already granted (4 MiB stayed buffered after lowering to 256 KiB;
    quinn-proto `receive_window_shrink_debt`, `streams/state.rs:948`). The
    scheduler therefore charges a connection `max(new window, old window)`
    until the application has read at least the old window's worth of bytes
    on that connection since the change; all reads go through lanes, so the
    count is exact.
  - **Raise rule.** A connection's windows are raised only if
    Σ charges (as defined above) + the increase ≤ budget. Lowering never
    frees budget immediately; it frees it as the debt is read. Hysteresis:
    raise after 2 consecutive RTT intervals at window-limited rate, lower
    after 5 s below 10 % utilisation.
  - A server-wide **window budget** (default 256 MiB, configurable) is
    allocated by a scheduler that raises a connection's windows via
    `Connection::set_receive_window` / `set_send_window` (quinn 0.11.12
    `connection.rs:651,658`) while it is transferring at window-limited
    rate, up to a ceiling (default 8 MiB), and lowers them when it idles or
    when the budget is contended. Σ granted windows ≤ budget + Σ floors.
  - `max_concurrent_bidi_streams` 64, `max_concurrent_uni_streams` 0,
    `datagram_receive_buffer_size` and `datagram_send_buffer_size` 64 KiB.
- **Allocator.** jemalloc with `background_thread:true` (or mimalloc).
  X3: after a 3.3 GB peak glibc kept 3.45 GB resident; jemalloc+bg thread
  returned to 399 MB, mimalloc to 368 MB. The residual ~300 MB above the
  30 MB baseline is unexplained (open item X3).
- **Stateless reset.** The server persists `reset_key` and uses
  `HashedConnectionIdGenerator::from_key` with a persisted key, so clients
  learn of a server restart immediately (X5: 1.35 ms) and go straight to
  resume (§5) instead of waiting for idle timeout.
- `max_idle_timeout` 30 s, keep-alive 5 s. The QUIC connection is a
  *disposable carrier*; outages longer than idle timeout are handled by
  session resume (§5), not by long idle timeouts.

## 2. Identity and authentication

### 2.1 Server identity
- The server presents a self-signed X.509 certificate generated at startup
  from an **OpenSSH host key** (default `/etc/ssh/ssh_host_ed25519_key`).
- The client verifies with a custom rustls verifier: the certificate's public
  key must match the host key recorded for that host in OpenSSH
  `known_hosts` (`~/.ssh/known_hosts`, `UserKnownHostsFile`), including
  hashed hostnames and `[host]:port` form. Unknown host → TOFU prompt per
  `StrictHostKeyChecking`. Mismatch → hard failure naming the file:line.
- Consequence: host keys and known_hosts are shared with OpenSSH; no second
  trust store.

### 2.2 User authentication
- After the handshake the client opens the **control stream** (first
  client bidi stream) and sends `Auth{user, pubkey, sig}` where
  `sig = Sign(key, "ssh3-rs auth v0" || exporter || str(user) ||
  str(pubkey_blob) || str(intent))`, where `str(x)` = u32 big-endian length
  || bytes (unambiguous concatenation), `pubkey_blob` is the OpenSSH wire
  encoding, `intent` is `"new"` or `"resume"`, and
  `exporter = TLS-Exporter("EXPORTER-ssh3-rs-auth", "", 32)` read **after**
  the handshake is confirmed. The server recomputes the same blob from its
  own exporter and verifies; nothing in the signed blob is taken from the
  client except `user`, `pubkey_blob`, `intent`.
- Keys: ed25519, ecdsa-sha2-nistp256/384, rsa-sha2-256/512. Signing via
  ssh-agent (`SSH_AUTH_SOCK`), or a private key file; `IdentityFile` may name
  a `.pub` to select the agent key.
- Server checks `~user/.ssh/authorized_keys` (OpenSSH format; options
  `from=`, `no-port-forwarding`, `permitopen=`, `permitlisten=`, `command=`
  honoured — subset listed in implementation).
- No timestamps, no tokens: auth cannot fail on clock skew.
- Multiple `Auth` attempts allowed up to `MaxAuthTries`, then close.

### 2.3 Pre-auth hard limits (O1, Go bug classes 1 and 3)
- Before successful auth the server accepts only the control stream; any
  other stream or datagram closes the connection.
- Control frames before auth: ≤ 16 KiB. Auth must complete within
  `LoginGraceTime` (default 10 s).
- Server-wide cap on concurrent unauthenticated connections
  (`MaxStartups`-like), enforced at accept before any per-connection
  allocation beyond quinn's.

## 3. Framing

- Control messages: `varint length || postcard(Message)`. Max frame size
  64 KiB after auth; a larger length prefix closes the connection **before**
  allocation.
- A message type unknown to the receiver closes the connection with an
  error naming the type (no silent ignore).
- Every request that can fail has an explicit reply (`Ok` / `Fail{reason}`);
  there are no fire-and-forget requests whose failure is invisible
  (Go ssh3 never sent OPEN_FAILURE).

## 4. Channels

A **channel** is a logical, resumable byte conversation identified by a
`chan_id` (u64, allocated by the opener: client even, server odd). A channel
has one or more **lanes**; each lane is an ordered byte stream per direction
(e.g. a session channel: lane 0 = stdin/stdout, lane 1 = stderr).

- Each lane is carried by a QUIC bidi stream that starts with
  `LaneHeader{chan_id, lane, offset_out}`. Thereafter the stream carries raw
  bytes. FIN = end of that direction.
- **Lane windows (application-level flow control, as SSH channel windows).**
  A sender may send lane bytes only up to `acked_offset + lane_window`, where
  `acked_offset` and `lane_window` come from the receiver's latest
  `LaneAck{chan_id, lane, offset, window}`. `offset` = bytes the receiver has
  accepted into its session-owned lane receive ring (§5). The receiver
  **always** drains every QUIC stream into the lane ring immediately; the ring
  is sized ≥ the window it advertised, so reading QUIC never blocks on the
  local sink.
  *Why:* without this, one lane whose local sink stalls (slow TCP peer,
  suspended terminal) keeps bytes in quinn and exhausts the connection-level
  credit, which then blocks every other lane **and the control stream that
  carries the acks** — head-of-line blocking across channels and a
  resume-ack deadlock (review D2; the same class as Go ssh3's 4.5 h stall).
  With lane windows, connection credit is only ever consumed transiently and
  the control stream cannot be starved.
- Lane windows are granted from the global budget (§1); Σ advertised lane
  windows on a connection ≤ its connection receive window minus a reserved
  64 KiB for the control stream.
- Channel lifecycle and control (open, ok/fail, pty-req, env, exec, shell,
  subsystem, window-change, signal, exit-status, exit-signal, close) are
  control-stream messages addressed by `chan_id`.
- Channel kinds: `session`, `direct-tcp` (-L, -D CONNECT), `forwarded-tcp`
  (-R), `direct-streamlocal` / `forwarded-streamlocal`, `direct-udp`,
  `forwarded-udp` (UDP over datagrams, §6), `agent` (agent forwarding),
  `jump` (-J, §7).
- **Ownership invariant.** Every channel and lane is an owned Rust value whose
  drop (normal end, error, panic unwinding) resets/finishes its QUIC streams
  and removes the channel from its registry. A stream is never left unread:
  an abandoned receive side is `stop()`ped so connection credit is returned.
  *(Go bug classes: 71k leaked registry entries / 490 MB; 4.5 h stall from
  leaked flow-control credit.)*
- Per-connection cap on channels (`MaxChannels`, default 256) and a
  server-wide cap; exceeding → `Fail{ResourceLimit}`, never queueing.

## 5. Sessions and resume (O2)

- A **session** owns: channels, pty(s), `-R` listeners, agent socket, the
  user identity. A QUIC connection is *attached* to at most one session.
- On auth success the server returns `SessionInfo{session_id (128-bit
  random), linger}`.
- **Reliable lanes.** Each lane direction has, on the sender, a send ring
  holding bytes sent but not yet acked, and on the receiver, a receive ring
  holding bytes accepted but not yet flushed to the local sink. Both rings
  are session state (they survive carrier death). The receiver acks via
  `LaneAck` (§4) every 16 KiB or 1 s, coalesced. When the send ring is full
  (unacked = peer window) the sender stops reading its local source (TCP
  socket, pty) — **backpressure, never growth**. `LaneBuffer` default
  256 KiB per direction, configurable per channel kind.
- **Received offset semantics.** `received_offset` = end of the bytes
  accepted into the receiver's receive ring. Bytes delivered to quinn but not
  yet copied into the ring are *not* counted, so a carrier death between the
  two cannot lose them: the sender still holds them and resends.
- **Detach.** When the carrier connection dies, the server keeps the session
  detached for `SessionLinger` (default 12 h, configurable; 0 disables).
  Local endpoints (pty, accepted TCP sockets, `-R` listeners) stay open and
  simply stop being read once their rings fill.
- **Resume.** The client opens a new QUIC connection (any address, any
  family), authenticates as in §2.2 with `intent="resume"`, and sends
  `Resume{session_id, [(chan_id, lane, received_offset)…]}`.
  - The session is owned by the **exact key** that created it; Resume with
    any other key — even one also present in authorized_keys — fails.
  - The server replies `Resumed{[(chan_id, lane, received_offset)…]}` or
    `Fail`. Lane streams are accepted on the new carrier only **after**
    `Resumed` is sent (extension of I4); a lane stream arriving earlier closes
    the connection.
  - Both sides reopen lanes with `LaneHeader{…, offset_out}` resending from
    the peer's received offset. Unacked bytes are guaranteed to be in the send
    ring (a sender never discards unacked data). A received offset outside
    `[acked, sent]` is a protocol error.
- **Reliable session events.** Byte offsets alone do not survive a carrier
  death: channel open/ok/fail/close, lane FIN (half-close) and reset,
  exit-status/exit-signal, `-R` accept notifications and window-change
  would be lost if sent on the dead control stream. Therefore every
  session-level control message after auth is carried in the **session
  event log**: a reliable, offset-tracked sequence with the same send-ring /
  ack / resend rules as a lane (it is lane 0 of a reserved `chan_id` 0).
  `Resume` carries its received offset; unacked events are replayed in
  order. Lane FIN is an event `LaneFin{chan_id, lane, final_offset}`, so a
  half-close is never confused with a carrier death. Connection-scoped
  messages (Auth, Resume/Resumed, LaneAck) stay on the plain control stream.
- **Attach is serialized per session.** Each attach increments the session's
  `attach_epoch` under a per-session lock; `Resumed` carries the epoch;
  messages and lane streams from a carrier with an older epoch are rejected.
  The newer attach closes the older carrier. Two simultaneous resumes cannot
  both succeed.
- **Detached `-R` listeners.** While detached, each `-R` listener accepts at
  most `DetachedAcceptMax` (default 8) pending connections, each with a
  bounded lane; further connections are refused (closed immediately) and
  counted.
- **Memory bound.** Per lane direction: send ring + receive ring
  (2 × `LaneBuffer`) in userspace, plus kernel buffers of the local endpoint,
  which the server caps explicitly (`SO_RCVBUF`/`SO_SNDBUF` on accepted and
  dialed sockets, default 64 KiB; pty buffers are kernel-fixed). Bound of a
  session = Σ over lanes of (2 × LaneBuffer + capped kernel buffers) + fixed
  overhead. The number of sessions (attached + detached) per user and
  server-wide is capped.
- Datagram channels are not replayed (lossy by contract).

### 5.1 Short outages: QUIC migration
- Client binds a fresh socket and `Endpoint::rebind`s on: a liveness probe
  failure (no ack for a PING within `max(3·RTT, 1 s)`) — the **primary**
  trigger, because netlink only sees the process's network namespace and is
  blind inside containers (the deployed client runs in the `autossh-ssh3`
  container, where a host Wi-Fi change changes no container interface); and
  OS network change via netlink as an accelerator where it is visible. E2 measured: rebind recovers in 3–6 ms;
  without rebind 1–3 s (PTO backoff).
- Server follows passively (E2: NAT rebinding detected, 2.4 ms).
- **All client sockets are dual-stack `[::]:0` with `IPV6_V6ONLY=0`**, both
  at connect and at every rebind. X1 root cause: quinn-proto compares the
  peer `SocketAddr` literally (`connection/mod.rs:1131`); after a v4 →
  dual-stack rebind replies arrive from `[::ffff:a.b.c.d]` and are discarded
  as "unrecognized peer", while `rebind_abstract` does not re-map existing
  connections' addresses; dual → v4 fails with EAFNOSUPPORT. Dual→dual
  works for v4 and v6 targets.
- A change of the **server's** address family cannot happen inside one QUIC
  connection; it is done by **resume** (§5) over a new connection.

## 6. UDP forwarding and datagrams

- QUIC DATAGRAM payload: `varint chan_id || frag_hdr || bytes`.
  `frag_hdr`: 0 = whole; 1 = fragment `{id u16, idx u8, count u8}`.
  The sender queries `max_datagram_size()` per send (E1: 1162 initially,
  1414 after PMTUD); payloads larger than it are fragmented. Max UDP payload
  65 507, never silently truncated (Go: 1500-byte truncation).
- Reassembly state is per channel, bounded (max in-flight fragment groups,
  max age 1 s), oldest evicted.
- `forwarded-udp` (reverse UDP): per-source flow table, bounded count + idle
  expiry + LRU; one channel per flow (Go bug class 4: per-source state
  growth to 1.4 GB).
- The same caps (count + idle expiry + LRU) apply to every UDP association:
  `direct-udp` forwards and SOCKS5 UDP ASSOCIATE, not only reverse flows.
- Reassembly memory is bounded **in aggregate**: a server-wide reassembly
  byte budget (default 4 MiB) across all flows and sessions; a fragment that
  would exceed it evicts the oldest group, counted.
- A slow datagram consumer never blocks the connection reader: datagrams to
  a full channel queue are dropped and counted.
- Verification of every cap is by internal counters before and after
  eviction/cancellation (live entries, bytes held), not by RSS — RSS and
  thread counts proved inadequate evidence in the Go OOM investigation.

## 7. Jump and NAT traversal (O3)

### 7.1 Rendezvous
- A server may also run as a **registered peer** at a gateway: its client
  connection to the gateway sends `Register{name}` (permission from the
  gateway's authorized_keys options). The gateway records the peer's
  observed address (server-reflexive) and host candidates the peer reports.
- At most 8 candidates per peer (`MaxCandidates`); extra ones are rejected
  with `Fail`. Punch fan-out is therefore ≤ 8 × 8 pairs.

### 7.2 Relay path
- `ssh3 -J gw target` opens a `jump` channel to the gateway. If `target` is a
  registered peer, the gateway relays **QUIC packets as datagrams** between
  the two carrier connections. Otherwise the gateway forwards UDP to
  `target:port` like `direct-udp`.
- **Fragmentation is end-to-end; the relay keeps no reassembly state.**
  Inner QUIC needs 1200-byte packets while the outer datagram limit can be
  1162 (E1). The *endpoints* split each inner packet into fragments of at
  most 1100 bytes (fits every outer path, since QUIC guarantees ≥ 1200-byte
  UDP payloads) using §6 `frag_hdr`; the gateway forwards each datagram
  opaquely from one carrier to the other. Reassembly is at the receiving
  endpoint, bounded per §6.
- **The inner connection is an ordinary end-to-end QUIC connection**: its
  server certificate is verified against the **target's** `known_hosts`
  entry (§2.1) and the user authenticates to the target (§2.2). The gateway
  sees only inner ciphertext and cannot impersonate the target, even if it is
  itself a registered peer.
- **Path socket.** The inner connection runs over an `AsyncUdpSocket`
  implementation that
  - presents to quinn one constant **virtual peer address** per inner
    connection (an address from `fd00::/8` chosen at dial, never routed);
    every inbound inner packet — via relay or via direct path — is
    delivered to quinn with that source address, which is required because
    quinn drops packets whose source differs from the path's remote
    (`connection/mod.rs:1131`);
  - maps egress for the virtual address to the *current* real path (relay
    datagram on the carrier, or UDP to the selected direct pair) through a
    single atomic pointer swapped on upgrade/fallback; packets in flight on
    the old path are simply delivered late or lost, which QUIC loss recovery
    covers;
  - authenticates direct-path inbound packets by the selected pair (source
    address) — anything else on the socket is demultiplexed to the carrier
    endpoint or to the punch handler (fixed bit, E3c).

- **One route owner.** A single per-endpoint `PathManager` owns, and is the
  only writer of: socket rebind (§5.1), the selected direct pair, carrier
  replacement (resume of the gateway connection) and relay fallback. Every
  change bumps a `path_epoch`; probe/punch completions carrying an older
  epoch are discarded. *(Go ssh3: the direct-path wrapper and
  AddPath/Switch were independent; Switch installed a new transport while
  the wrapper still referenced the old socket.)* Required tests: rebind
  during an upgrade; carrier replacement during fallback.

### 7.3 Direct path upgrade
1. Over the authenticated inner connection the peers exchange candidates
   (server-reflexive addresses from the gateway, host addresses of the
   **sending socket's own namespace**). Addresses of container bridges and
   other non-routable ranges are not offered as host candidates.
2. Both send punch packets (fixed bit 0, random nonce, HMAC keyed from the
   inner connection's exporter) to every candidate pair from the socket that
   carries their gateway connection, so the NAT mapping already observed by
   the gateway is reused. The socket demultiplexes by fixed bit (E3c).
3. **Nomination.** The controlling peer (lower (key, address) tuple, as
   for simultaneous dial) nominates one validated pair with
   `Nominate{generation, pair}` over the inner connection; the other peer
   answers `NominateAck{generation}` only if it has itself validated that
   pair; both switch on ack. A newer generation supersedes older ones.
   Punch and response packets carry `HMAC(exporter-derived key,
   session id || both peer key fingerprints || pair || role || generation ||
   nonce)`, so replayed or cross-session responses are rejected.
   The path socket then switches inner packets to the pair.
   Because the virtual address hides the change from quinn, quinn will not
   reset PMTU or congestion state by itself (open item X8).
4. Relay stays as fallback; on direct-path loss the path socket falls back to
   relay without breaking the inner connection.
- Simultaneous inner dial (both peers initiating) resolves deterministically:
  keep the connection whose client has the lower (key, address) tuple
  (E3b: both sides converge without an extra round trip).

## 8. Robustness invariants (Go bug classes, by construction)

- I1 No allocation sized by a peer-supplied length before checking it
  against a static cap.
- I2 Each connection and each channel is its own task; a panic is caught at
  the task boundary, logged with the peer identity, and closes only that
  connection/channel.
- I3 The accept loop never awaits anything per-connection; dials and DNS run
  in channel tasks with timeouts reported as `Fail{reason}`.
- I4 Session registration completes before the server acknowledges auth, so
  no channel-open or datagram can arrive for an unregistered session.
- I5 Clean shutdown: SIGTERM/SIGINT send CONNECTION_CLOSE with a reason
  (client) and release `-R` listeners immediately (server).
- I6 Introspection: `ssh3-server --stats` (or a control socket) reports
  per-user/session counts of connections, channels, lane bytes buffered,
  flow tables. Memory problems are diagnosed by reading counters, not logs.

## 9. Client CLI and configuration (O4)

- Binary `ssh3` accepts the OpenSSH grammar for `-L -R -D -J -N -T -t -l -p
  -i -o -F -A -v -W`, repeatable forwards, and reads `~/.ssh/config`
  (`Host`, `Match host/originalhost/user/exec`, `Include`, `IdentityFile`,
  `ProxyJump`, `LocalForward`, `RemoteForward`, `DynamicForward`, `User`,
  `Port`, `ServerAliveInterval`, `StrictHostKeyChecking`).
- `-D` implements SOCKS5 CONNECT and UDP ASSOCIATE (over `direct-udp`).
- Server binary `ssh3-server`; static musl build for deployment.

## 10. Open items (must be resolved by experiment, not assumption)

- X1 resolved (§5.1). X2 resolved (§1, BBR + budgeted windows). X5 resolved
  (§1 stateless reset; default config ignores stray short-header packets).
- X3 Residual ~300 MB RSS after drain with jemalloc/mimalloc: source unknown.
- X4 Hole punching on real NATs (oracle gateway, gambetta, corentin). The
  only historical success was corentin→gambetta over global IPv6 in the
  same /64 with a relay on gambetta — not evidence for NAT traversal. NAT
  mapping/filtering types and oracle IPv6 are unmeasured.
- X8 Path switch under a virtual peer address: how to make quinn re-probe
  PMTU and reset congestion state (large-PMTU relay → smaller direct path,
  and direct → relay fallback); test asymmetric loss/delay and replayed
  responses.
- X6 resolved (§1 accounting rule). `set_send_window` not yet measured.
- X7 X2 relay had no bottleneck queue and i.i.d. loss; re-measure on real
  paths (oracle ↔ gambetta).
