//! `PathManager` (SPEC §7.2 "One route owner", §7.3): the single owner, per endpoint, of
//! socket rebind, relay carrier replacement, selected direct pair and fallback; one [`PeerPath`]
//! state machine per inner connection drives candidate exchange, authenticated punching,
//! nomination, direct-path keepalive and fallback. Every change bumps an epoch; punch
//! completions from older generations are discarded.
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use quinn::{AsyncUdpSocket, Endpoint};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep_until};

use crate::socket::{PathSocket, Real, RelayLink, RouteId, SIDE_QUEUE, Shared, SocketStats};
use crate::wire::{
    self, DecodeError, KIND_CHECK, KIND_KEEPALIVE, MAX_CANDIDATES, NONCE_LEN, Punch, PunchKey,
    ROLE_CONTROLLED, ROLE_CONTROLLING, Resp, SideMsg, Signal,
};

/// Timers of the direct-path machinery. Every value is configurable (SPEC §9) so tests run in
/// milliseconds.
#[derive(Clone, Debug)]
pub struct PathConfig {
    /// Interval between punch bursts to every candidate pair during a round.
    pub punch_interval: Duration,
    /// A round without an acknowledged nomination ends after this long.
    pub round_timeout: Duration,
    /// After a failed round or a fallback, the controlling peer starts the next round after
    /// this long.
    pub retry_interval: Duration,
    /// Keepalive punches on the selected direct pair.
    pub keepalive_interval: Duration,
    /// No keepalive response for this long → fall back to the relay.
    pub direct_timeout: Duration,
    /// Reset quinn's path state (`Connection::path_changed`, vendored patch X9) on every switch.
    /// Only for the X9 comparison measurement; keep `true`.
    pub reset_on_switch: bool,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            punch_interval: Duration::from_millis(50),
            round_timeout: Duration::from_secs(3),
            retry_interval: Duration::from_secs(10),
            keepalive_interval: Duration::from_millis(500),
            direct_timeout: Duration::from_secs(2),
            reset_on_switch: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathMode {
    Relay,
    Direct(SocketAddr),
}

/// Why the last finished round did not end on a direct path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RoundOutcome {
    #[default]
    None,
    Direct,
    /// No pair answered: typical for endpoint-dependent (symmetric) mapping on both sides, or
    /// filtering that never opened.
    NoValidatedPair { remote_candidates: usize, punches_sent: u64, punches_heard: u64, responses: u64 },
    /// Pairs validated on this side but the peer never acknowledged a nomination.
    NotAcknowledged,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerStatus {
    pub mode: PathMode,
    pub generation: u32,
    pub epoch: u64,
    pub last_outcome: RoundOutcome,
    pub switches_direct: u64,
    pub fallbacks: u64,
}

/// Per-peer counters (SPEC I6).
#[derive(Default, Debug)]
pub struct PeerCounters {
    pub punches_sent: AtomicU64,
    pub punches_heard: AtomicU64,
    pub responses: AtomicU64,
    pub stale_generation: AtomicU64,
    pub replayed: AtomicU64,
    pub bad_mac: AtomicU64,
    pub malformed: AtomicU64,
    pub unsolicited: AtomicU64,
    pub asymmetric: AtomicU64,
    pub nominations_sent: AtomicU64,
    pub nominations_acked: AtomicU64,
    pub nominations_refused: AtomicU64,
    pub keepalive_failures: AtomicU64,
    pub signals_bad: AtomicU64,
    pub stale_signals: AtomicU64,
}

/// The per-endpoint path layer: owns the shared socket state and the endpoint's rebinds.
pub struct PathManager {
    shared: Arc<Shared>,
    endpoint: Mutex<Option<Endpoint>>,
    epoch: AtomicU64,
    peers: Mutex<Vec<mpsc::UnboundedSender<Cmd>>>,
}

impl PathManager {
    pub fn new(io: Arc<dyn AsyncUdpSocket>) -> Arc<Self> {
        Arc::new(Self {
            shared: Shared::new(io),
            endpoint: Mutex::new(None),
            epoch: AtomicU64::new(0),
            peers: Mutex::new(Vec::new()),
        })
    }

    /// The socket to build the quinn endpoint on (`Endpoint::new_with_abstract_socket`). The
    /// endpoint config must have `grease_quic_bit(false)` (side channel demux, E3c).
    pub fn socket(&self) -> Arc<PathSocket> {
        PathSocket::new(self.shared.io(), self.shared.clone())
    }

    /// Hand the endpoint built on [`Self::socket`] to the manager so that [`Self::rebind`] can
    /// move it. Without it, rebind only changes the side channel.
    pub fn attach_endpoint(&self, ep: Endpoint) {
        *self.endpoint.lock().unwrap() = Some(ep);
    }

    pub fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    pub fn socket_stats(&self) -> SocketStats {
        self.shared.stats()
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Register an inner connection's route, initially over the relay.
    pub fn add_relay_route(&self, link: Arc<dyn RelayLink>) -> (RouteId, SocketAddr) {
        self.shared.add_route(Real::Relay(link))
    }

    pub fn relay_input(&self, route: RouteId, packet: Bytes) {
        self.shared.relay_input(route, packet)
    }

    /// The one place a socket rebind happens (§5.1 liveness / network change): the endpoint
    /// moves to `io`, the side channel follows, the epoch is bumped and every peer path falls
    /// back to the relay and starts over (its direct mapping belonged to the old socket).
    pub fn rebind(&self, io: Arc<dyn AsyncUdpSocket>) -> io::Result<()> {
        self.shared.set_io(io.clone());
        if let Some(ep) = self.endpoint.lock().unwrap().as_ref() {
            ep.rebind_abstract(PathSocket::new(io, self.shared.clone()))?;
        }
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.broadcast(Cmd::Rebound);
        Ok(())
    }

    fn broadcast(&self, cmd: Cmd) {
        self.peers.lock().unwrap().retain(|tx| tx.send(cmd.clone()).is_ok());
    }

    /// Start the direct-path machinery for one inner connection.
    pub fn start_peer(self: &Arc<Self>, setup: PeerSetup) -> PeerPath {
        let PeerSetup { route, relay, conn, secret, controlling, signals, reflexive, cfg } = setup;
        let key = PunchKey::new(&secret);
        let (side_tx, side_rx) = mpsc::channel(SIDE_QUEUE);
        self.shared.register_punch(key.tag(), side_tx);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        self.peers.lock().unwrap().push(cmd_tx.clone());
        let counters = Arc::new(PeerCounters::default());
        let status0 = PeerStatus {
            mode: PathMode::Relay,
            generation: 0,
            epoch: self.epoch(),
            last_outcome: RoundOutcome::None,
            switches_direct: 0,
            fallbacks: 0,
        };
        let (status_tx, status_rx) = watch::channel(status0.clone());
        let peer = Peer {
            mgr: self.clone(),
            route,
            relay,
            conn,
            key,
            controlling,
            signals,
            reflexive,
            cfg,
            counters: counters.clone(),
            status_tx,
            status: status0,
            generation: 0,
            round: None,
            direct: None,
            pending_nominate: None,
            next_round_at: Some(Instant::now()),
            heard_nonces: VecDeque::new(),
        };
        let task = tokio::spawn(peer.run(cmd_rx, side_rx));
        PeerPath { cmd: cmd_tx, status: status_rx, counters, task: Some(task) }
    }
}

/// Everything [`PathManager::start_peer`] needs for one inner connection.
pub struct PeerSetup {
    /// The route returned by [`PathManager::add_relay_route`].
    pub route: RouteId,
    /// Current relay carrier (fallback path).
    pub relay: Arc<dyn RelayLink>,
    /// The inner QUIC connection (for `path_changed` and lifetime).
    pub conn: quinn::Connection,
    /// 32 bytes from the inner connection's exporter ([`wire::EXPORTER_LABEL`]), identical on
    /// both peers.
    pub secret: [u8; 32],
    /// The peer with the lower (key, address) tuple controls (SPEC §7.3).
    pub controlling: bool,
    /// Where encoded [`Signal`]s for the peer go (over the inner connection); feed the peer's
    /// signals back with [`PeerPath::signal_in`].
    pub signals: mpsc::UnboundedSender<Vec<u8>>,
    /// Server-reflexive address the gateway observed, if known.
    pub reflexive: Option<SocketAddr>,
    pub cfg: PathConfig,
}

#[derive(Clone)]
enum Cmd {
    Signal(Vec<u8>),
    SetRelay(Arc<dyn RelayLink>),
    SetReflexive(SocketAddr),
    Rebound,
    Close,
}

/// Handle of one inner connection's path machinery.
pub struct PeerPath {
    cmd: mpsc::UnboundedSender<Cmd>,
    status: watch::Receiver<PeerStatus>,
    pub counters: Arc<PeerCounters>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl PeerPath {
    /// Feed an encoded signal received from the peer over the inner connection.
    pub fn signal_in(&self, bytes: Vec<u8>) {
        let _ = self.cmd.send(Cmd::Signal(bytes));
    }
    /// The relay carrier was replaced (resume of the gateway connection).
    pub fn set_relay(&self, link: Arc<dyn RelayLink>) {
        let _ = self.cmd.send(Cmd::SetRelay(link));
    }
    pub fn set_reflexive(&self, addr: SocketAddr) {
        let _ = self.cmd.send(Cmd::SetReflexive(addr));
    }
    pub fn status(&self) -> PeerStatus {
        self.status.borrow().clone()
    }
    pub fn watch(&self) -> watch::Receiver<PeerStatus> {
        self.status.clone()
    }
}

impl Drop for PeerPath {
    fn drop(&mut self) {
        let _ = self.cmd.send(Cmd::Close);
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

struct Round {
    generation: u32,
    deadline: Instant,
    local: Vec<SocketAddr>,
    remote: Vec<SocketAddr>,
    /// nonce → address the punch was sent to.
    sent: HashMap<[u8; NONCE_LEN], SocketAddr>,
    /// (remote address that answered, our address as the remote saw it).
    validated: Vec<(SocketAddr, SocketAddr)>,
    next_punch: Instant,
    punches_sent: u64,
    punches_heard: u64,
    responses: u64,
}

struct Direct {
    remote: SocketAddr,
    last_ok: Instant,
    next_keepalive: Instant,
    sent: HashMap<[u8; NONCE_LEN], Instant>,
}

struct Peer {
    mgr: Arc<PathManager>,
    route: RouteId,
    relay: Arc<dyn RelayLink>,
    conn: quinn::Connection,
    key: PunchKey,
    controlling: bool,
    signals: mpsc::UnboundedSender<Vec<u8>>,
    reflexive: Option<SocketAddr>,
    cfg: PathConfig,
    counters: Arc<PeerCounters>,
    status_tx: watch::Sender<PeerStatus>,
    status: PeerStatus,
    generation: u32,
    round: Option<Round>,
    direct: Option<Direct>,
    /// (generation, you_are_at, i_am_at) of the outstanding nomination.
    pending_nominate: Option<(u32, SocketAddr, SocketAddr)>,
    next_round_at: Option<Instant>,
    heard_nonces: VecDeque<[u8; NONCE_LEN]>,
}

/// Remembered inbound punch nonces of the current generation (replay rejection).
const HEARD_NONCES: usize = 512;
/// Upper bound of remote candidates incl. peer-reflexive ones learned during a round.
const MAX_REMOTE: usize = 2 * MAX_CANDIDATES;
/// Outstanding punch nonces remembered per round / direct path.
const MAX_SENT: usize = 1024;

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

impl Peer {
    async fn run(
        mut self,
        mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
        mut side_rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    ) {
        let conn = self.conn.clone();
        loop {
            let wake = self.next_wake();
            tokio::select! {
                c = cmd_rx.recv() => match c {
                    None | Some(Cmd::Close) => break,
                    Some(c) => self.on_cmd(c),
                },
                s = side_rx.recv() => match s {
                    None => break,
                    Some((from, d)) => self.on_side(from, &d),
                },
                _ = conn.closed() => break,
                _ = sleep_until(wake) => {}
            }
            self.on_timers(Instant::now());
        }
        self.mgr.shared.unregister_punch(&self.key.tag());
    }

    fn next_wake(&self) -> Instant {
        let far = Instant::now() + Duration::from_secs(3600);
        let mut t = far;
        if let Some(r) = &self.round {
            t = t.min(r.next_punch).min(r.deadline);
        }
        if let Some(d) = &self.direct {
            t = t.min(d.next_keepalive).min(d.last_ok + self.cfg.direct_timeout);
        }
        if let Some(n) = self.next_round_at {
            t = t.min(n);
        }
        t
    }

    fn publish(&mut self) {
        self.status.generation = self.generation;
        self.status.epoch = self.mgr.epoch();
        self.status.mode = match &self.direct {
            Some(d) => PathMode::Direct(d.remote),
            None => PathMode::Relay,
        };
        let _ = self.status_tx.send(self.status.clone());
    }

    fn role(&self) -> u8 {
        if self.controlling { ROLE_CONTROLLING } else { ROLE_CONTROLLED }
    }

    fn send_signal(&self, s: &Signal) {
        let _ = self.signals.send(wire::encode_signal(s));
    }

    /// Host candidates from the sending socket's own namespace, the reflexive address first.
    fn local_candidates(&self) -> Vec<SocketAddr> {
        let mut v = Vec::new();
        if let Some(r) = self.reflexive {
            v.push(r);
        }
        if let Ok(local) = self.mgr.shared.io().local_addr() {
            for c in crate::candidates::host_candidates(local) {
                if !v.contains(&c) {
                    v.push(c);
                }
            }
        }
        v.truncate(MAX_CANDIDATES);
        v
    }

    fn new_round(&mut self, generation: u32, remote: Vec<SocketAddr>, now: Instant) {
        self.mgr.shared.clear_accept(self.route, self.direct.as_ref().map(|d| d.remote));
        self.generation = generation;
        self.heard_nonces.clear();
        self.pending_nominate = None;
        let local = self.local_candidates();
        self.round = Some(Round {
            generation,
            deadline: now + self.cfg.round_timeout,
            local,
            remote,
            sent: HashMap::new(),
            validated: Vec::new(),
            next_punch: now,
            punches_sent: 0,
            punches_heard: 0,
            responses: 0,
        });
        self.next_round_at = None;
    }

    fn on_cmd(&mut self, c: Cmd) {
        let now = Instant::now();
        match c {
            Cmd::Signal(b) => match wire::decode_signal(&b) {
                Ok(s) => self.on_signal(s, now),
                Err(_) => bump(&self.counters.signals_bad),
            },
            Cmd::SetRelay(link) => {
                self.relay = link.clone();
                if self.direct.is_none() {
                    self.mgr.shared.set_real(self.route, Real::Relay(link));
                    self.reset_quic_path();
                }
                self.publish();
            }
            Cmd::SetReflexive(a) => {
                self.reflexive = Some(a);
            }
            Cmd::Rebound => {
                // Our NAT mapping changed: the direct pair is gone and so is every round state.
                self.fall_back();
                self.mgr.shared.clear_accept(self.route, None);
                self.round = None;
                if self.controlling {
                    self.next_round_at = Some(now);
                } else {
                    self.send_signal(&Signal::Restart);
                }
                self.publish();
            }
            Cmd::Close => {}
        }
    }

    fn on_signal(&mut self, s: Signal, now: Instant) {
        match s {
            Signal::Candidates { generation, candidates } => {
                let mut remote = candidates;
                remote.truncate(MAX_CANDIDATES);
                if self.controlling {
                    match &mut self.round {
                        Some(r) if r.generation == generation => {
                            for c in remote {
                                if !r.remote.contains(&c) && r.remote.len() < MAX_REMOTE {
                                    r.remote.push(c);
                                }
                            }
                            r.next_punch = now;
                        }
                        _ => bump(&self.counters.stale_signals),
                    }
                } else {
                    if generation <= self.generation {
                        bump(&self.counters.stale_signals);
                        return;
                    }
                    // A new round means the controlling peer considers the current path not
                    // direct; follow it onto the relay so both sides agree.
                    self.fall_back();
                    self.new_round(generation, remote, now);
                    let local = self.round.as_ref().unwrap().local.clone();
                    self.send_signal(&Signal::Candidates { generation, candidates: local });
                    self.publish();
                }
            }
            Signal::Nominate { generation, you_are_at, i_am_at } => {
                if self.controlling || generation != self.generation {
                    bump(&self.counters.stale_signals);
                    self.send_signal(&Signal::NominateNak { generation });
                    return;
                }
                let ok = self
                    .round
                    .as_ref()
                    .is_some_and(|r| r.validated.iter().any(|(remote, _)| *remote == i_am_at));
                // `you_are_at` is our address as the controlling peer sees it; nothing to check:
                // its own validation of that pair is what made it nominate.
                let _ = you_are_at;
                if ok {
                    self.send_signal(&Signal::NominateAck { generation });
                    self.switch_direct(i_am_at, now);
                } else {
                    bump(&self.counters.nominations_refused);
                    self.send_signal(&Signal::NominateNak { generation });
                }
            }
            Signal::NominateAck { generation } => {
                match self.pending_nominate.take() {
                    Some((g, you_are_at, _)) if g == generation && generation == self.generation => {
                        bump(&self.counters.nominations_acked);
                        self.switch_direct(you_are_at, now);
                    }
                    other => {
                        self.pending_nominate = other;
                        bump(&self.counters.stale_signals);
                    }
                }
            }
            Signal::NominateNak { generation } => {
                if matches!(self.pending_nominate, Some((g, _, _)) if g == generation) {
                    bump(&self.counters.nominations_refused);
                    self.pending_nominate = None;
                }
            }
            Signal::Restart => {
                if self.controlling {
                    self.fall_back();
                    self.round = None;
                    self.next_round_at = Some(now);
                    self.publish();
                }
            }
        }
    }

    fn on_side(&mut self, from: SocketAddr, d: &[u8]) {
        let now = Instant::now();
        let msg = match wire::decode_side(&self.key, d) {
            Ok(m) => m,
            Err(DecodeError::BadMac) => return bump(&self.counters.bad_mac),
            Err(DecodeError::Malformed) => return bump(&self.counters.malformed),
        };
        match msg {
            SideMsg::Punch(p) => self.on_punch(from, p, now),
            SideMsg::Resp(r) => self.on_resp(from, r, now),
        }
    }

    fn on_punch(&mut self, from: SocketAddr, p: Punch, now: Instant) {
        if p.generation != self.generation || self.generation == 0 {
            return bump(&self.counters.stale_generation);
        }
        if p.role == self.role() {
            // Both claim the same role: reflected or cross-wired packet.
            return bump(&self.counters.malformed);
        }
        if self.heard_nonces.contains(&p.nonce) {
            return bump(&self.counters.replayed);
        }
        self.heard_nonces.push_back(p.nonce);
        if self.heard_nonces.len() > HEARD_NONCES {
            self.heard_nonces.pop_front();
        }
        bump(&self.counters.punches_heard);
        let resp = Resp { tag: self.key.tag(), generation: p.generation, nonce: p.nonce, role: self.role(), observed: from };
        self.mgr.shared.send_side(from, &wire::encode_resp(&self.key, &resp));
        if p.kind == KIND_CHECK
            && let Some(r) = &mut self.round {
                r.punches_heard += 1;
                // Peer-reflexive candidate: the peer's NAT chose a mapping we were not told
                // about (endpoint-dependent mapping on its side). Check it too.
                if !r.remote.contains(&from) && r.remote.len() < MAX_REMOTE {
                    r.remote.push(from);
                    r.next_punch = now;
                }
            }
    }

    fn on_resp(&mut self, from: SocketAddr, r: Resp, now: Instant) {
        if r.generation != self.generation || self.generation == 0 {
            return bump(&self.counters.stale_generation);
        }
        if r.role == self.role() {
            return bump(&self.counters.malformed);
        }
        // Keepalive on the direct path?
        if let Some(d) = &mut self.direct
            && d.sent.remove(&r.nonce).is_some() {
                if from == d.remote {
                    d.last_ok = now;
                    bump(&self.counters.responses);
                } else {
                    bump(&self.counters.asymmetric);
                }
                return;
            }
        let Some(round) = &mut self.round else {
            return bump(&self.counters.unsolicited);
        };
        let Some(sent_to) = round.sent.remove(&r.nonce) else {
            // Not a nonce we sent (or already answered): replay or forgery with the right key.
            return bump(&self.counters.unsolicited);
        };
        if sent_to != from {
            // The answer did not come from where we sent: no proof that `from` reaches us
            // symmetrically. It is learnt as a candidate and checked on its own.
            bump(&self.counters.asymmetric);
            if !round.remote.contains(&from) && round.remote.len() < MAX_REMOTE {
                round.remote.push(from);
                round.next_punch = now;
            }
            return;
        }
        round.responses += 1;
        bump(&self.counters.responses);
        if !round.validated.iter().any(|(a, _)| *a == from) {
            round.validated.push((from, r.observed));
            self.mgr.shared.accept_inbound(self.route, from);
        }
        if self.controlling && self.pending_nominate.is_none() && self.direct.is_none() {
            let g = self.generation;
            self.pending_nominate = Some((g, from, r.observed));
            bump(&self.counters.nominations_sent);
            self.send_signal(&Signal::Nominate { generation: g, you_are_at: from, i_am_at: r.observed });
        }
    }

    fn on_timers(&mut self, now: Instant) {
        let role = self.role();
        let tag = self.key.tag();
        // Direct path liveness.
        if let Some(d) = &mut self.direct {
            if now >= d.last_ok + self.cfg.direct_timeout {
                bump(&self.counters.keepalive_failures);
                self.fall_back();
                if self.controlling {
                    self.next_round_at = Some(now + self.cfg.retry_interval);
                } else {
                    self.send_signal(&Signal::Restart);
                }
                self.publish();
            } else if now >= d.next_keepalive {
                d.next_keepalive = now + self.cfg.keepalive_interval;
                let nonce: [u8; NONCE_LEN] = self.mgr.shared.random();
                if d.sent.len() >= MAX_SENT {
                    d.sent.clear();
                }
                d.sent.insert(nonce, now);
                let p = Punch { tag, generation: self.generation, nonce, role, kind: KIND_KEEPALIVE };
                let remote = d.remote;
                self.mgr.shared.send_side(remote, &wire::encode_punch(&self.key, &p));
                bump(&self.counters.punches_sent);
            }
        }

        // Round progress.
        if let Some(r) = &mut self.round {
            if now >= r.deadline {
                let outcome = if r.validated.is_empty() {
                    RoundOutcome::NoValidatedPair {
                        remote_candidates: r.remote.len(),
                        punches_sent: r.punches_sent,
                        punches_heard: r.punches_heard,
                        responses: r.responses,
                    }
                } else {
                    RoundOutcome::NotAcknowledged
                };
                self.status.last_outcome = outcome;
                self.round = None;
                self.pending_nominate = None;
                if self.controlling {
                    self.next_round_at = Some(now + self.cfg.retry_interval);
                }
                self.publish();
            } else if now >= r.next_punch {
                r.next_punch = now + self.cfg.punch_interval;
                if r.sent.len() + r.remote.len() > MAX_SENT {
                    r.sent.clear();
                }
                let targets = r.remote.clone();
                for to in targets {
                    let nonce: [u8; NONCE_LEN] = self.mgr.shared.random();
                    r.sent.insert(nonce, to);
                    r.punches_sent += 1;
                    let p = Punch { tag, generation: r.generation, nonce, role, kind: KIND_CHECK };
                    self.mgr.shared.send_side(to, &wire::encode_punch(&self.key, &p));
                    bump(&self.counters.punches_sent);
                }
                // The controlling side re-nominates a validated pair after a refusal.
                if self.controlling && self.pending_nominate.is_none() && self.direct.is_none()
                    && let Some(&(you, me)) = r.validated.first() {
                        let g = r.generation;
                        self.pending_nominate = Some((g, you, me));
                        bump(&self.counters.nominations_sent);
                        let _ = self.signals.send(wire::encode_signal(&Signal::Nominate { generation: g, you_are_at: you, i_am_at: me }));
                    }
            }
        }

        // Next round (controlling only).
        if self.controlling && self.direct.is_none() && self.round.is_none()
            && let Some(at) = self.next_round_at
                && now >= at {
                    let g = self.generation.wrapping_add(1).max(1);
                    self.new_round(g, Vec::new(), now);
                    let local = self.round.as_ref().unwrap().local.clone();
                    self.send_signal(&Signal::Candidates { generation: g, candidates: local });
                    self.publish();
                }
    }

    fn switch_direct(&mut self, remote: SocketAddr, now: Instant) {
        self.mgr.shared.set_real(self.route, Real::Direct(remote));
        self.mgr.shared.clear_accept(self.route, Some(remote));
        self.mgr.epoch.fetch_add(1, Ordering::SeqCst);
        self.reset_quic_path();
        self.direct = Some(Direct {
            remote,
            last_ok: now,
            next_keepalive: now + self.cfg.keepalive_interval,
            sent: HashMap::new(),
        });
        self.round = None;
        self.pending_nominate = None;
        self.status.switches_direct += 1;
        self.status.last_outcome = RoundOutcome::Direct;
        self.publish();
    }

    /// Leave the direct path (if any) for the relay.
    fn fall_back(&mut self) {
        if self.direct.take().is_some() {
            self.mgr.shared.set_real(self.route, Real::Relay(self.relay.clone()));
            self.mgr.epoch.fetch_add(1, Ordering::SeqCst);
            self.reset_quic_path();
            self.status.fallbacks += 1;
        }
    }

    fn reset_quic_path(&self) {
        if !self.cfg.reset_on_switch {
            return;
        }
        self.conn.path_changed();
    }
}

/// Addresses that are never offered as host candidates.
pub(crate) fn non_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_link_local() || v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => {
            v6.is_unspecified() || v6.is_multicast() || (v6.segments()[0] & 0xffc0) == 0xfe80 || crate::socket::is_virtual(ip)
        }
    }
}
