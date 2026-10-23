//! Sessions, channels, the event log and the carrier connection
//! (SPEC §4, §5, §8).
//!
//! A session outlives any one QUIC connection ("carrier"). Channels, their
//! lanes and the session **event log** (lane 0 of channel 0) are session
//! state; the carrier owns only connection-scoped tasks: the control stream
//! (LaneAck), the lane-stream acceptor and the death watcher.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use quinn::{Connection, RecvStream, SendStream};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;

use crate::auth::Authz;
use crate::budget::Budget;
use crate::error::{Error, Result, close};
use crate::frame::{self, MAX_FRAME};
use crate::lane::{AckQueue, Lane, LaneEnv, Stats, read_header, write_header};
use crate::limits::Limits;
use crate::msg::{ChannelKind, EVENT_CHANNEL, FailReason, LaneHeader, LanePos, Message, SessionId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    fn peer(self) -> Role {
        match self {
            Role::Client => Role::Server,
            Role::Server => Role::Client,
        }
    }
}

/// The process-wide (server-wide) lane storage budgets (SPEC §4).
pub struct Budgets {
    pub recv: Arc<Budget>,
    pub send: Arc<Budget>,
    /// Floor chunks; unlimited, counted.
    pub floor: Arc<Budget>,
    /// Connection windows above the floor (§1).
    pub conn: Arc<Budget>,
}

impl Budgets {
    pub fn new(l: &Limits) -> Arc<Self> {
        Arc::new(Self {
            recv: Budget::new("LaneCreditBudget", l.lane_credit_budget),
            send: Budget::new("LaneSendBudget", l.lane_send_budget),
            floor: Budget::new("lane floor", u64::MAX),
            conn: Budget::new("ConnWindowBudget", l.conn_window_budget),
        })
    }
}

pub(crate) type Registry = Mutex<HashMap<SessionId, Arc<SessionShared>>>;

/// A server-side -R listener. Dropping it aborts the accept task, which
/// drops the socket: the port is released at once (SPEC I5).
struct Listener {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) struct Channel {
    pub chan_id: u64,
    pub lanes: Vec<Arc<Lane>>,
    /// Client side: ChannelOpen sent, ChannelOk not yet received. No lane
    /// streams exist yet, so they are not reopened on resume.
    opening: AtomicBool,
    tasks: Mutex<JoinSet<()>>,
    stats: Arc<Stats>,
}

impl Channel {
    fn spawn(&self, f: impl std::future::Future<Output = ()> + Send + 'static) {
        self.tasks.lock().unwrap().spawn(f);
    }
}

/// Ownership invariant (SPEC §4): dropping a channel — completion, error,
/// ChannelClose, session teardown — closes its lanes (returning ring chunks
/// and budget permits) and aborts its tasks; their QUIC send streams reset
/// (`LaneSend`) and receive streams stop on drop.
impl Drop for Channel {
    fn drop(&mut self) {
        for l in &self.lanes {
            l.close();
        }
        self.stats.channels.fetch_sub(1, Ordering::Relaxed);
    }
}

struct Carrier {
    epoch: u64,
    conn: Connection,
    /// Keeps the control writer alive (it exits when all senders drop).
    _ctrl: mpsc::Sender<Message>,
    _tasks: JoinSet<()>,
}

pub struct SessionShared {
    pub id: SessionId,
    pub role: Role,
    pub user: String,
    /// The exact key that created the session (SPEC §5: resume requires it).
    pub owner_key: Vec<u8>,
    /// Re-evaluated at every attach; each value is immutable.
    authz: Mutex<Arc<Authz>>,
    pub limits: Limits,
    pub stats: Arc<Stats>,
    pub budgets: Arc<Budgets>,
    acks: Arc<AckQueue>,
    channels: Mutex<HashMap<u64, Arc<Channel>>>,
    next_chan: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<std::result::Result<u64, FailReason>>>>,
    /// Server: -R listeners owned by the session (dropped = port released).
    listeners: Mutex<HashMap<(String, u16), Listener>>,
    /// Client: -R requests in flight, by req_id → (bind host, target), and
    /// established forwards (bind host, bound port) → target.
    listen_pending: Mutex<HashMap<u64, (String, (String, u16), oneshot::Sender<std::result::Result<u16, FailReason>>)>>,
    remote_forwards: Mutex<HashMap<(String, u16), (String, u16)>>,
    next_req: AtomicU64,
    pub refused_detached: AtomicU64,
    events: mpsc::Sender<Message>,
    carrier: Mutex<Option<Carrier>>,
    epoch: AtomicU64,
    /// Serializes attach (new carrier) per session (SPEC §5).
    pub(crate) attach_lock: tokio::sync::Mutex<()>,
    /// Current carrier epoch, 0 while detached.
    carrier_state: watch::Sender<u64>,
    /// Highest Pong received (client liveness probe).
    pub(crate) last_pong: watch::Sender<u64>,
    registry: Option<Weak<Registry>>,
}

impl SessionShared {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: SessionId,
        role: Role,
        user: String,
        owner_key: Vec<u8>,
        authz: Authz,
        limits: Limits,
        budgets: Arc<Budgets>,
        registry: Option<Weak<Registry>>,
    ) -> Arc<Self> {
        let (events_tx, events_rx) = mpsc::channel(limits.event_queue);
        let s = Arc::new(Self {
            id,
            role,
            user,
            owner_key,
            authz: Mutex::new(Arc::new(authz)),
            stats: Arc::new(Stats::default()),
            budgets,
            acks: Arc::new(AckQueue::default()),
            channels: Mutex::new(HashMap::new()),
            next_chan: AtomicU64::new(if role == Role::Client { 2 } else { 1 }),
            pending: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            listen_pending: Mutex::new(HashMap::new()),
            remote_forwards: Mutex::new(HashMap::new()),
            next_req: AtomicU64::new(1),
            refused_detached: AtomicU64::new(0),
            events: events_tx,
            carrier: Mutex::new(None),
            epoch: AtomicU64::new(0),
            attach_lock: tokio::sync::Mutex::new(()),
            carrier_state: watch::channel(0).0,
            last_pong: watch::channel(0).0,
            registry,
            limits,
        });
        s.start_event_log(events_rx);
        s
    }

    pub fn authz(&self) -> Arc<Authz> {
        self.authz.lock().unwrap().clone()
    }

    pub(crate) fn set_authz(&self, a: Authz) {
        *self.authz.lock().unwrap() = Arc::new(a);
    }

    fn lane_env(&self) -> LaneEnv {
        LaneEnv {
            cap: self.limits.lane_buffer as u64,
            floor: self.limits.lane_floor,
            ack_interval: self.limits.ack_interval,
            stats: self.stats.clone(),
            acks: self.acks.clone(),
            recv_budget: self.budgets.recv.clone(),
            send_budget: self.budgets.send.clone(),
            floor_budget: self.budgets.floor.clone(),
            events: self.events.clone(),
        }
    }

    /// Channel 0, lane 0 carries the session event log. Outgoing events go
    /// through a bounded queue into an in-memory pipe that is the lane's
    /// local source; the lane's sink is a pipe read by the event dispatcher.
    fn start_event_log(self: &Arc<Self>, mut rx: mpsc::Receiver<Message>) {
        let ch = self.make_channel(EVENT_CHANNEL, 1);
        let lane = ch.lanes[0].clone();
        let (mut prod, src) = tokio::io::duplex(4096);
        let (snk, mut cons) = tokio::io::duplex(4096);
        ch.spawn(async move {
            while let Some(m) = rx.recv().await {
                if prod.write_all(&frame::encode(&m)).await.is_err() {
                    return;
                }
            }
        });
        let l = lane.clone();
        ch.spawn(async move {
            let _ = l.source_task(src).await;
        });
        ch.spawn(async move {
            let _ = lane.sink_task(snk).await;
        });
        let me = Arc::downgrade(self);
        ch.spawn(async move {
            loop {
                let r = frame::read_message(&mut cons, MAX_FRAME).await;
                let Some(s) = me.upgrade() else { return };
                let res = match r {
                    Ok(Some(m)) => s.dispatch_event(m).await,
                    Ok(None) => return,
                    Err(e) => Err(e),
                };
                if let Err(e) = res {
                    tracing::warn!(session = %hex(&s.id), "event log violation, closing session: {e}");
                    if let Some((c, _)) = s.conn() {
                        c.close(close::PROTOCOL.into(), e.to_string().as_bytes());
                    }
                    s.teardown();
                    return;
                }
            }
        });
        self.channels.lock().unwrap().insert(EVENT_CHANNEL, ch);
    }

    pub fn channel_count(&self) -> usize {
        self.channels.lock().unwrap().keys().filter(|&&k| k != EVENT_CHANNEL).count()
    }

    pub fn is_attached(&self) -> bool {
        *self.carrier_state.borrow() != 0
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    pub(crate) fn carrier_state_rx(&self) -> watch::Receiver<u64> {
        self.carrier_state.subscribe()
    }

    /// Resolves when no carrier is attached.
    pub async fn carrier_lost(&self) {
        let mut rx = self.carrier_state.subscribe();
        let _ = rx.wait_for(|g| *g == 0).await;
    }

    fn channel(&self, id: u64) -> Option<Arc<Channel>> {
        self.channels.lock().unwrap().get(&id).cloned()
    }

    /// Send a connection-scoped message on the current carrier's control
    /// stream; false if detached or the queue is full.
    pub(crate) fn send_ctrl(&self, m: Message) -> bool {
        self.carrier.lock().unwrap().as_ref().is_some_and(|c| c._ctrl.try_send(m).is_ok())
    }

    /// Smoothed RTT of the current carrier.
    pub(crate) fn rtt(&self) -> Option<std::time::Duration> {
        self.carrier.lock().unwrap().as_ref().map(|c| c.conn.rtt())
    }

    fn conn(&self) -> Option<(Connection, u64)> {
        self.carrier.lock().unwrap().as_ref().map(|c| (c.conn.clone(), c.epoch))
    }

    /// Queue a session event (reliable, survives carrier death).
    pub(crate) async fn send_event(&self, m: Message) -> Result<()> {
        self.events.send(m).await.map_err(|_| Error::Protocol("session event log closed".into()))
    }

    /// Reply from inside the event dispatcher: never waits (two dispatchers
    /// waiting on each other's event credit would deadlock). A peer that
    /// lets our replies pile up beyond the queue is violating the protocol.
    fn reply_event(&self, m: Message) -> Result<()> {
        self.events.try_send(m).map_err(|_| Error::Protocol(format!("peer left {} session events unconsumed", self.limits.event_queue)))
    }

    // ------------------------------------------------------------ channels

    fn make_channel(self: &Arc<Self>, chan_id: u64, nlanes: u8) -> Arc<Channel> {
        let env = self.lane_env();
        let lanes = (0..nlanes).map(|i| Lane::new(chan_id, i, env.clone())).collect::<Vec<_>>();
        let ch = Arc::new(Channel {
            chan_id,
            lanes,
            opening: AtomicBool::new(false),
            tasks: Mutex::new(JoinSet::new()),
            stats: self.stats.clone(),
        });
        self.stats.channels.fetch_add(1, Ordering::Relaxed);
        for l in &ch.lanes {
            ch.spawn(l.clone().sender_task());
        }
        ch
    }

    fn new_channel(self: &Arc<Self>, chan_id: u64, nlanes: u8) -> std::result::Result<Arc<Channel>, FailReason> {
        let mut map = self.channels.lock().unwrap();
        if map.len() > self.limits.max_channels {
            return Err(FailReason::ResourceLimit);
        }
        if map.contains_key(&chan_id) {
            return Err(FailReason::Protocol(format!("channel {chan_id} already exists")));
        }
        let ch = self.make_channel(chan_id, nlanes);
        // Supervisor: drop the channel once every lane is complete.
        let me = Arc::downgrade(self);
        let lanes = ch.lanes.clone();
        ch.spawn(async move {
            for l in &lanes {
                loop {
                    let fut = l.done.notified();
                    tokio::pin!(fut);
                    fut.as_mut().enable();
                    if l.is_complete() {
                        break;
                    }
                    fut.await;
                }
            }
            if let Some(s) = me.upgrade() {
                drop(s.drop_channel(chan_id));
                let _ = s.send_event(Message::ChannelDone { chan_id }).await;
            }
        });
        map.insert(chan_id, ch.clone());
        Ok(ch)
    }

    fn drop_channel(&self, chan_id: u64) -> Option<Arc<Channel>> {
        if chan_id == EVENT_CHANNEL {
            return None;
        }
        self.channels.lock().unwrap().remove(&chan_id)
    }

    /// Abnormal end of a channel: drop it and tell the peer (as an event, so
    /// it survives a carrier death).
    pub(crate) async fn abort_channel(&self, chan_id: u64, reason: String) {
        if let Some(ch) = self.drop_channel(chan_id) {
            tracing::debug!(chan = chan_id, "closing channel: {reason}");
            drop(ch);
            let _ = self.send_event(Message::ChannelClose { chan_id, reason }).await;
        }
    }

    /// Bridge a TCP connection to lane 0 of `ch`.
    fn start_tcp(self: &Arc<Self>, ch: &Arc<Channel>, tcp: TcpStream) {
        let sock = socket2::SockRef::from(&tcp);
        let _ = sock.set_recv_buffer_size(self.limits.tcp_socket_buffer);
        let _ = sock.set_send_buffer_size(self.limits.tcp_socket_buffer);
        let _ = tcp.set_nodelay(true);
        let (r, w) = tcp.into_split();
        let lane = ch.lanes[0].clone();
        let chan_id = ch.chan_id;
        let me = Arc::downgrade(self);
        let l2 = lane.clone();
        let me2 = me.clone();
        ch.spawn(async move {
            if let Err(e) = l2.source_task(r).await
                && let Some(s) = me2.upgrade()
            {
                s.abort_channel(chan_id, format!("local read failed: {e}")).await;
            }
        });
        ch.spawn(async move {
            if let Err(e) = lane.sink_task(w).await
                && let Some(s) = me.upgrade()
            {
                s.abort_channel(chan_id, format!("local write failed: {e}")).await;
            }
        });
    }

    /// Open a QUIC stream for `lane` on the current carrier.
    async fn open_lane(self: &Arc<Self>, lane: &Arc<Lane>) -> Result<()> {
        let (conn, _) = self.conn().ok_or(Error::CarrierLost)?;
        let (mut s, mut r) = conn.open_bi().await?;
        let epoch = lane.epoch();
        write_header(&mut s, &LaneHeader { chan_id: lane.chan_id, lane: lane.lane, offset_out: lane.send_from() }).await?;
        let lane = lane.clone();
        tokio::spawn(async move {
            let res = async {
                let h = read_header(&mut r).await?;
                if h.chan_id != lane.chan_id || h.lane != lane.lane {
                    return Err(Error::Protocol(format!(
                        "lane reply header names {}/{}, expected {}/{}",
                        h.chan_id, h.lane, lane.chan_id, lane.lane
                    )));
                }
                lane.attach(conn.clone(), s, r, h.offset_out, epoch)
            }
            .await;
            match res {
                Err(Error::Protocol(m)) => conn.close(close::PROTOCOL.into(), m.as_bytes()),
                Err(e) => tracing::debug!("lane open failed: {e}"),
                Ok(()) => {}
            }
        });
        Ok(())
    }

    /// Client: open a `direct-tcp` channel and bridge `tcp` to it.
    pub async fn open_direct_tcp(self: &Arc<Self>, tcp: TcpStream, host: String, port: u16) -> Result<u64> {
        self.open_tcp_channel(tcp, ChannelKind::DirectTcp { host, port }).await
    }

    /// Open a channel for a local TCP connection and bridge it once the peer
    /// accepts. Lane streams are always opened by the client.
    async fn open_tcp_channel(self: &Arc<Self>, tcp: TcpStream, kind: ChannelKind) -> Result<u64> {
        let chan_id = self.next_chan.fetch_add(2, Ordering::Relaxed);
        let ch = self.new_channel(chan_id, 1).map_err(Error::Refused)?;
        ch.opening.store(true, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(chan_id, tx);
        let limit = ch.lanes[0].initial_limit();
        self.send_event(Message::ChannelOpen { chan_id, kind, limit }).await?;
        // The answer is an event too: it arrives after a resume if the
        // carrier dies meanwhile. Only teardown drops `tx`.
        let peer_limit = match rx.await {
            Ok(Ok(l)) => l,
            Ok(Err(reason)) => {
                drop(self.drop_channel(chan_id));
                return Err(Error::Refused(reason));
            }
            Err(_) => {
                drop(self.drop_channel(chan_id));
                return Err(Error::CarrierLost);
            }
        };
        ch.lanes[0].set_peer_limit(peer_limit);
        ch.opening.store(false, Ordering::Relaxed);
        self.start_tcp(&ch, tcp);
        if self.role == Role::Client
            && let Err(e) = self.open_lane(&ch.lanes[0]).await
        {
            // Detached now: the next resume opens it.
            tracing::debug!(chan = chan_id, "lane not opened now ({e}); the next resume will");
        }
        Ok(chan_id)
    }

    /// Peer's ChannelOpen (from the event log).
    async fn on_channel_open(self: &Arc<Self>, chan_id: u64, kind: ChannelKind, peer_limit: u64) -> Result<()> {
        let peer_parity = if self.role == Role::Server { 0 } else { 1 };
        if chan_id % 2 != peer_parity || chan_id == EVENT_CHANNEL {
            return Err(Error::Protocol(format!("channel id {chan_id} is not the peer's to open")));
        }
        let (host, port) = match (self.role, kind) {
            (Role::Server, ChannelKind::DirectTcp { host, port }) => {
                if !self.authz().allows_direct_tcp(&host, port) {
                    return self.reply_event(Message::ChannelFail { chan_id, reason: FailReason::Prohibited });
                }
                (host, port)
            }
            (Role::Client, ChannelKind::ForwardedTcp { bind_host, bind_port, .. }) => {
                match self.remote_forwards.lock().unwrap().get(&(bind_host, bind_port)).cloned() {
                    Some(target) => target,
                    None => return self.reply_event(Message::ChannelFail { chan_id, reason: FailReason::Prohibited }),
                }
            }
            (_, k) => return Err(Error::Protocol(format!("{:?} may not open {k:?}", self.role.peer()))),
        };
        self.accept_tcp_channel(chan_id, host, port, peer_limit)
    }

    /// Accept a peer's channel by dialing `host:port`; answer Ok/Fail.
    fn accept_tcp_channel(self: &Arc<Self>, chan_id: u64, host: String, port: u16, peer_limit: u64) -> Result<()> {
        let ch = match self.new_channel(chan_id, 1) {
            Ok(ch) => ch,
            Err(FailReason::Protocol(m)) => return Err(Error::Protocol(m)),
            Err(reason) => return self.reply_event(Message::ChannelFail { chan_id, reason }),
        };
        ch.lanes[0].set_peer_limit(peer_limit);
        let me = Arc::downgrade(self);
        let timeout = self.limits.connect_timeout;
        let ch2 = ch.clone();
        ch.spawn(async move {
            let dial = tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), port))).await;
            let Some(s) = me.upgrade() else { return };
            let res = match dial {
                Ok(Ok(tcp)) => Ok(tcp),
                Ok(Err(e)) => Err(format!("{host}:{port}: {e}")),
                Err(_) => Err(format!("{host}:{port}: no answer within {timeout:?}")),
            };
            match res {
                Ok(tcp) => {
                    s.start_tcp(&ch2, tcp);
                    let limit = ch2.lanes[0].initial_limit();
                    let _ = s.send_event(Message::ChannelOk { chan_id, limit }).await;
                    if s.role == Role::Client
                        && let Err(e) = s.open_lane(&ch2.lanes[0]).await
                    {
                        tracing::debug!(chan = chan_id, "lane not opened now ({e}); the next resume will");
                    }
                }
                Err(e) => {
                    drop(ch2);
                    drop(s.drop_channel(chan_id));
                    let _ = s.send_event(Message::ChannelFail { chan_id, reason: FailReason::ConnectFailed(e) }).await;
                }
            }
        });
        Ok(())
    }

    // ------------------------------------------------------------ -R

    /// Client: ask the server to listen on `bind_host:bind_port` and forward
    /// accepted connections to `target`. Returns the bound port.
    pub async fn forward_remote(self: &Arc<Self>, bind_host: String, bind_port: u16, target: (String, u16)) -> Result<u16> {
        let req_id = self.next_req.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.listen_pending.lock().unwrap().insert(req_id, (bind_host.clone(), target, tx));
        self.send_event(Message::ListenRequest { req_id, host: bind_host, port: bind_port }).await?;
        match rx.await {
            Ok(Ok(port)) => Ok(port),
            Ok(Err(reason)) => Err(Error::Refused(reason)),
            Err(_) => Err(Error::CarrierLost),
        }
    }

    /// Server: a ListenRequest.
    async fn on_listen_request(self: &Arc<Self>, req_id: u64, host: String, port: u16) -> Result<()> {
        if self.role != Role::Server {
            return Err(Error::Protocol("ListenRequest sent to a client".into()));
        }
        if !self.authz().allows_listen(&host, port) {
            return self.reply_event(Message::ListenFail { req_id, reason: FailReason::Prohibited });
        }
        if self.listeners.lock().unwrap().len() >= self.limits.max_listeners {
            return self.reply_event(Message::ListenFail { req_id, reason: FailReason::ResourceLimit });
        }
        // OpenSSH: empty or "localhost" binds loopback; "*" all addresses.
        let addr = match host.as_str() {
            "" | "localhost" => "127.0.0.1".to_string(),
            "*" => "0.0.0.0".to_string(),
            h => h.to_string(),
        };
        let l = match tokio::net::TcpListener::bind((addr.as_str(), port)).await {
            Ok(l) => l,
            Err(e) => return self.reply_event(Message::ListenFail { req_id, reason: FailReason::BindFailed(format!("{addr}:{port}: {e}")) }),
        };
        let bound = l.local_addr()?.port();
        let key = (host.clone(), bound);
        if self.listeners.lock().unwrap().contains_key(&key) {
            return self.reply_event(Message::ListenFail { req_id, reason: FailReason::BindFailed(format!("{host}:{bound} already forwarded")) });
        }
        let me = Arc::downgrade(self);
        let (bind_host, max) = (host.clone(), self.limits.detached_accept_max);
        let waiting = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, origin)) = l.accept().await else { return };
                let Some(s) = me.upgrade() else { return };
                // While detached, a bounded number of connections may wait.
                if !s.is_attached() && waiting.load(Ordering::Acquire) >= max as u64 {
                    s.refused_detached.fetch_add(1, Ordering::Relaxed);
                    drop(tcp);
                    continue;
                }
                waiting.fetch_add(1, Ordering::AcqRel);
                let waiting = waiting.clone();
                let kind = ChannelKind::ForwardedTcp { bind_host: bind_host.clone(), bind_port: bound, origin_host: origin.ip().to_string(), origin_port: origin.port() };
                tokio::spawn(async move {
                    let r = s.open_tcp_channel(tcp, kind).await;
                    waiting.fetch_sub(1, Ordering::AcqRel);
                    if let Err(e) = r {
                        tracing::debug!("-R connection from {origin} not forwarded: {e}");
                    }
                });
            }
        });
        self.listeners.lock().unwrap().insert(key, Listener { task });
        self.reply_event(Message::ListenOk { req_id, port: bound })
    }

    pub fn listener_count(&self) -> usize {
        self.listeners.lock().unwrap().len()
    }

    // ---------------------------------------------------------- dispatch

    /// Session events (reliable log).
    async fn dispatch_event(self: &Arc<Self>, m: Message) -> Result<()> {
        match m {
            Message::ChannelOpen { chan_id, kind, limit } => self.on_channel_open(chan_id, kind, limit).await,
            Message::ChannelOk { chan_id, limit } => match self.pending.lock().unwrap().remove(&chan_id) {
                Some(tx) => {
                    let _ = tx.send(Ok(limit));
                    Ok(())
                }
                None => Err(Error::Protocol(format!("ChannelOk for channel {chan_id} that is not being opened"))),
            },
            Message::ChannelFail { chan_id, reason } => {
                if let Some(tx) = self.pending.lock().unwrap().remove(&chan_id) {
                    let _ = tx.send(Err(reason));
                }
                Ok(())
            }
            Message::ChannelClose { chan_id, reason } => {
                tracing::debug!(chan = chan_id, "peer closed channel: {reason}");
                drop(self.drop_channel(chan_id));
                Ok(())
            }
            Message::ListenRequest { req_id, host, port } => self.on_listen_request(req_id, host, port).await,
            Message::ListenOk { req_id, port } => {
                // Register the target here, in event order: the server's
                // first ChannelOpen for this listener comes after ListenOk.
                let p = self.listen_pending.lock().unwrap().remove(&req_id);
                match p {
                    Some((host, target, tx)) => {
                        self.remote_forwards.lock().unwrap().insert((host, port), target);
                        let _ = tx.send(Ok(port));
                        Ok(())
                    }
                    None => Err(Error::Protocol(format!("ListenOk for unknown request {req_id}"))),
                }
            }
            Message::ListenFail { req_id, reason } => {
                if let Some((_, _, tx)) = self.listen_pending.lock().unwrap().remove(&req_id) {
                    let _ = tx.send(Err(reason));
                }
                Ok(())
            }
            Message::ListenCancel { host, port } => {
                drop(self.listeners.lock().unwrap().remove(&(host, port)));
                Ok(())
            }
            Message::ChannelDone { chan_id } => {
                if let Some(ch) = self.channel(chan_id) {
                    for l in &ch.lanes {
                        l.peer_done();
                    }
                }
                Ok(())
            }
            Message::LaneFin { chan_id, lane, final_offset } => {
                if let Some(ch) = self.channel(chan_id) {
                    let l = ch.lanes.get(lane as usize).ok_or_else(|| Error::Protocol(format!("LaneFin for lane {lane} of channel {chan_id}")))?;
                    l.on_fin(final_offset)?;
                }
                Ok(())
            }
            other => Err(Error::Protocol(format!("connection-scoped message in the session event log: {other:?}"))),
        }
    }

    /// Control stream after authentication: only LaneAck.
    fn dispatch_control(&self, m: Message) -> Result<()> {
        match m {
            Message::Ping { n } => {
                // Best effort: a full queue means the path is congested
                // anyway, and the prober will try again.
                let _ = self.send_ctrl(Message::Pong { n });
                Ok(())
            }
            Message::Pong { n } => {
                self.last_pong.send_if_modified(|v| {
                    let up = n > *v;
                    if up {
                        *v = n;
                    }
                    up
                });
                Ok(())
            }
            Message::LaneAck { chan_id, lane, accepted, limit } => {
                // A channel closed locally may still receive in-flight acks.
                if let Some(ch) = self.channel(chan_id) {
                    let l = ch.lanes.get(lane as usize).ok_or_else(|| Error::Protocol(format!("ack for lane {lane} of channel {chan_id}")))?;
                    l.on_ack(accepted, limit)?;
                }
                Ok(())
            }
            other => Err(Error::Protocol(format!("unexpected message on the control stream after authentication: {other:?}"))),
        }
    }

    // ------------------------------------------------------------- carrier

    async fn control_reader(self: Arc<Self>, conn: Connection, mut recv: RecvStream) {
        loop {
            match frame::read_message(&mut recv, MAX_FRAME).await {
                Ok(Some(m)) => {
                    if let Err(e) = self.dispatch_control(m) {
                        tracing::warn!(session = %hex(&self.id), "closing carrier: {e}");
                        conn.close(close::PROTOCOL.into(), e.to_string().as_bytes());
                        return;
                    }
                }
                Ok(None) => {
                    conn.close(close::SHUTDOWN.into(), b"control stream finished");
                    return;
                }
                Err(Error::Protocol(m)) => {
                    conn.close(close::PROTOCOL.into(), m.as_bytes());
                    return;
                }
                Err(e) => {
                    tracing::debug!("control stream ended: {e}");
                    return;
                }
            }
        }
    }

    async fn write_ack(send: &mut SendStream, l: &Lane) -> bool {
        let (accepted, limit) = l.take_ack();
        let m = Message::LaneAck { chan_id: l.chan_id, lane: l.lane, accepted, limit };
        frame::write_message(send, &m).await.is_ok()
    }

    async fn control_writer(self: Arc<Self>, mut send: SendStream, mut rx: mpsc::Receiver<Message>, first: Option<Message>) {
        if let Some(m) = first
            && frame::write_message(&mut send, &m).await.is_err()
        {
            return;
        }
        let mut tick = tokio::time::interval(self.limits.ack_interval);
        loop {
            let fut = self.acks.notify.notified();
            tokio::pin!(fut);
            fut.as_mut().enable();
            let urgent = std::mem::take(&mut *self.acks.urgent.lock().unwrap());
            for l in urgent {
                if !Self::write_ack(&mut send, &l).await {
                    return;
                }
            }
            tokio::select! {
                m = rx.recv() => match m {
                    Some(m) => {
                        if frame::write_message(&mut send, &m).await.is_err() {
                            return;
                        }
                    }
                    None => return,
                },
                _ = fut => {}
                _ = tick.tick() => {
                    let lazy = std::mem::take(&mut *self.acks.lazy.lock().unwrap());
                    for l in lazy {
                        if !Self::write_ack(&mut send, &l).await {
                            return;
                        }
                    }
                }
            }
        }
    }

    async fn acceptor(self: Arc<Self>, conn: Connection) {
        loop {
            let Ok((mut s, mut r)) = conn.accept_bi().await else { return };
            let me = self.clone();
            let conn = conn.clone();
            tokio::spawn(async move {
                let res = async {
                    let h = read_header(&mut r).await?;
                    let Some(ch) = me.channel(h.chan_id) else {
                        // Closed meanwhile (its close event is in the log).
                        let _ = s.reset(0u32.into());
                        let _ = r.stop(0u32.into());
                        return Ok(());
                    };
                    let lane = ch.lanes.get(h.lane as usize).cloned().ok_or_else(|| {
                        Error::Protocol(format!("lane {} of channel {} does not exist", h.lane, h.chan_id))
                    })?;
                    let epoch = lane.epoch();
                    write_header(&mut s, &LaneHeader { chan_id: h.chan_id, lane: h.lane, offset_out: lane.send_from() }).await?;
                    lane.attach(conn.clone(), s, r, h.offset_out, epoch)
                }
                .await;
                match res {
                    Err(Error::Protocol(m)) => conn.close(close::PROTOCOL.into(), m.as_bytes()),
                    Err(e) => tracing::debug!("lane accept failed: {e}"),
                    Ok(()) => {}
                }
            });
        }
    }

    /// Datagrams are SPEC §6 (next milestone): drained and dropped so they
    /// never hold connection buffers.
    async fn datagram_sink(conn: Connection) {
        while conn.read_datagram().await.is_ok() {}
    }

    /// §1 connection-window scheduler. Every max(RTT, window_sample_min) it
    /// compares the bytes moved (either direction) with what the window
    /// allows per RTT. After `window_raise_after` window-limited samples the
    /// windows double, up to the ceiling, charged to the ConnWindowBudget
    /// (only what the budget gives is granted). After `window_lower_after`
    /// below `window_lower_util_pct` they drop to the floor — but credit
    /// already granted cannot be revoked (X6), so the charge stays at the old
    /// window until that many bytes have been received since the change.
    async fn window_scheduler(self: Arc<Self>, conn: Connection) {
        use crate::budget::Permit;
        let l = self.limits.clone();
        let floor = l.floor_window;
        let mut window = floor;
        let mut charge = Permit::empty(self.budgets.conn.clone()); // above the floor
        let mut debt: Option<(u64, u64)> = None; // (old window, rx when lowered)
        let mut streak = 0u32;
        let mut low_since: Option<std::time::Instant> = None;
        let st0 = conn.stats();
        let (mut last_rx, mut last_tx) = (st0.udp_rx.bytes, st0.udp_tx.bytes);
        let publish = |window: u64, charge: &Permit| {
            self.stats.conn_window.store(window, Ordering::Relaxed);
            self.stats.conn_window_charged.store(floor + charge.amount(), Ordering::Relaxed);
        };
        publish(window, &charge);
        loop {
            let rtt = conn.rtt().max(std::time::Duration::from_micros(100));
            let period = rtt.max(l.window_sample_min);
            tokio::time::sleep(period).await;
            let st = conn.stats();
            let (rx, tx) = (st.udp_rx.bytes, st.udp_tx.bytes);
            let moved = (rx - last_rx).max(tx - last_tx);
            (last_rx, last_tx) = (rx, tx);
            if let Some((old, at)) = debt
                && rx - at >= old
            {
                debt = None;
                charge.set(window - floor);
            }
            // What the window allows in one period at this RTT.
            let allowed = (window as f64 * period.as_secs_f64() / rtt.as_secs_f64()).max(1.0);
            let util = moved as f64 / allowed;
            tracing::trace!(session = %hex(&self.id), ?rtt, ?period, moved, allowed, util, window, "window sample");
            if util >= 0.8 {
                streak += 1;
                low_since = None;
            } else {
                streak = 0;
                if util * 100.0 < l.window_lower_util_pct as f64 {
                    low_since.get_or_insert_with(std::time::Instant::now);
                } else {
                    low_since = None;
                }
            }
            if streak >= l.window_raise_after && window < l.conn_window_ceiling {
                let target = (window * 2).min(l.conn_window_ceiling);
                if target - floor > charge.amount() {
                    let want = target - floor - charge.amount();
                    charge.grow_upto(want);
                }
                let new = target.min(floor + charge.amount());
                if new > window {
                    window = new;
                    conn.set_receive_window(quinn::VarInt::from_u64(window).expect("window fits a varint"));
                    conn.set_send_window(window);
                    self.stats.window_raises.fetch_add(1, Ordering::Relaxed);
                }
                streak = 0;
            }
            if low_since.is_some_and(|t| t.elapsed() >= l.window_lower_after) && window > floor {
                // Keep charging the old window until it has been read.
                debt = Some((window, rx));
                window = floor;
                conn.set_receive_window(quinn::VarInt::from_u64(window).expect("window fits a varint"));
                conn.set_send_window(window);
                self.stats.window_lowers.fetch_add(1, Ordering::Relaxed);
                low_since = None;
            }
            publish(window, &charge);
        }
    }

    async fn watch_death(self: Arc<Self>, conn: Connection, epoch: u64) {
        let reason = conn.closed().await;
        tracing::debug!(session = %hex(&self.id), epoch, "carrier closed: {reason}");
        self.on_carrier_death(epoch);
    }

    fn on_carrier_death(self: &Arc<Self>, epoch: u64) {
        let old = {
            let mut c = self.carrier.lock().unwrap();
            if c.as_ref().map(|c| c.epoch) != Some(epoch) {
                return;
            }
            c.take()
        };
        self.carrier_state.send_replace(0);
        if self.role == Role::Server && self.registry.is_some() {
            let me = Arc::downgrade(self);
            let linger = self.limits.linger;
            tokio::spawn(async move {
                tokio::time::sleep(linger).await;
                if let Some(s) = me.upgrade()
                    && s.epoch.load(Ordering::SeqCst) == epoch
                    && !s.is_attached()
                {
                    tracing::info!(session = %hex(&s.id), "detached session expired after {linger:?}");
                    s.teardown();
                }
            });
        }
        drop(old); // aborts this task too; nothing follows
    }

    /// Install a new carrier; the caller holds `attach_lock`. `first` is
    /// written before anything else on the control stream (AuthOk/Resumed).
    /// Returns the new attach epoch.
    pub(crate) fn install_carrier(self: &Arc<Self>, conn: Connection, send: SendStream, recv: RecvStream, first: impl FnOnce(u64) -> Option<Message>) -> u64 {
        let epoch = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;
        let (tx, rx) = mpsc::channel(16);
        let mut tasks = JoinSet::new();
        tasks.spawn(self.clone().control_writer(send, rx, first(epoch)));
        tasks.spawn(self.clone().control_reader(conn.clone(), recv));
        tasks.spawn(self.clone().acceptor(conn.clone()));
        tasks.spawn(Self::datagram_sink(conn.clone()));
        tasks.spawn(self.clone().watch_death(conn.clone(), epoch));
        tasks.spawn(self.clone().window_scheduler(conn.clone()));
        let old = self.carrier.lock().unwrap().replace(Carrier { epoch, conn, _ctrl: tx, _tasks: tasks });
        if let Some(old) = old {
            old.conn.close(close::SUPERSEDED.into(), b"superseded by a newer carrier");
        }
        self.carrier_state.send_replace(epoch);
        epoch
    }

    /// Detach the current carrier (resume path, shutdown).
    pub(crate) fn detach(&self, code: u32, reason: &[u8]) {
        let old = self.carrier.lock().unwrap().take();
        if let Some(c) = old {
            c.conn.close(code.into(), reason);
        }
        self.carrier_state.send_replace(0);
    }

    /// Drop everything: carrier, channels, pending opens, registry entry.
    pub fn teardown(&self) {
        self.detach(close::SHUTDOWN, b"session closed");
        let listeners: Vec<_> = self.listeners.lock().unwrap().drain().collect();
        drop(listeners);
        let lp: Vec<_> = self.listen_pending.lock().unwrap().drain().collect();
        drop(lp);
        let pending: Vec<_> = self.pending.lock().unwrap().drain().collect();
        drop(pending);
        let chans: Vec<_> = self.channels.lock().unwrap().drain().collect();
        drop(chans);
        if let Some(r) = self.registry.as_ref().and_then(|r| r.upgrade()) {
            let me = r.lock().unwrap().remove(&self.id);
            drop(me);
        }
    }

    /// Our position on every lane, fencing off tasks of the old carrier.
    pub(crate) fn snapshot_lanes(&self) -> Vec<LanePos> {
        let chans: Vec<_> = self.channels.lock().unwrap().values().cloned().collect();
        chans.iter().flat_map(|ch| ch.lanes.iter().map(|l| l.fence())).collect()
    }

    /// Check a peer's resume positions without touching anything: the whole
    /// Resume is validated before the current carrier is detached.
    pub(crate) fn validate_resume(&self, peer: &[LanePos]) -> Result<()> {
        if peer.len() > (self.limits.max_channels + 1) * 4 {
            return Err(Error::Protocol(format!("resume lists {} lanes, more than possible", peer.len())));
        }
        for p in peer {
            if let Some(ch) = self.channel(p.chan_id) {
                let l = ch.lanes.get(p.lane as usize).ok_or_else(|| {
                    Error::Protocol(format!("resume names lane {} of channel {}, which has {}", p.lane, p.chan_id, ch.lanes.len()))
                })?;
                l.check_resume(p)?;
            }
        }
        Ok(())
    }

    /// Apply the peer's positions. Only lanes the peer lists are rewound; a
    /// snapshot never releases bytes of a lane it does not mention, so a
    /// stale or competing snapshot cannot discard data. Channels the peer
    /// completed are finished by its ChannelDone event, channels it aborted
    /// by its ChannelClose event — both replayed in the event log.
    pub(crate) fn reconcile(&self, peer: &[LanePos]) -> Result<()> {
        self.validate_resume(peer)?;
        for p in peer {
            if let Some(ch) = self.channel(p.chan_id) {
                ch.lanes[p.lane as usize].on_resume(p)?;
            }
        }
        Ok(())
    }

    /// Client after attach: open every lane on the new carrier, except
    /// channels still waiting for ChannelOk.
    pub(crate) async fn reopen_lanes(self: &Arc<Self>) -> Result<()> {
        let chans: Vec<_> = self.channels.lock().unwrap().values().cloned().collect();
        for ch in chans {
            if ch.opening.load(Ordering::Relaxed) {
                continue;
            }
            for l in &ch.lanes {
                self.open_lane(l).await?;
            }
        }
        Ok(())
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
