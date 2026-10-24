//! Control-stream messages (SPEC §3). Encoded with postcard; the enum
//! discriminant is the "message type" and is checked before decoding so that
//! an unknown type is reported by number instead of as a generic decode error.

use serde::{Deserialize, Serialize};

pub type SessionId = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Intent {
    New,
    Resume,
}

impl Intent {
    /// The string signed into the auth blob (SPEC §2.2).
    pub fn as_str(self) -> &'static str {
        match self {
            Intent::New => "new",
            Intent::Resume => "resume",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: SessionId,
    pub linger_secs: u64,
}

/// Position of one lane in a Resume/Resumed exchange: the sender of the
/// message has `accepted` bytes of that lane in its receive ring and grants
/// credit up to the absolute `limit` (SPEC §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanePos {
    pub chan_id: u64,
    pub lane: u8,
    pub accepted: u64,
    pub limit: u64,
    /// The receiver's fence seq for this lane (SPEC §4 retraction).
    pub seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelKind {
    /// -L / -D CONNECT: the server dials `host:port`.
    DirectTcp { host: String, port: u16 },
    /// -R: a connection accepted by the server's listener `bind_host:bind_port`
    /// (as bound) from `origin`; the client dials its registered target.
    ForwardedTcp { bind_host: String, bind_port: u16, origin_host: String, origin_port: u16 },
    /// Interactive or exec session (lane 0 stdin/stdout, lane 1 stderr).
    Session,
    /// A connection to the session's forwarded agent socket (server opens;
    /// the client bridges it to its local agent).
    AuthAgent,
    /// -L UDP / SOCKS UDP ASSOCIATE: one flow; the server sends to `host:port`.
    DirectUdp { host: String, port: u16 },
    /// -R UDP: one flow from `origin` to the server's UDP listener.
    ForwardedUdp { bind_host: String, bind_port: u16, origin_host: String, origin_port: u16 },
    /// Client → gateway (SPEC §7.2): relay datagrams to the peer registered
    /// as `name` (inner QUIC packets, end-to-end fragmented).
    JumpPeer { name: String },
    /// Gateway → registered peer: the other end of a JumpPeer relay; `from`
    /// is the jumping client's address as the gateway observes it.
    PeerRelay { from: String },
}

/// A request on a session channel (RFC 4254 §6, carried as events).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessReq {
    Pty { term: String, cols: u32, rows: u32, xpixel: u32, ypixel: u32, modes: Vec<u8> },
    Env { name: String, value: String },
    Shell,
    Exec { command: String },
    Subsystem { name: String },
    WindowChange { cols: u32, rows: u32, xpixel: u32, ypixel: u32 },
    Signal { name: String },
    /// Agent forwarding for the session (auth-agent-req@openssh.com).
    AuthAgent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailReason {
    ResourceLimit,
    Prohibited,
    ConnectFailed(String),
    BindFailed(String),
    UnknownChannel,
    Protocol(String),
}

impl std::fmt::Display for FailReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailReason::ResourceLimit => write!(f, "resource limit reached"),
            FailReason::Prohibited => write!(f, "prohibited by server policy"),
            FailReason::ConnectFailed(e) => write!(f, "connect failed: {e}"),
            FailReason::BindFailed(e) => write!(f, "bind failed: {e}"),
            FailReason::UnknownChannel => write!(f, "unknown channel"),
            FailReason::Protocol(e) => write!(f, "protocol error: {e}"),
        }
    }
}

/// Every message. Variant order is the wire type number: append only, never
/// reorder.
///
/// Connection-scoped (plain control stream): Auth, AuthOk, AuthFail, Resume,
/// Resumed, Fail, LaneAck. Session-scoped (reliable event log, SPEC §5):
/// ChannelOpen, ChannelOk, ChannelFail, ChannelClose, LaneFin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    Auth { user: String, pubkey: Vec<u8>, sig: Vec<u8>, intent: Intent },
    AuthOk { session: Option<SessionInfo> },
    AuthFail { reason: String },
    Resume { session_id: SessionId, lanes: Vec<LanePos> },
    /// `epoch`: the session's attach epoch of this carrier.
    Resumed { lanes: Vec<LanePos>, epoch: u64 },
    Fail { reason: FailReason },
    /// `limit`: initial absolute credit the opener grants on every lane.
    ChannelOpen { chan_id: u64, kind: ChannelKind, limit: u64 },
    ChannelOk { chan_id: u64, limit: u64 },
    ChannelFail { chan_id: u64, reason: FailReason },
    /// Abnormal end of a channel (reset); normal ends are LaneFin on every
    /// lane direction.
    ChannelClose { chan_id: u64, reason: String },
    /// Receiver → sender: `accepted` bytes are in the receiver's ring (replay
    /// retention); the sender may send bytes with offset < `limit`
    /// (absolute, monotone credit; SPEC §4).
    LaneAck { chan_id: u64, lane: u8, accepted: u64, limit: u64, seq: u64 },
    /// End of one lane direction at `final_offset` (half-close), as an event
    /// so it is never confused with a carrier death (SPEC §5).
    LaneFin { chan_id: u64, lane: u8, final_offset: u64 },
    /// The sender completed the channel (every lane direction finished and
    /// delivered): it holds all bytes the receiver sent. Lets the receiver
    /// finish a channel whose final ack died with a carrier.
    ChannelDone { chan_id: u64 },
    /// -R: ask the server to listen on `host:port` (port 0 = any).
    ListenRequest { req_id: u64, host: String, port: u16 },
    /// The listener is up on `port`.
    ListenOk { req_id: u64, port: u16 },
    ListenFail { req_id: u64, reason: FailReason },
    /// Stop a listener (as bound).
    ListenCancel { host: String, port: u16 },
    /// Liveness probe on the control stream (connection-scoped, SPEC §5.1).
    Ping { n: u64 },
    Pong { n: u64 },
    /// Session-channel request; answered by SessionReply (error text on
    /// failure).
    SessionRequest { chan_id: u64, req_id: u64, req: SessReq },
    SessionReply { chan_id: u64, req_id: u64, error: Option<String> },
    /// The session's process ended (RFC 4254 §6.10), as events so they are
    /// replayed after a resume.
    ExitStatus { chan_id: u64, status: u32 },
    ExitSignal { chan_id: u64, signal: String, core_dumped: bool },
    /// -R UDP: listen on `host:port` (0 = any); answered by ListenOk/Fail.
    UdpListenRequest { req_id: u64, host: String, port: u16 },
    UdpListenCancel { host: String, port: u16 },
    /// Receiver → sender (control stream): stop at max(sent, new_limit);
    /// opens fence `seq` (SPEC §4 fenced credit retraction).
    Retract { chan_id: u64, lane: u8, seq: u64, new_limit: u64 },
    /// Sender → receiver: it stopped; `sent` = end of bytes sent on the lane.
    RetractAck { chan_id: u64, lane: u8, seq: u64, sent: u64 },
    /// Client → server, event log: the client ends the session on purpose;
    /// the server destroys it at once (SPEC §5 "Deliberate end").
    SessionEnd,
    /// Client → gateway, event log (SPEC §7.1): register this session as the
    /// peer `name`; answered by ListenOk (port 0) / ListenFail.
    Register { req_id: u64, name: String },
    /// Server → client, control stream, after every attach: the client's
    /// address as the server observes it (server-reflexive, SPEC §7.3).
    Observed { addr: String },
    /// Inner connection, control stream: an encoded ssh3-path signal
    /// (candidates, nomination; SPEC §7.3).
    PathSignal { bytes: Vec<u8> },
}

/// Number of variants of `Message`; a wire type ≥ this is unknown.
pub const MESSAGE_TYPES: u32 = 31;

/// Channel id of the session event log (lane 0).
pub const EVENT_CHANNEL: u64 = 0;

/// First frame on every lane stream, in both directions (SPEC §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneHeader {
    pub chan_id: u64,
    pub lane: u8,
    /// Offset of the first byte that follows on this stream.
    pub offset_out: u64,
}
