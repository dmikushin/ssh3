//! Every cap of SPEC §1, §2.3, §4, §5 in one place. All finite.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Limits {
    // §1 transport
    pub floor_window: u64,
    /// Connection windows are raised up to this (§1 scheduler).
    pub conn_window_ceiling: u64,
    /// Server-wide budget for connection windows above the floor.
    pub conn_window_budget: u64,
    /// The scheduler samples every max(RTT, this).
    pub window_sample_min: Duration,
    /// Raise after this many consecutive window-limited samples.
    pub window_raise_after: u32,
    /// Lower to the floor after this long below `window_lower_util_pct`.
    pub window_lower_after: Duration,
    pub window_lower_util_pct: u8,
    pub stream_receive_window: u64,
    pub max_bidi_streams: u32,
    pub datagram_buffer: usize,
    pub idle_timeout: Duration,
    pub keep_alive: Duration,
    // §2.3 pre-auth
    pub login_grace: Duration,
    pub max_auth_tries: u32,
    pub max_unauthenticated: usize,
    // §4 channels
    pub max_channels: usize,
    pub connect_timeout: Duration,
    /// -R listeners of one session, server side.
    pub max_listeners: usize,
    /// While detached, each -R listener keeps at most this many accepted
    /// connections waiting; more are closed at once (SPEC §5).
    pub detached_accept_max: usize,
    // §4 lane credit and budgets
    /// Ring capacity per lane direction: the cap on one lane's credit and
    /// send ring. It caps a single forward's throughput at lane_buffer/RTT,
    /// so it defaults to the connection-window ceiling; memory is bounded by
    /// the server-wide budgets, not by this cap.
    pub lane_buffer: usize,
    /// Credit every lane gets without the budget.
    pub lane_floor: u64,
    /// LaneCreditBudget: receive-ring chunk storage, server-wide.
    pub lane_credit_budget: u64,
    /// LaneSendBudget: send-ring chunk storage, server-wide.
    pub lane_send_budget: u64,
    /// Session events queued but not yet in the event lane.
    pub event_queue: usize,
    // §5 sessions
    pub ack_interval: Duration,
    pub linger: Duration,
    // §5.1 client roaming
    /// Liveness probe period while attached; None disables probing.
    pub probe_interval: Option<Duration>,
    /// A probe is lost if unanswered within max(3·RTT, this).
    pub probe_timeout_min: Duration,
    /// Resume automatically after a carrier death.
    pub auto_resume: bool,
    pub resume_backoff_initial: Duration,
    pub resume_backoff_max: Duration,
    pub max_sessions: usize,
    /// SO_RCVBUF / SO_SNDBUF on dialed and accepted TCP sockets (SPEC §5
    /// memory bound).
    pub tcp_socket_buffer: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            floor_window: 256 * 1024,
            conn_window_ceiling: 8 * 1024 * 1024,
            conn_window_budget: 256 * 1024 * 1024,
            window_sample_min: Duration::from_millis(100),
            window_raise_after: 2,
            window_lower_after: Duration::from_secs(5),
            window_lower_util_pct: 10,
            stream_receive_window: 8 * 1024 * 1024,
            max_bidi_streams: 64,
            datagram_buffer: 64 * 1024,
            idle_timeout: Duration::from_secs(30),
            keep_alive: Duration::from_secs(5),
            login_grace: Duration::from_secs(10),
            max_auth_tries: 6,
            max_unauthenticated: 64,
            max_channels: 256,
            connect_timeout: Duration::from_secs(10),
            max_listeners: 64,
            detached_accept_max: 8,
            lane_buffer: 8 * 1024 * 1024,
            lane_floor: 16 * 1024,
            lane_credit_budget: 64 * 1024 * 1024,
            lane_send_budget: 64 * 1024 * 1024,
            event_queue: 1024,
            ack_interval: Duration::from_secs(1),
            linger: Duration::from_secs(12 * 3600),
            probe_interval: Some(Duration::from_secs(1)),
            probe_timeout_min: Duration::from_secs(1),
            auto_resume: true,
            resume_backoff_initial: Duration::from_millis(200),
            resume_backoff_max: Duration::from_secs(10),
            max_sessions: 1024,
            tcp_socket_buffer: 64 * 1024,
        }
    }
}
