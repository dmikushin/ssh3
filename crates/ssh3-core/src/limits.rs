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
    /// Ring cap of pty output lanes (SPEC §5): must hold a full redraw of
    /// the largest allowed screen (validated).
    pub pty_lane_buffer: usize,
    /// pty sizes are clamped to this (pty-req, window-change), which bounds
    /// the redraw.
    pub pty_max_cols: u16,
    pub pty_max_rows: u16,
    /// Credit every lane gets without the budget. Must be a multiple of the
    /// 16 KiB ring chunk, at most 2 chunks (the storage exempt from budgets).
    pub lane_floor: u64,
    /// The receiver acks (releasing the sender's ring) after this many newly
    /// accepted bytes; credit updates follow 1/4 of the grant.
    pub lane_ack_bytes: u64,
    /// A lane without arrivals this long has its credit retracted to the
    /// floor (SPEC §4 demand-driven grants, `CreditIdle`).
    pub credit_idle: Duration,
    /// A Retract unacknowledged after max(4·RTT, this) cuts the carrier.
    pub retract_timeout_min: Duration,
    /// LaneCreditBudget: receive-ring chunk storage, server-wide.
    pub lane_credit_budget: u64,
    /// LaneSendBudget: send-ring chunk storage, server-wide.
    pub lane_send_budget: u64,
    /// Session events queued but not yet in the event lane.
    pub event_queue: usize,
    // §5 sessions
    pub ack_interval: Duration,
    pub linger: Duration,
    /// Linger of sessions with a pty; None = until the processes exit
    /// (SPEC §5 "Session lifetime", as mosh).
    pub pty_linger: Option<Duration>,
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
    // §6 UDP
    /// Flows per UDP listener (LRU beyond).
    pub udp_flows_max: usize,
    /// A UDP flow idle this long is closed (both sides).
    pub udp_flow_idle: Duration,
    /// Inbound datagrams queued per flow before dropping.
    pub udp_queue: usize,
    /// Server-wide fragment reassembly storage.
    pub reassembly_budget: u64,
    pub reassembly_max_age: Duration,
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
            // 320x120: max redraw 13.7 MB (ssh3_term::max_resync_len).
            pty_lane_buffer: 16 * 1024 * 1024,
            pty_max_cols: 320,
            pty_max_rows: 120,
            lane_floor: 16 * 1024,
            lane_ack_bytes: 16 * 1024,
            credit_idle: Duration::from_secs(5),
            retract_timeout_min: Duration::from_secs(2),
            lane_credit_budget: 64 * 1024 * 1024,
            lane_send_budget: 64 * 1024 * 1024,
            event_queue: 1024,
            ack_interval: Duration::from_secs(1),
            linger: Duration::from_secs(12 * 3600),
            pty_linger: None,
            probe_interval: Some(Duration::from_secs(1)),
            probe_timeout_min: Duration::from_secs(1),
            auto_resume: true,
            resume_backoff_initial: Duration::from_millis(200),
            resume_backoff_max: Duration::from_secs(10),
            max_sessions: 1024,
            tcp_socket_buffer: 64 * 1024,
            udp_flows_max: 256,
            udp_flow_idle: Duration::from_secs(60),
            udp_queue: 128,
            reassembly_budget: 4 * 1024 * 1024,
            reassembly_max_age: Duration::from_secs(1),
        }
    }
}

impl Limits {
    /// Reject configurations the protocol engine cannot honour, naming the
    /// field (QA: a misconfiguration must fail loudly, not be quantised).
    pub fn validate(&self) -> Result<(), String> {
        let chunk = crate::ring::CHUNK as u64;
        if self.lane_floor < chunk || self.lane_floor > 2 * chunk || !self.lane_floor.is_multiple_of(chunk) {
            return Err(format!(
                "lane_floor {} must be {chunk} or {}: credit is stored in {chunk}-byte chunks and only two per lane are exempt from the budgets",
                self.lane_floor,
                2 * chunk
            ));
        }
        if (self.lane_buffer as u64) < self.lane_floor || !(self.lane_buffer as u64).is_multiple_of(chunk) {
            return Err(format!("lane_buffer {} must be a multiple of {chunk} and at least lane_floor {}", self.lane_buffer, self.lane_floor));
        }
        if self.pty_max_cols < ssh3_term::MIN_COLUMNS
            || self.pty_max_cols > ssh3_term::MAX_COLUMNS
            || self.pty_max_rows < ssh3_term::MIN_LINES
            || self.pty_max_rows > ssh3_term::MAX_LINES
        {
            return Err(format!(
                "pty_max_cols x pty_max_rows {}x{} outside {}..={} x {}..={}",
                self.pty_max_cols,
                self.pty_max_rows,
                ssh3_term::MIN_COLUMNS,
                ssh3_term::MAX_COLUMNS,
                ssh3_term::MIN_LINES,
                ssh3_term::MAX_LINES
            ));
        }
        let redraw = ssh3_term::max_resync_len(self.pty_max_cols, self.pty_max_rows);
        if self.pty_lane_buffer < redraw || !(self.pty_lane_buffer as u64).is_multiple_of(chunk) {
            return Err(format!(
                "pty_lane_buffer {} must be a multiple of {chunk} and hold a full redraw of a {}x{} screen ({redraw} bytes)",
                self.pty_lane_buffer, self.pty_max_cols, self.pty_max_rows
            ));
        }
        if self.lane_ack_bytes == 0 {
            return Err("lane_ack_bytes must be positive".into());
        }
        if self.floor_window > self.conn_window_ceiling {
            return Err(format!("floor_window {} exceeds conn_window_ceiling {}", self.floor_window, self.conn_window_ceiling));
        }
        if self.udp_flows_max == 0 || self.udp_queue == 0 || self.udp_flow_idle.is_zero() {
            return Err("udp_flows_max, udp_queue and udp_flow_idle must be positive".into());
        }
        if self.max_auth_tries == 0 {
            return Err("max_auth_tries must be at least 1".into());
        }
        Ok(())
    }
}
