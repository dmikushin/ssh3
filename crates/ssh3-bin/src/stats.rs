//! `ServerStats` as JSON (SPEC §8 I6: every state a test or operator waits
//! on is observable). The destructuring is exhaustive, so a counter added to
//! `ServerStats` fails to compile here until it is exported.

use serde_json::{Value, json};
use ssh3_core::ServerStats;

pub fn to_json(s: &ServerStats) -> Value {
    let ServerStats {
        sessions,
        attached,
        detached,
        channels,
        send_ring_bytes,
        recv_ring_bytes,
        credit_outstanding,
        recv_budget_used,
        send_budget_used,
        floor_chunks_bytes,
        auth_failures,
        resumes_accepted,
        resumes_rejected,
        protocol_closes,
        refused_unauth_cap,
        listeners,
        refused_detached,
        conn_window_budget_used,
        window_raises,
        window_lowers,
    } = *s;
    json!({
        "sessions": sessions,
        "attached": attached,
        "detached": detached,
        "channels": channels,
        "send_ring_bytes": send_ring_bytes,
        "recv_ring_bytes": recv_ring_bytes,
        "credit_outstanding": credit_outstanding,
        "recv_budget_used": recv_budget_used,
        "send_budget_used": send_budget_used,
        "floor_chunks_bytes": floor_chunks_bytes,
        "auth_failures": auth_failures,
        "resumes_accepted": resumes_accepted,
        "resumes_rejected": resumes_rejected,
        "protocol_closes": protocol_closes,
        "refused_unauth_cap": refused_unauth_cap,
        "listeners": listeners,
        "refused_detached": refused_detached,
        "conn_window_budget_used": conn_window_budget_used,
        "window_raises": window_raises,
        "window_lowers": window_lowers,
    })
}
