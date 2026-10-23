//! ssh3-rs path layer: everything **below quinn** needed for SPEC §7 (jump, relay, NAT
//! traversal) — objective O3.
//!
//! # Pieces
//! * [`PathSocket`] — the endpoint's `AsyncUdpSocket`: virtual peer addresses (`fd00::/8`) per
//!   inner connection, swappable real path (relay carrier or direct UDP), strict inbound,
//!   side-channel demultiplexing by the QUIC fixed bit.
//! * [`PathManager`] — per endpoint, the single owner of rebind, relay carrier replacement,
//!   selected direct pair and fallback; [`PeerPath`] — per inner connection, the candidate
//!   exchange / authenticated punching / nomination / keepalive / fallback state machine.
//! * [`wire`] — side-channel and signal formats.
//! * [`sim`] — in-memory network with RFC 4787 NAT behaviours and a test gateway.
//!
//! # Integration contract for ssh3-core (not yet wired)
//! 1. Build the endpoint on `PathManager::socket()` with `EndpointConfig::grease_quic_bit(false)`
//!    and call `attach_endpoint`.
//! 2. For `ssh3 -J gw target` / a registered peer: implement [`RelayLink`] over the `jump`
//!    channel (end-to-end fragmentation of §7.2 lives there), `add_relay_route` → dial (client)
//!    or expect (server) the inner connection at the returned virtual address; feed relayed
//!    inbound packets to `relay_input`.
//! 3. After the inner handshake: derive 32 bytes with `export_keying_material(
//!    wire::EXPORTER_LABEL, b"", ..)`, decide `controlling` (lower (key, address) tuple), open a
//!    signal stream on the inner connection and `start_peer`; ship the encoded signals both ways
//!    (`PeerPath::signal_in`).
//! 4. Pass the gateway-observed address (`Register` reply) as `reflexive`; on carrier resume call
//!    `PeerPath::set_relay`; the client's liveness rebind (§5.1) goes through
//!    `PathManager::rebind`, never around it.
//!
//! The vendored quinn (`vendor/quinn`) adds `Connection::path_changed` (X9), called on both
//! ends of an inner connection on every switch.
pub mod candidates;
pub mod manager;
pub mod sim;
pub mod socket;
pub mod wire;

pub use manager::{PathConfig, PathManager, PathMode, PeerCounters, PeerPath, PeerSetup, PeerStatus, RoundOutcome};
pub use socket::{PathSocket, Real, RelayLink, RouteId, Shared, SocketStats, is_virtual};
