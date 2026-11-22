//! Transport adapters (② §3): WS primary channel, REST, gRPC (internal), MQTT (P3), QUIC (P4), WebTransport.

pub mod grpc;
pub mod http;
pub mod mqtt;
pub mod quic;
pub mod ws;

/// WebTransport (HTTP/3) browser ingress gateway (PL-13 13.3; feature = "webtransport", not compiled by default).
///
/// The gateway bridges browser WebTransport bidirectional streams to the local QUIC relay (reusing JWT/device/participant auth and
/// TLV/relay/rate limiting); when the feature is not compiled the module does not exist and has zero side effects.
#[cfg(feature = "webtransport")]
pub mod webtransport;
