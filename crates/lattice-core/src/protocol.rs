//! Value conventions (single source of truth: design doc §17).
//!
//! This module only turns the values in the doc into constants/enums; it makes no policy decisions. Change design §17 before changing this file.

use serde::{Deserialize, Serialize};

/// Protocol version (design §17.12).
pub const PROTOCOL_VERSION: u8 = 1;
/// Deployed-configuration lower bound (design §17.12).
pub const MIN_SUPPORTED_PROTOCOL: u8 = 1;
/// The frame header version field is fixed at 1 byte (⑤ §9.1).
pub const FRAME_VERSION: u8 = 1;

/// WS frame command set — the 13 commands from design §17.10, the **only command set**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WsCommand {
    Hello,
    Byef,
    Envelope,
    Chunk,
    Ack,
    Receipt,
    Ping,
    Pong,
    Keepalive,
    StreamSig,
    StreamData,
    RequestChunks,
    Error,
}

impl WsCommand {
    pub const ALL: [WsCommand; 13] = [
        WsCommand::Hello,
        WsCommand::Byef,
        WsCommand::Envelope,
        WsCommand::Chunk,
        WsCommand::Ack,
        WsCommand::Receipt,
        WsCommand::Ping,
        WsCommand::Pong,
        WsCommand::Keepalive,
        WsCommand::StreamSig,
        WsCommand::StreamData,
        WsCommand::RequestChunks,
        WsCommand::Error,
    ];

    /// Wire cmd byte. Values follow the row order of the doc table for easy cross-checking.
    pub const fn to_u8(self) -> u8 {
        match self {
            WsCommand::Hello => 1,
            WsCommand::Byef => 2,
            WsCommand::Envelope => 3,
            WsCommand::Chunk => 4,
            WsCommand::Ack => 5,
            WsCommand::Receipt => 6,
            WsCommand::Ping => 7,
            WsCommand::Pong => 8,
            WsCommand::Keepalive => 9,
            WsCommand::StreamSig => 10,
            WsCommand::StreamData => 11,
            WsCommand::RequestChunks => 12,
            WsCommand::Error => 13,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        WsCommand::ALL.iter().copied().find(|c| c.to_u8() == v)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            WsCommand::Hello => "hello",
            WsCommand::Byef => "byef",
            WsCommand::Envelope => "envelope",
            WsCommand::Chunk => "chunk",
            WsCommand::Ack => "ack",
            WsCommand::Receipt => "receipt",
            WsCommand::Ping => "ping",
            WsCommand::Pong => "pong",
            WsCommand::Keepalive => "keepalive",
            WsCommand::StreamSig => "stream-sig",
            WsCommand::StreamData => "stream-data",
            WsCommand::RequestChunks => "request-chunks",
            WsCommand::Error => "error",
        }
    }

    /// body encoding: `hello/ack/receipt/keepalive/request-chunks/error/byef/ping/pong` are JSON,
    /// `envelope/chunk/stream-sig` are Envelope protobuf, `stream-data` is raw bytes (⑤ §9.1).
    pub const fn body_is_json(self) -> bool {
        matches!(
            self,
            WsCommand::Hello
                | WsCommand::Byef
                | WsCommand::Ack
                | WsCommand::Receipt
                | WsCommand::Ping
                | WsCommand::Pong
                | WsCommand::Keepalive
                | WsCommand::RequestChunks
                | WsCommand::Error
        )
    }

    /// Protected set under backpressure drops (⑤ §9.5): `stream-sig`/`ack`/`receipt`/`byef` are kept.
    pub const fn is_protected_under_backpressure(self) -> bool {
        matches!(
            self,
            WsCommand::StreamSig | WsCommand::Ack | WsCommand::Receipt | WsCommand::Byef
        )
    }
}

/// Error codes (design §17.10 + the 3 REST extension codes from ⑤ §0.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    AuthFail,
    Protocol,
    Quota,
    NotFound,
    Format,
    Plugin,
    Rate,
    Internal,
    /// REST extension code, **must not** appear in WS frames (§17.10).
    Forbidden,
    /// REST extension code, **must not** appear in WS frames (§17.10).
    Conflict,
    /// REST extension code, **must not** appear in WS frames (§17.10).
    TooLarge,
}

impl ErrorCode {
    pub const WS_SET: [ErrorCode; 8] = [
        ErrorCode::AuthFail,
        ErrorCode::Protocol,
        ErrorCode::Quota,
        ErrorCode::NotFound,
        ErrorCode::Format,
        ErrorCode::Plugin,
        ErrorCode::Rate,
        ErrorCode::Internal,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::AuthFail => "AUTH_FAIL",
            ErrorCode::Protocol => "PROTOCOL",
            ErrorCode::Quota => "QUOTA",
            ErrorCode::NotFound => "NOT_FOUND",
            ErrorCode::Format => "FORMAT",
            ErrorCode::Plugin => "PLUGIN",
            ErrorCode::Rate => "RATE",
            ErrorCode::Internal => "INTERNAL",
            ErrorCode::Forbidden => "FORBIDDEN",
            ErrorCode::Conflict => "CONFLICT",
            ErrorCode::TooLarge => "TOO_LARGE",
        }
    }

    /// Unknown codes collapse to `INTERNAL` semantics (§17.10: clients must tolerate unknown values).
    pub fn normalize(raw: &str) -> Self {
        match raw {
            "AUTH_FAIL" => ErrorCode::AuthFail,
            "PROTOCOL" => ErrorCode::Protocol,
            "QUOTA" => ErrorCode::Quota,
            "NOT_FOUND" => ErrorCode::NotFound,
            "FORMAT" => ErrorCode::Format,
            "PLUGIN" => ErrorCode::Plugin,
            "RATE" => ErrorCode::Rate,
            "FORBIDDEN" => ErrorCode::Forbidden,
            "CONFLICT" => ErrorCode::Conflict,
            "TOO_LARGE" => ErrorCode::TooLarge,
            _ => ErrorCode::Internal,
        }
    }

    /// HTTP status code mapping (⑤ §0.6).
    pub const fn http_status(self) -> u16 {
        match self {
            ErrorCode::Protocol => 400,
            ErrorCode::AuthFail => 401,
            ErrorCode::Forbidden => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::Conflict => 409,
            ErrorCode::TooLarge => 413,
            ErrorCode::Format => 422,
            ErrorCode::Rate | ErrorCode::Quota => 429,
            ErrorCode::Plugin | ErrorCode::Internal => 500,
        }
    }

    /// Whether a WS frame may carry this code (§17.10: the 3 extension codes are REST-only).
    pub const fn allowed_on_ws(self) -> bool {
        matches!(
            self,
            ErrorCode::AuthFail
                | ErrorCode::Protocol
                | ErrorCode::Quota
                | ErrorCode::NotFound
                | ErrorCode::Format
                | ErrorCode::Plugin
                | ErrorCode::Rate
                | ErrorCode::Internal
        )
    }
}

/// The 8 delivery states (design §17.3), used by `delivery_log.state` / `receipt` / console filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryState {
    Sent,
    Persisted,
    Routed,
    Delivered,
    Acked,
    Dropped,
    Expired,
    Dlq,
}

impl DeliveryState {
    pub const ALL: [DeliveryState; 8] = [
        DeliveryState::Sent,
        DeliveryState::Persisted,
        DeliveryState::Routed,
        DeliveryState::Delivered,
        DeliveryState::Acked,
        DeliveryState::Dropped,
        DeliveryState::Expired,
        DeliveryState::Dlq,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            DeliveryState::Sent => "sent",
            DeliveryState::Persisted => "persisted",
            DeliveryState::Routed => "routed",
            DeliveryState::Delivered => "delivered",
            DeliveryState::Acked => "acked",
            DeliveryState::Dropped => "dropped",
            DeliveryState::Expired => "expired",
            DeliveryState::Dlq => "dlq",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        DeliveryState::ALL.into_iter().find(|s| s.as_str() == raw)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            DeliveryState::Dropped | DeliveryState::Expired | DeliveryState::Dlq
        )
    }

    /// `acked` = at least one target device has acked (§17.4-3); this decides the receipt sent to the sender.
    pub const fn sender_facing(self) -> bool {
        matches!(
            self,
            DeliveryState::Sent
                | DeliveryState::Persisted
                | DeliveryState::Routed
                | DeliveryState::Delivered
                | DeliveryState::Acked
                | DeliveryState::Dropped
                | DeliveryState::Expired
                | DeliveryState::Dlq
        )
    }
}

/// Value domain of `messages.status`: the subset of the §17.3 eight states that applies to a **message row**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageStatus {
    Persisted,
    Expired,
    Dropped,
}

impl MessageStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            MessageStatus::Persisted => "persisted",
            MessageStatus::Expired => "expired",
            MessageStatus::Dropped => "dropped",
        }
    }
}

/// Deployment mode (§17.7): only two names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    ZeroKnowledge,
    Inspectable,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::ZeroKnowledge
    }
}

// ---------------------------------------------------------------------------
// Threshold matrix (§17.6 / §17.8 / §17.13) — no second copy of these numbers may exist in the implementation
// ---------------------------------------------------------------------------

/// ≤ 1MB: inline in a single envelope (§17.6).
pub const INLINE_MAX_BYTES: usize = 1024 * 1024;
/// 1MB < size ≤ 32MB: WS chunking (§17.6, D1 default 32MB).
pub const CHUNK_THRESHOLD_MAX_BYTES: u64 = 32 * 1024 * 1024;
/// Network chunk part size 256KB (§17.6).
pub const CHUNK_PART_BYTES: usize = 256 * 1024;
/// MinIO multipart part size 8MB (§17.6).
pub const UPLOAD_PART_BYTES: u64 = 8 * 1024 * 1024;
/// Per-frame limit: `envelope`/`chunk` ≤ 512KB (§17.13).
pub const FRAME_MAX_BYTES: usize = 512 * 1024;
/// `stream-data` ≤ 64KB (§17.13).
pub const STREAM_DATA_MAX_BYTES: usize = 64 * 1024;
/// 256 frames queued per connection (§17.13).
pub const BACKPRESSURE_QUEUE_FRAMES: usize = 256;
/// Dedup hot layer TTL defaults to 24h (§17.5 / §18 D5).
pub const DEDUP_TTL_SECS: u64 = 86_400;
/// Route key TTL 90s, renewed every 25s (§17.8).
pub const CONN_TTL_SECS: u64 = 90;
/// Application-layer keepalive interval 25s (§17.8).
pub const KEEPALIVE_INTERVAL_SECS: u64 = 25;
/// WS ping interval 30s (§17.8).
pub const WS_PING_INTERVAL_SECS: u64 = 30;
/// Client declared dead after 45s with no frame (§17.8).
pub const CLIENT_DEAD_SECS: u64 = 45;
/// Server declared dead after 90s with no frame (§17.8).
pub const SERVER_DEAD_SECS: u64 = 90;
/// Node heartbeat `lattice:node:{id}` EX 10s (§17.8).
pub const NODE_HEARTBEAT_TTL_SECS: u64 = 10;
/// seq watermark flushed to PG every 30s (§6.4).
pub const SEQ_WATERMARK_FLUSH_SECS: u64 = 30;
/// Per-user redelivery rate limit 200 msg/s (§17.13).
pub const PENDING_RATE_LIMIT_PER_SEC: u32 = 200;
/// 10 connections per user, 100 connections per IP (§17.13).
pub const MAX_CONNS_PER_USER: usize = 10;
/// 100 connections per IP (§17.13).
pub const MAX_CONNS_PER_IP: usize = 100;
/// Admin console SSE heartbeat 30s, 100 concurrent per cluster (§17.13).
pub const SSE_PING_INTERVAL_SECS: u64 = 30;
/// Admin console SSE concurrency cap (§17.13).
pub const SSE_MAX_CONNECTIONS: usize = 100;
/// Presigned URL TTL 900s, single use (§17.13).
pub const PRESIGN_TTL_SECS: u64 = 900;

/// Default user quota values (§17.13 "user quota and rate limiting").
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Quota {
    pub msg_per_s: u32,
    pub bytes_per_s: u64,
    pub topics: u32,
    pub storage_bytes: u64,
}

impl Default for Quota {
    fn default() -> Self {
        Quota {
            msg_per_s: 100,
            bytes_per_s: 26_214_400,
            topics: 100,
            storage_bytes: 10 * 1024 * 1024 * 1024,
        }
    }
}

/// Login rate limit (§17.13): 10/min per IP, 5/min per account.
pub const LOGIN_RATE_PER_IP: u32 = 10;
/// Login rate limit (§17.13): 5/min per account.
pub const LOGIN_RATE_PER_ACCOUNT: u32 = 5;
/// Retransmit backoff sequence and cap (§6.5).
pub const RETRANSMIT_BACKOFF_SECS: [u64; 5] = [1, 2, 4, 8, 16];
/// Retransmit attempt cap (§6.5).
pub const RETRANSMIT_MAX_ATTEMPTS: u32 = 5;
/// Wait 10s for a single ACK (§6.5).
pub const ACK_TIMEOUT_SECS: u64 = 10;
/// Chunk reassembly timeout 24h (§6.2).
pub const CHUNK_TIMEOUT_SECS: u64 = 86_400;
/// Offline redelivery scan interval (⑥ §6.4: 5min).
pub const RECONCILE_INTERVAL_SECS: u64 = 300;
/// Delivery audit online retention 90 days (⑥ §2.6).
pub const DELIVERY_LOG_RETENTION_DAYS: i64 = 90;
/// Message online retention defaults to 12 months (§18 D7).
pub const MESSAGES_ONLINE_RETENTION_MONTHS: i32 = 12;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_roundtrip() {
        for c in WsCommand::ALL {
            assert_eq!(WsCommand::from_u8(c.to_u8()), Some(c));
            assert!(!c.as_str().is_empty());
        }
        // Unknown cmd → None (the server replies PROTOCOL and ignores the frame, ⑤ §9.6)
        assert_eq!(WsCommand::from_u8(99), None);
    }

    #[test]
    fn rest_extension_codes_not_on_ws() {
        assert!(!ErrorCode::Forbidden.allowed_on_ws());
        assert!(!ErrorCode::Conflict.allowed_on_ws());
        assert!(!ErrorCode::TooLarge.allowed_on_ws());
        assert_eq!(ErrorCode::normalize("SOMETHING_NEW"), ErrorCode::Internal);
    }

    #[test]
    fn status_mapping_matches_doc() {
        assert_eq!(ErrorCode::NotFound.http_status(), 404);
        assert_eq!(ErrorCode::Rate.http_status(), 429);
        assert_eq!(ErrorCode::Format.http_status(), 422);
        assert_eq!(ErrorCode::TooLarge.http_status(), 413);
    }

    #[test]
    fn quota_defaults_match_17_13() {
        let q = Quota::default();
        assert_eq!(q.msg_per_s, 100);
        assert_eq!(q.bytes_per_s, 25 * 1024 * 1024);
        assert_eq!(q.topics, 100);
        assert_eq!(q.storage_bytes, 10 * 1024 * 1024 * 1024);
    }
}
