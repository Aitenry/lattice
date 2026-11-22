//! Unified message envelope (design doc §5). Fields and field numbers are the proto definition, kept in sync with `proto/lattice/v1/envelope.proto`.

use std::collections::HashMap;

use prost::Message;
use serde::{Deserialize, Serialize};

/// Envelope (design §5). `payload` is opaque in zero-knowledge mode (§17.7).
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct Envelope {
    /// ULID; for a chunk envelope, `<id>.c<i>` (§17.2)
    #[prost(string, tag = "1")]
    pub id: String,
    /// `text|json|xml|proto|msgpack|binary|file|image|media|stream|custom:<ns>` (§5)
    #[prost(string, tag = "2")]
    pub r#type: String,
    #[prost(string, tag = "3")]
    pub content_type: String,
    /// `utf8|base64|raw`
    #[prost(string, tag = "4")]
    pub encoding: String,
    #[prost(message, optional, tag = "5")]
    pub compression: Option<Compression>,
    #[prost(message, optional, tag = "6")]
    pub encryption: Option<Encryption>,
    #[prost(message, optional, tag = "7")]
    pub chunks: Option<ChunkInfo>,
    #[prost(message, optional, tag = "8")]
    pub route: Option<RouteInfo>,
    /// Business extensions; the server must not depend on their contents (§5: protocol-level fields must be explicit)
    #[prost(map = "string, string", tag = "9")]
    pub metadata: HashMap<String, String>,
    /// Opaque bytes; for a chunked message, the content of one chunk
    #[prost(bytes = "vec", tag = "10")]
    pub payload: Vec<u8>,
    #[prost(uint64, tag = "11")]
    pub created_at: u64,
    /// 0 = never expires (affects the dedup retention window, §17.5)
    #[prost(uint32, tag = "12")]
    pub ttl_seconds: u32,
    /// Written and verified by the server from the authenticated identity; forged values are rejected (§5)
    #[prost(string, tag = "13")]
    pub sender: String,
    /// Session key; `topic:{t}` for broadcast
    #[prost(string, tag = "14")]
    pub conv_id: String,
    /// Monotonic sequence within the session, **assigned by the server**; not assigned for chunk envelopes (§17.2)
    #[prost(uint64, tag = "15")]
    pub seq: u64,
    /// Checksum of the whole logical message (sha256); the head chunk carries it for chunked messages (§17.6)
    #[prost(bytes = "vec", tag = "16")]
    pub checksum_sha256: Vec<u8>,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct Compression {
    #[prost(string, tag = "1")]
    pub algorithm: String,
    #[prost(uint32, tag = "2")]
    pub level: u32,
}

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct Encryption {
    #[prost(string, tag = "1")]
    pub algorithm: String,
    #[prost(bytes = "vec", tag = "2")]
    pub nonce: Vec<u8>,
    #[prost(string, tag = "3")]
    pub key_fp: String,
}

/// Chunk info; `checksum` is the per-chunk xxhash64 (§6.2).
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct ChunkInfo {
    #[prost(uint32, tag = "1")]
    pub total: u32,
    #[prost(uint32, tag = "2")]
    pub index: u32,
    #[prost(uint32, tag = "3")]
    pub size: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub checksum: Vec<u8>,
}

/// Route info (§17.4: deliver to all devices by default, target devices via `to_devices`).
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct RouteInfo {
    #[prost(string, tag = "1")]
    pub to_user: String,
    #[prost(string, tag = "2")]
    pub to_topic: String,
    #[prost(string, repeated, tag = "3")]
    pub cc: Vec<String>,
    #[prost(string, repeated, tag = "4")]
    pub to_devices: Vec<String>,
}

impl Envelope {
    pub fn decode_body(body: &[u8]) -> Result<Self, crate::LatticeError> {
        Envelope::decode(body).map_err(|e| {
            crate::LatticeError::format(format!("envelope protobuf decode failed: {e}"))
                .with_reason("envelope_decode")
        })
    }

    pub fn encode_body(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Whether this is a chunk envelope (§17.2: `chunks.total > 1`).
    pub fn is_chunk(&self) -> bool {
        self.chunks.as_ref().map(|c| c.total > 1).unwrap_or(false)
    }

    /// Payload size, used for threshold matrix decisions (§17.6).
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub fn route(&self) -> &RouteInfo {
        static EMPTY: std::sync::OnceLock<RouteInfo> = std::sync::OnceLock::new();
        self.route
            .as_ref()
            .unwrap_or_else(|| EMPTY.get_or_init(RouteInfo::default))
    }

    pub fn checksum_b64(&self) -> Option<String> {
        if self.checksum_sha256.is_empty() {
            None
        } else {
            Some(format!(
                "b64:{}",
                base64_encode(&self.checksum_sha256)
            ))
        }
    }
}

pub fn base64_encode(raw: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(raw)
}

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let s = s.strip_prefix("b64:").unwrap_or(s);
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// Whole-message sha256 (how `checksum_sha256` is computed).
pub fn sha256_hex(raw: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex_encode(&Sha256::digest(raw))
}

fn hex_encode(raw: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(raw.len() * 2);
    for b in raw {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Per-chunk xxhash64 (§6.2: `ChunkInfo.checksum`).
pub fn xxhash64(raw: &[u8]) -> [u8; 8] {
    xxhash_rust::xxh64::xxh64(raw, 0).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_protobuf_roundtrip() {
        let mut env = Envelope {
            id: "01J0000000000000000000000A".into(),
            r#type: "text".into(),
            content_type: "text/plain".into(),
            encoding: "utf8".into(),
            payload: b"hello".to_vec(),
            conv_id: "01H0000000000000000000000B".into(),
            sender: "01G0000000000000000000000C".into(),
            ttl_seconds: 0,
            ..Default::default()
        };
        env.metadata.insert("k".into(), "v".into());
        let bytes = env.encode_body();
        let back = Envelope::decode_body(&bytes).expect("decode");
        assert_eq!(back.id, env.id);
        assert_eq!(back.payload, env.payload);
        assert_eq!(back.metadata.get("k").map(String::as_str), Some("v"));
        assert!(!back.is_chunk());
    }

    #[test]
    fn chunk_envelope_detected() {
        let env = Envelope {
            id: "01J0000000000000000000000A.c3".into(),
            chunks: Some(ChunkInfo { total: 4, index: 3, size: 1024, checksum: vec![1, 2] }),
            ..Default::default()
        };
        assert!(env.is_chunk());
    }

    #[test]
    fn checksum_and_base64() {
        let d = sha256_hex(b"abc");
        assert_eq!(
            d,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let b = base64_encode(b"\x00\x01\x02");
        assert_eq!(base64_decode(&b).unwrap(), b"\x00\x01\x02");
        assert_eq!(base64_decode("b64:AAEC").unwrap(), b"\x00\x01\x02");
    }
}
