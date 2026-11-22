//! WS frame format (⑤ §9.1):
//!
//! ```text
//! +-----+-----+------------+------------------+
//! | ver | cmd | len (u32 BE) | body            |
//! +-----+-----+------------+------------------+
//! ```
//!
//! Single-frame limit is 512KB (§17.13), and 64KB for `stream-data`.

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::{WsCommand, FRAME_MAX_BYTES, FRAME_VERSION, STREAM_DATA_MAX_BYTES};
use crate::LatticeError;

/// One frame. The encoding of `body` is determined by `cmd` (⑤ §9.1).
#[derive(Debug, Clone)]
pub struct Frame {
    pub ver: u8,
    pub cmd: WsCommand,
    pub body: Bytes,
}

impl Frame {
    pub fn new(cmd: WsCommand, body: impl Into<Bytes>) -> Self {
        Frame { ver: FRAME_VERSION, cmd, body: body.into() }
    }

    pub fn json<T: serde::Serialize>(cmd: WsCommand, value: &T) -> Result<Self, LatticeError> {
        let body = serde_json::to_vec(value)
            .map_err(|e| LatticeError::internal(format!("json encode failed: {e}")))?;
        Ok(Frame::new(cmd, body))
    }

    pub fn error(code: crate::ErrorCode, message: &str, envelope_id: Option<&str>) -> Self {
        let body = serde_json::json!({
            "code": code.as_str(),
            "message": message,
            "envelope_id": envelope_id,
        });
        Frame::new(WsCommand::Error, Bytes::from(body.to_string()))
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(6 + self.body.len());
        buf.put_u8(self.ver);
        buf.put_u8(self.cmd.to_u8());
        buf.put_u32(self.body.len() as u32);
        buf.extend_from_slice(&self.body);
        buf.freeze()
    }

    /// Maximum legal body length for this frame (§17.13).
    pub fn body_limit(cmd: WsCommand) -> usize {
        match cmd {
            WsCommand::StreamData => STREAM_DATA_MAX_BYTES,
            _ => FRAME_MAX_BYTES,
        }
    }
}

/// Frame codec: reads frames from any `AsyncRead` and writes frames to an `AsyncWrite`.
pub struct FrameCodec;

impl FrameCodec {
    /// Read one frame. `Ok(None)` means the peer closed cleanly.
    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Frame>, LatticeError> {
        let mut head = [0u8; 6];
        match reader.read_exact(&mut head).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => {
                return Err(LatticeError::internal(format!("frame read failed: {e}")))
            }
        }
        let ver = head[0];
        let cmd_raw = head[1];
        let len = u32::from_be_bytes([head[2], head[3], head[4], head[5]]) as usize;

        let cmd = match WsCommand::from_u8(cmd_raw) {
            Some(c) => c,
            // Unknown cmd → PROTOCOL and ignore the frame without closing the connection (⑤ §9.6). Return an error here;
            // the ws adapter converts it into an error frame and continues reading the next frame.
            None => {
                return Err(LatticeError::protocol(format!("unknown cmd byte {cmd_raw}")))
            }
        };

        if len > Frame::body_limit(cmd) {
            return Err(LatticeError::format(format!(
                "frame body {len} exceeds limit {} for cmd {}",
                Frame::body_limit(cmd),
                cmd.as_str()
            )));
        }
        let mut body = vec![0u8; len];
        if len > 0 {
            reader
                .read_exact(&mut body)
                .await
                .map_err(|e| LatticeError::internal(format!("frame body read failed: {e}")))?;
        }
        Ok(Some(Frame { ver, cmd, body: Bytes::from(body) }))
    }

    pub async fn write<W: AsyncWrite + Unpin>(
        writer: &mut W,
        frame: &Frame,
    ) -> Result<(), LatticeError> {
        writer
            .write_all(&frame.encode())
            .await
            .map_err(|e| LatticeError::internal(format!("frame write failed: {e}")))?;
        writer
            .flush()
            .await
            .map_err(|e| LatticeError::internal(format!("frame flush failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::FRAME_MAX_BYTES;

    #[tokio::test]
    async fn roundtrip_and_limits() {
        let f = Frame::new(WsCommand::Hello, Bytes::from_static(br#"{"protocol":{"min":1,"max":1}}"#));
        let raw = f.encode();
        assert_eq!(&raw[..2], &[FRAME_VERSION, WsCommand::Hello.to_u8()]);

        let mut reader: &[u8] = &raw;
        let back = FrameCodec::read(&mut reader).await.unwrap().unwrap();
        assert_eq!(back.cmd, WsCommand::Hello);
        assert_eq!(back.body, f.body);
    }

    #[tokio::test]
    async fn oversized_frame_rejected() {
        let len = (FRAME_MAX_BYTES + 1) as u32;
        let mut raw = Vec::new();
        raw.push(FRAME_VERSION);
        raw.push(WsCommand::Envelope.to_u8());
        raw.extend_from_slice(&len.to_be_bytes());
        let mut reader: &[u8] = &raw;
        let err = FrameCodec::read(&mut reader).await.unwrap_err();
        assert_eq!(err.code, crate::ErrorCode::Format);
    }

    #[tokio::test]
    async fn unknown_cmd_is_protocol_error() {
        let mut raw = Vec::new();
        raw.push(FRAME_VERSION);
        raw.push(200);
        raw.extend_from_slice(&0u32.to_be_bytes());
        let mut reader: &[u8] = &raw;
        let err = FrameCodec::read(&mut reader).await.unwrap_err();
        assert_eq!(err.code, crate::ErrorCode::Protocol);
    }

    #[tokio::test]
    async fn eof_is_clean_close() {
        let mut reader: &[u8] = &[];
        assert!(FrameCodec::read(&mut reader).await.unwrap().is_none());
    }
}
