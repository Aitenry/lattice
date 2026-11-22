//! Lattice shared core.
//!
//! This crate codifies the **value conventions and wire format**: every field and value traces back to §17 of the design document,
//! and no constants are defined separately in code (design §17.14: conventions are defined only once).
//!
//! - [`protocol`]: WS command set (§17.10), error codes, delivery states (§17.3), threshold matrix (§17.6/§17.8/§17.13)
//! - [`envelope`]: unified message envelope (§5)
//! - [`frame`]: WS frame format `ver|cmd|len|body` (⑤ §9.1)
//! - [`keys`]: Redis keys and PubSub channels (§8.2, ⑥ §3.1)
//! - [`error`]: error codes ↔ HTTP status codes (⑤ §0.6)
//! - [`ids`]: ULID and chunk id `<id>.c<i>` (§17.2)

pub mod envelope;
pub mod error;
pub mod frame;
pub mod ids;
pub mod keys;
pub mod protocol;

pub use envelope::{ChunkInfo, Compression, Encryption, Envelope, RouteInfo};
pub use error::LatticeError;
pub use frame::{Frame, FrameCodec};
pub use protocol::{DeliveryState, ErrorCode, MessageStatus, Mode, Quota, WsCommand};
