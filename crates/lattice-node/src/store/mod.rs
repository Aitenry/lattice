//! Storage layer (② §1 `store/`): PG metadata, Redis routing and queues, MinIO large objects, bus, local WAL.
//!
//! Division of labor and lifecycle authority: ⑥ §1 (storage overview), §2.6 (retention matrix), §3.4 (Redis rebuild sources).

pub mod bus;
pub mod nats;
pub mod pg;
pub mod redis;
pub mod s3;
pub mod wal;

pub use bus::{
    build, Bus, BusKind, BusSub, OnlineHandler, RedisBus, RouteEnvelope, RouteHandler,
};
pub use nats::NatsBus;
pub use pg::Pool;
pub use redis::Redis;
pub use s3::S3;
pub use wal::{Wal, WalRecord};
