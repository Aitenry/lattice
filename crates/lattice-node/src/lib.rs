//! Lattice platform node (the crate layout from doc ② §1).
//!
//! Module layout maps one-to-one to the docs:
//! `config` (§2.3) / `node` (lifecycle §7.2) / `transport` (§3) / `auth` (§6) /
//! `pipeline` (§2.2, §4.3–§4.6) / `routing` (§4.1–§4.2) / `store` (§5) / `admin` (§9 backend) /
//! `observe` (§8) / `jobs` (§5 scheduled jobs) / `degrade` (§4.8).

pub mod admin;
pub mod auth;
pub mod config;
pub mod degrade;
pub mod error;
pub mod hub;
pub mod jobs;
pub mod live;
pub mod maintenance;
pub mod node;
pub mod observe;
pub mod pipeline;
pub mod plugins;
pub mod routing;
pub mod state;
pub mod store;
pub mod transfer;
pub mod transport;

pub use error::{LatticeError, Result};
pub use state::AppState;
