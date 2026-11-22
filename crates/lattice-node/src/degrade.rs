//! Degradation policy aggregation (② §4.8 degradation matrix / `degrade.rs`).
//!
//! Functions here only evaluate and record metrics; actual behavior lives at each call site (routing, dedup, WAL, bus).

use std::sync::atomic::{AtomicU64, Ordering};

use crate::state::AppState;

/// Dependency health snapshot (used by `/v1/ready` and alerts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepHealth {
    Ok,
    Degraded,
    Down,
}

impl DepHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            DepHealth::Ok => "ok",
            DepHealth::Degraded => "degraded",
            DepHealth::Down => "down",
        }
    }
}

/// Redis flapping detection: command timeout/error rate > 5% (10s window, ② §4.8).
#[derive(Default)]
pub struct ErrorRateWindow {
    total: AtomicU64,
    failed: AtomicU64,
}

impl ErrorRateWindow {
    pub fn record(&self, ok: bool) {
        self.total.fetch_add(1, Ordering::Relaxed);
        if !ok {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn ratio(&self) -> f64 {
        let total = self.total.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        self.failed.load(Ordering::Relaxed) as f64 / total as f64
    }

    pub fn is_degraded(&self) -> bool {
        self.ratio() > 0.05
    }

    pub fn reset(&self) {
        self.total.store(0, Ordering::Relaxed);
        self.failed.store(0, Ordering::Relaxed);
    }
}

/// Whether WAL writes are allowed when PG is unwritable (② §4.8: buffer small messages, replay in order after recovery).
pub fn wal_enabled(st: &AppState) -> bool {
    st.cfg.wal.enabled && !st.cfg.wal.effective_dir(&st.cfg.degrade).trim().is_empty()
}

/// Bus degradation path: NATS unavailable → Redis PubSub → broadcast paused (② §4.8).
///
/// Must read the **runtime bus instance**, not `cfg.bus.kind`: config may say `nats`, but a failed connection at
/// startup silently degrades to RedisBus; reporting `nats` in `ready` would then be a false state (a conventions issue found during PL-17 reconciliation).
pub fn bus_mode(st: &AppState) -> &'static str {
    st.bus.kind().as_str()
}

/// Degradation summary for the current node (shown on the console Settings page).
pub fn summary(st: &AppState) -> serde_json::Value {
    serde_json::json!({
        "bus": bus_mode(st),
        "bus_healthy": st.bus.healthy(),
        "wal_enabled": wal_enabled(st),
        "redis_stale_cache": st.cfg.degrade.redis_stale_cache,
        "mode": match st.mode() {
            lattice_core::Mode::ZeroKnowledge => "zero-knowledge",
            lattice_core::Mode::Inspectable => "inspectable",
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_rate_threshold() {
        let w = ErrorRateWindow::default();
        for _ in 0..100 {
            w.record(true);
        }
        assert!(!w.is_degraded());
        for _ in 0..6 {
            w.record(false);
        }
        assert!(w.is_degraded(), "6/106 > 5%");
        w.reset();
        assert_eq!(w.ratio(), 0.0);
        assert!(!w.is_degraded());
    }
}
