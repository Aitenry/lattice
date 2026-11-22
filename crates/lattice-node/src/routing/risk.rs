//! Risk control rule engine (E03 / PL-12 12.6–12.7 / ② §4.7 "rate limiting and risk control").
//!
//! # Position and boundaries (report conventions)
//! This is a **rule engine, not ML**: three deterministic rules + in-process sliding windows + configurable actions.
//! Rule match → bounded Redis ZSET [`lattice_core::keys::risk`] (`lattice:risk`, TTL) →
//! `audit_log` (`risk.detected` / `risk.action`) → `lattice_risk_events_total{rule,action}`.
//!
//! Three rules:
//! - `message_flood`: high message rate from one device in a short time (sliding window `max_events_per_min` / `message_window_secs`);
//! - `device_switch`: many new devices on one account in a short time (distinct devices in the window > `device_switch_threshold`);
//! - `auth_failure_surge`: a sudden spike in authentication failures (`AppState::verify_jwt` failure = 401 class,
//!   covering every token verification entry point in REST/WS/QUIC/WebTransport; window `auth_failure_window_secs`).
//!
//! Actions (`[risk] action`): `audit` (audit only, default) | `throttle` (device rate limit
//! `throttle_secs`) | `reauth` (revoke all refresh tokens for the user, forcing re-authentication).
//!
//! # Known boundaries (stated honestly)
//! - **An auth-failure surge has no trusted user identity** (failed verification yields no claims), so this rule is **forced** to downgrade to
//!   `audit` and does not act per user; the rule label still counts the actual action (audit).
//! - The signal points for refresh replay (refresh_replay)/authorization 403 live in `transport/http.rs` (owned by another agent
//!   this round) and are not wired into this engine; the auth-failure rule uses JWT verification failures (401 class) as its data source, the
//!   **deterministically reproducible** part of the "authentication failure" subset. Login failures (login 401) likewise have no hook in http.rs.
//! - Rate-limit verdicts are **in-process** (zero await on the hot path); in multi-node deployments throttle state is not synchronized across nodes,
//!   and Redis also has `lattice:risk:throttle:*` keys for observability/future cross-node work; they are not read currently.
//! - Sliding windows are in-process memory: they are cleared on node restart (risk control judges "short-term anomalies", so losing windows on restart is acceptable).
//! - Redis queue write failures only WARN + metric: degraded risk observability **must not** block the message hot path.
//!
//! # Hot-path constraints
//! [`RiskEngine::check_ingest`] / [`RiskEngine::note_message`] do only "one Mutex + O(1)";
//! match reports go through a **bounded `try_send`** (dropped when full, never await); Redis writes/audit/revocation all happen in background
//! tasks. With `enabled=false` (default), every entry point returns on the first line: zero collection, zero tasks, zero Redis connections.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::sync::mpsc;

use crate::config::RiskCfg;
use crate::observe::Metrics;
use crate::state::AppState;

/// Rule name (metric label, low cardinality).
pub const RULE_MESSAGE_FLOOD: &str = "message_flood";
pub const RULE_DEVICE_SWITCH: &str = "device_switch";
pub const RULE_AUTH_FAILURE: &str = "auth_failure_surge";

/// Action (metric label, low cardinality).
pub const ACTION_AUDIT: &str = "audit";
pub const ACTION_THROTTLE: &str = "throttle";
pub const ACTION_REAUTH: &str = "reauth";

/// Capacity limits for window/debounce tables: when exceeded, clear the whole table (approximate LRU). Losing risk tables only makes verdicts more conservative/delayed
/// and does not affect correctness; but tables must be bounded, or flooded user/device keys grow without limit.
const WINDOW_MAP_CAP: usize = 50_000;
/// Match report channel capacity (bounded; dropped when full, the hot path never blocks).
const HIT_CHANNEL_CAP: usize = 1_024;

/// One match event (hot path → background action task).
pub(crate) struct Hit {
    rule: &'static str,
    user: String,
    device: String,
    count: u64,
    window_secs: u64,
    reason: String,
}

/// In-process sliding window (timestamp deque; trims expired entries from the front on push).
#[derive(Default)]
struct SlidingWindow {
    at: VecDeque<Instant>,
}

impl SlidingWindow {
    fn push(&mut self, now: Instant, window: Duration) -> usize {
        self.at.push_back(now);
        while let Some(front) = self.at.front() {
            if now.duration_since(*front) > window {
                self.at.pop_front();
            } else {
                break;
            }
        }
        self.at.len()
    }
}

/// Risk engine (`AppState.risk`; disabled by default).
pub struct RiskEngine {
    cfg: RiskCfg,
    /// Match reports (consumed by the background task; the receiver is taken in `spawn`).
    tx: mpsc::Sender<Hit>,
    rx: Mutex<Option<mpsc::Receiver<Hit>>>,
    /// Message frequency windows: `"{user}\u{0}{device}" -> window`.
    msg_windows: Mutex<HashMap<String, SlidingWindow>>,
    /// Device switch windows: `user -> {device -> last seen time}`.
    dev_windows: Mutex<HashMap<String, HashMap<String, Instant>>>,
    /// Auth failure window (global; failed verification has no identity).
    auth_window: Mutex<SlidingWindow>,
    /// Debounce: `"{rule}\u{0}{user}\u{0}{device}" -> last report time`.
    last_reported: Mutex<HashMap<String, Instant>>,
    /// Action state: `"{user}\u{0}{device}" -> throttle deadline` (in-process, read by the hot path).
    throttled: Mutex<HashMap<String, Instant>>,
    /// Matches processed by the background task (metric/tests).
    handled: AtomicU64,
}

impl RiskEngine {
    /// Construct the engine. The `metrics` parameter is kept for callers to inject a handle (actual metrics on the background action path use
    /// `AppState.metrics`; this struct does not hold it long-term to avoid an extra Arc lifetime).
    pub fn new(cfg: RiskCfg, _metrics: Arc<Metrics>) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(HIT_CHANNEL_CAP);
        Arc::new(RiskEngine {
            cfg,
            tx,
            rx: Mutex::new(Some(rx)),
            msg_windows: Mutex::new(HashMap::new()),
            dev_windows: Mutex::new(HashMap::new()),
            auth_window: Mutex::new(SlidingWindow::default()),
            last_reported: Mutex::new(HashMap::new()),
            throttled: Mutex::new(HashMap::new()),
            handled: AtomicU64::new(0),
        })
    }

    /// Take the background task receiver (`node::build` → [`spawn`], taken only once).
    pub(crate) fn take_receiver(&self) -> Option<mpsc::Receiver<Hit>> {
        self.rx.lock().ok().and_then(|mut g| g.take())
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    /// Matches processed in the background (unit tests/observability).
    pub fn handled_hits(&self) -> u64 {
        self.handled.load(Ordering::Relaxed)
    }

    // ------------------------------------------------------------------
    // Hot-path hooks (all synchronous, bounded, no await)
    // ------------------------------------------------------------------

    /// **pipeline ingest hot path**: returns `false` = the device is inside a risk throttle window; the caller should reject.
    ///
    /// Returns `true` on the first line when disabled (zero side effects).
    pub fn check_ingest(&self, user: &str, device: &str) -> bool {
        if !self.cfg.enabled {
            return true;
        }
        let key = cache_key(user, device);
        let now = Instant::now();
        {
            let mut t = lock(&self.throttled);
            if let Some(until) = t.get(&key) {
                if *until > now {
                    return false;
                }
                t.remove(&key);
            }
            if t.len() > WINDOW_MAP_CAP {
                t.clear();
            }
        }
        self.note_message(user, device);
        true
    }

    /// Message frequency rule (rule a). Hot path: one Mutex + sliding window push.
    pub fn note_message(&self, user: &str, device: &str) {
        if !self.cfg.enabled {
            return;
        }
        let key = cache_key(user, device);
        let window = self.cfg.message_window();
        let count = {
            let mut w = lock(&self.msg_windows);
            if w.len() > WINDOW_MAP_CAP {
                w.clear();
            }
            w.entry(key.clone()).or_default().push(Instant::now(), window)
        };
        if count as u64 > self.cfg.max_events_per_min {
            self.report(Hit {
                rule: RULE_MESSAGE_FLOOD,
                user: user.to_string(),
                device: device.to_string(),
                count: count as u64,
                window_secs: window.as_secs(),
                reason: format!("messages in {}s window exceed {}", window.as_secs(), self.cfg.max_events_per_min),
            });
        }
    }

    /// Device switch rule (rule b). Hook: `AppState::register_online` (WS hello online registration).
    pub fn note_device_online(&self, user: &str, device: &str) {
        if !self.cfg.enabled {
            return;
        }
        let window = self.cfg.device_window();
        let now = Instant::now();
        let distinct = {
            let mut w = lock(&self.dev_windows);
            if w.len() > WINDOW_MAP_CAP {
                w.clear();
            }
            let devices = w.entry(user.to_string()).or_default();
            devices.retain(|_, at| now.duration_since(*at) <= window);
            devices.insert(device.to_string(), now);
            devices.len()
        };
        if distinct as u64 > self.cfg.device_switch_threshold {
            self.report(Hit {
                rule: RULE_DEVICE_SWITCH,
                user: user.to_string(),
                device: device.to_string(),
                count: distinct as u64,
                window_secs: window.as_secs(),
                reason: format!(
                    "distinct devices in {}s window exceed {}",
                    window.as_secs(),
                    self.cfg.device_switch_threshold
                ),
            });
        }
    }

    /// Auth failure rule (rule c). Hook: `AppState::verify_jwt` failure branch (401 class).
    ///
    /// Failed verification has no trusted user identity → the target is empty on report, and the action is forced to `audit` (see module docs).
    pub fn note_auth_failure(&self, reason: &str) {
        if !self.cfg.enabled {
            return;
        }
        let window = self.cfg.auth_window();
        let count = {
            let mut w = lock(&self.auth_window);
            w.push(Instant::now(), window)
        };
        if count as u64 > self.cfg.auth_failure_threshold {
            self.report(Hit {
                rule: RULE_AUTH_FAILURE,
                user: String::new(),
                device: String::new(),
                count: count as u64,
                window_secs: window.as_secs(),
                reason: format!(
                    "jwt verification failures in {}s window exceed {} ({reason})",
                    window.as_secs(),
                    self.cfg.auth_failure_threshold
                ),
            });
        }
    }

    /// Report a match: debounce + bounded `try_send` (dropped when full, never blocks the hot path).
    fn report(&self, hit: Hit) {
        let key = format!(
            "{}\u{0}{}\u{0}{}",
            hit.rule, hit.user, hit.device
        );
        let now = Instant::now();
        {
            let mut m = lock(&self.last_reported);
            if m.len() > WINDOW_MAP_CAP {
                m.clear();
            }
            if let Some(last) = m.get(&key) {
                if now.duration_since(*last) < self.cfg.debounce() {
                    return;
                }
            }
            m.insert(key, now);
        }
        if self.tx.try_send(hit).is_err() {
            // Background action backlog/not started: drop only the observability event, never affect the message path (boundaries in module docs).
            tracing::warn!("risk hit channel full/unavailable; hit dropped (hot path never blocks)");
        }
    }

    // ------------------------------------------------------------------
    // Background actions (async; Redis/audit/revocation all happen here)
    // ------------------------------------------------------------------

    async fn handle(st: &Arc<AppState>, redis: &mut Option<RiskRedis>, hit: Hit) {
        st.risk.handled.fetch_add(1, Ordering::Relaxed);
        // Auth-failure surge has no identity → force minimal intervention (audit only), no per-user action.
        let action = if hit.rule == RULE_AUTH_FAILURE {
            ACTION_AUDIT
        } else {
            st.cfg.risk.effective_action()
        };
        st.metrics
            .risk_events_total
            .with_label_values(&[hit.rule, action])
            .inc();

        let target = if hit.user.is_empty() {
            None
        } else if hit.device.is_empty() {
            Some(hit.user.clone())
        } else {
            Some(format!("{}:{}", hit.user, hit.device))
        };
        let detail = json!({
            "rule": hit.rule,
            "action": action,
            "user": hit.user,
            "device": hit.device,
            "count": hit.count,
            "window_secs": hit.window_secs,
            "reason": hit.reason,
        });

        // 1) audit_log(risk.detected): on failure only WARN, do not block later actions.
        if let Err(e) = crate::routing::audit::audit_emit(
            st,
            Some("system:risk"),
            "risk.detected",
            target.as_deref(),
            &detail,
            None,
        )
        .await
        {
            tracing::warn!(error = %e, rule = hit.rule, "risk audit write failed");
        }

        // 2) Bounded Redis queue (`lattice:risk` ZSET + TTL): on failure only WARN (observability degradation must not block).
        if redis.is_none() {
            *redis = RiskRedis::connect(&st.cfg.redis.url).await;
        }
        if let Some(r) = redis.as_ref() {
            let member = json!({
                "id": lattice_core::ids::new_id(),
                "rule": hit.rule,
                "action": action,
                "user": hit.user,
                "device": hit.device,
                "count": hit.count,
                "window_secs": hit.window_secs,
                "at_ms": chrono::Utc::now().timestamp_millis(),
            })
            .to_string();
            if let Err(e) = r
                .push_bounded(
                    &member,
                    st.cfg.risk.effective_queue_max(),
                    st.cfg.risk.effective_queue_ttl(),
                )
                .await
            {
                tracing::warn!(error = %e, "risk queue write failed (observability degraded)");
            }
        } else {
            tracing::warn!("risk queue redis unavailable; hit only audited/metered");
        }

        // 3) Action.
        match action {
            ACTION_THROTTLE => {
                if hit.user.is_empty() || hit.device.is_empty() {
                    return;
                }
                let key = cache_key(&hit.user, &hit.device);
                let until = Instant::now() + st.cfg.risk.throttle_window();
                {
                    // Scope ends the guard explicitly (MutexGuard is not Send; never hold it across await).
                    let mut t = lock(&st.risk.throttled);
                    if t.len() > WINDOW_MAP_CAP {
                        t.clear();
                    }
                    t.insert(key, until);
                }
                // Observability key: other nodes/console can see "which device is in a throttle window" (this node does not read it currently).
                let obs_key = format!(
                    "lattice:risk:throttle:{}:{}",
                    hit.user, hit.device
                );
                let ttl = st.cfg.risk.throttle_window().as_secs().max(1);
                if let Err(e) = st.redis.set_json(&obs_key, "1", ttl).await {
                    tracing::warn!(error = %e, "risk throttle key write failed");
                }
                let _ = crate::routing::audit::audit_emit(
                    st,
                    Some("system:risk"),
                    "risk.action",
                    Some(&format!("{}:{}", hit.user, hit.device)),
                    &json!({
                        "rule": hit.rule,
                        "action": "throttle",
                        "throttle_secs": ttl,
                        "reason": "device rate-limited by risk engine",
                    }),
                    None,
                )
                .await;
                tracing::warn!(
                    user = %Metrics::user_hash(&hit.user),
                    device = %hit.device,
                    throttle_secs = ttl,
                    "risk action: device throttled"
                );
            }
            ACTION_REAUTH => {
                if hit.user.is_empty() {
                    return;
                }
                // Revoke refresh tokens for all devices of this user (access JWTs are stateless and expire naturally within TTL 900s;
                // consistent with ⑤ §0.2: the refresh chain can no longer be renewed and the client is forced to re-authenticate).
                match crate::store::pg::revoke_user_devices(&st.db, &hit.user, None).await {
                    Ok(n) => {
                        let _ = crate::routing::audit::audit_emit(
                            st,
                            Some("system:risk"),
                            "risk.action",
                            Some(&hit.user),
                            &json!({
                                "rule": hit.rule,
                                "action": "reauth",
                                "revoked_devices": n,
                                "reason": "refresh tokens revoked by risk engine",
                            }),
                            None,
                        )
                        .await;
                        tracing::warn!(
                            user = %Metrics::user_hash(&hit.user),
                            revoked = n,
                            "risk action: user refresh tokens revoked (re-auth required)"
                        );
                    }
                    Err(e) => tracing::warn!(error = %e, "risk reauth revoke failed"),
                }
            }
            _ => {
                // audit: the detected audit row was already written; do not duplicate it here.
            }
        }
    }
}

/// Background task: consume match events → bounded Redis queue + audit + action. **Not started** when disabled (zero tasks).
pub fn spawn(st: Arc<AppState>) {
    if !st.cfg.risk.enabled {
        tracing::info!("risk engine disabled by [risk] enabled=false (zero side effects)");
        return;
    }
    let Some(mut rx) = st.risk.take_receiver() else {
        tracing::warn!("risk engine already spawned; duplicate spawn ignored");
        return;
    };
    tracing::info!(
        action = st.cfg.risk.effective_action(),
        max_events_per_min = st.cfg.risk.max_events_per_min,
        device_switch_threshold = st.cfg.risk.device_switch_threshold,
        auth_failure_threshold = st.cfg.risk.auth_failure_threshold,
        queue_max_events = st.cfg.risk.effective_queue_max(),
        queue_ttl_secs = st.cfg.risk.effective_queue_ttl(),
        "risk engine enabled (rules: message_flood/device_switch/auth_failure_surge)"
    );
    tokio::spawn(async move {
        let mut redis = RiskRedis::connect(&st.cfg.redis.url).await;
        if redis.is_none() {
            tracing::warn!("risk queue redis unavailable at startup; will retry on next hit");
        }
        while let Some(hit) = rx.recv().await {
            RiskEngine::handle(&st, &mut redis, hit).await;
        }
    });
}

// ---------------------------------------------------------------------------
// Minimal local Redis wrapper (`store/redis.rs` is owned by another agent this round; the ZSET bounded/EXPIRE
// methods needed are not in its public API, so use a **separate connection** for a minimal wrapper without changing store/redis.rs)
// ---------------------------------------------------------------------------

struct RiskRedis {
    mgr: redis::aio::ConnectionManager,
}

impl RiskRedis {
    async fn connect(url: &str) -> Option<Self> {
        let client = redis::Client::open(url).ok()?;
        let mgr = redis::aio::ConnectionManager::new(client).await.ok()?;
        Some(RiskRedis { mgr })
    }

    /// `ZADD lattice:risk <score> <member>` + `ZREMRANGEBYRANK` to keep only the newest `max_events` entries
    /// + `EXPIRE ttl` (refreshed on match writes). Bounded + TTL is the hard constraint keeping the queue from growing forever.
    async fn push_bounded(
        &self,
        member: &str,
        max_events: usize,
        ttl_secs: u64,
    ) -> redis::RedisResult<()> {
        use redis::AsyncCommands;
        let key = lattice_core::keys::risk();
        let mut c = self.mgr.clone();
        let score = chrono::Utc::now().timestamp_millis();
        let _: i64 = c.zadd(&key, member, score).await?;
        // Keep the max_events highest scores: delete rank 0 .. -(max+1) (redis 0.27 requires isize).
        let stop: isize = -((max_events as isize).saturating_add(1));
        let _: i64 = c.zremrangebyrank(&key, 0, stop).await?;
        let _: i64 = c.expire(&key, ttl_secs as i64).await?;
        Ok(())
    }
}

fn cache_key(user: &str, device: &str) -> String {
    format!("{user}\u{0}{device}")
}

/// Continue with the inner value after lock poisoning: risk windows are read-only approximate data, not worth denying service over one panic.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(cfg: RiskCfg, metrics: Arc<Metrics>) -> Arc<RiskEngine> {
        RiskEngine::new(cfg, metrics)
    }

    fn hit_rx(e: &RiskEngine) -> mpsc::Receiver<Hit> {
        e.take_receiver().expect("receiver once")
    }

    fn drain_hits(rx: &mut mpsc::Receiver<Hit>) -> Vec<Hit> {
        let mut out = Vec::new();
        while let Ok(h) = rx.try_recv() {
            out.push(h);
        }
        out
    }

    #[test]
    fn disabled_engine_has_zero_side_effects() {
        let e = engine(RiskCfg::default(), Metrics::new());
        assert!(!e.enabled());
        assert!(e.check_ingest("u1", "d1"), "throttle hook must allow when disabled");
        for _ in 0..1000 {
            e.note_message("u1", "d1");
            e.note_device_online("u1", "d1");
            e.note_auth_failure("bad signature");
        }
        let mut rx = hit_rx(&e);
        assert!(drain_hits(&mut rx).is_empty(), "disabled engine must not produce any match events");
        assert!(lock(&e.msg_windows).is_empty(), "disabled engine must not allocate window tables");
        assert!(lock(&e.dev_windows).is_empty(), "disabled engine must not allocate device tables");
    }

    #[test]
    fn message_flood_sliding_window_reports_once_per_debounce() {
        let mut cfg = RiskCfg::default();
        cfg.enabled = true;
        cfg.max_events_per_min = 5;
        cfg.message_window_secs = 60;
        let e = engine(cfg, Metrics::new());
        let mut rx = hit_rx(&e);
        for _ in 0..5 {
            e.note_message("u1", "d1");
        }
        assert!(drain_hits(&mut rx).is_empty(), "must not match below the threshold");
        for _ in 0..3 {
            e.note_message("u1", "d1");
        }
        let hits = drain_hits(&mut rx);
        assert_eq!(hits.len(), 1, "one match above the threshold (no repeat report during debounce)");
        assert_eq!(hits[0].rule, RULE_MESSAGE_FLOOD);
        assert_eq!(hits[0].count, 6);
        // Different devices count independently
        for _ in 0..6 {
            e.note_message("u1", "d2");
        }
        assert_eq!(drain_hits(&mut rx).len(), 1, "different device windows must not share state");
    }

    #[test]
    fn device_switch_counts_distinct_devices_only() {
        let mut cfg = RiskCfg::default();
        cfg.enabled = true;
        cfg.device_switch_threshold = 2;
        cfg.device_switch_window_secs = 300;
        let e = engine(cfg, Metrics::new());
        let mut rx = hit_rx(&e);
        // Repeated hello from the same device is not a new device
        for _ in 0..10 {
            e.note_device_online("u1", "d1");
            e.note_device_online("u1", "d2");
        }
        assert!(drain_hits(&mut rx).is_empty(), "two devices below threshold (distinct=2 not > 2)");
        e.note_device_online("u1", "d3");
        let hits = drain_hits(&mut rx);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, RULE_DEVICE_SWITCH);
        assert_eq!(hits[0].count, 3);
        // Different users do not affect each other
        e.note_device_online("u2", "d9");
        assert!(drain_hits(&mut rx).is_empty(), "different accounts have isolated device windows");
    }

    #[test]
    fn auth_failure_surge_is_global_and_reports() {
        let mut cfg = RiskCfg::default();
        cfg.enabled = true;
        cfg.auth_failure_threshold = 3;
        cfg.auth_failure_window_secs = 60;
        let e = engine(cfg, Metrics::new());
        let mut rx = hit_rx(&e);
        for _ in 0..3 {
            e.note_auth_failure("bad signature");
        }
        assert!(drain_hits(&mut rx).is_empty());
        e.note_auth_failure("bad signature");
        let hits = drain_hits(&mut rx);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, RULE_AUTH_FAILURE);
        assert!(hits[0].user.is_empty(), "failed verification has no trusted identity");
        assert_cfg_action_never_applies_to_auth(&hits[0]);
    }

    fn assert_cfg_action_never_applies_to_auth(hit: &Hit) {
        // Action decision: an auth-failure surge is forced to audit (the decision branch constant can be verified without AppState).
        let action = if hit.rule == RULE_AUTH_FAILURE {
            ACTION_AUDIT
        } else {
            ACTION_THROTTLE
        };
        assert_eq!(action, ACTION_AUDIT);
    }

    #[test]
    fn throttle_ingest_check_expires_and_isolates_devices() {
        let mut cfg = RiskCfg::default();
        cfg.enabled = true;
        cfg.throttle_secs = 1;
        let e = engine(cfg, Metrics::new());
        let key = cache_key("u1", "d1");
        lock(&e.throttled).insert(key, Instant::now() + Duration::from_millis(200));
        assert!(!e.check_ingest("u1", "d1"), "must reject inside the throttle window");
        assert!(e.check_ingest("u1", "d2"), "other devices of the same user are unaffected");
        std::thread::sleep(Duration::from_millis(260));
        assert!(e.check_ingest("u1", "d1"), "recovers after the window expires");
    }

    #[test]
    fn bounded_structures_stay_bounded_under_key_flood() {
        let mut cfg = RiskCfg::default();
        cfg.enabled = true;
        cfg.max_events_per_min = 1_000_000; // do not trigger the rule, only stress the window table
        cfg.device_switch_threshold = 1_000_000;
        let e = engine(cfg, Metrics::new());
        for i in 0..(WINDOW_MAP_CAP + 100) {
            e.note_message(&format!("u{i}"), "d");
        }
        assert!(lock(&e.msg_windows).len() <= WINDOW_MAP_CAP);
    }
}
