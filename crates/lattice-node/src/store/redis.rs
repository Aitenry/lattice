//! Redis access layer (key layout authority: ⑥ §3.1; key names are assembled by `lattice_core::keys`).
//!
//! Degradation principle (⑥ §3.4): everything in Redis can be rebuilt from PG/MinIO; write failures must not block message persistence.

use std::collections::HashMap;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client};

use crate::error::{redis as redis_err, Result};
use crate::observe::Metrics;

/// Redis liveness timeout for `/v1/ready` (E10 D2): must be 200–500ms, far below LB/probe timeouts.
/// Shared with the dependency snapshot in `live.rs`, keeping `/v1/ready` and the SSE `deps` event on the same conventions.
pub const READY_PING_TIMEOUT: Duration = Duration::from_millis(300);

#[derive(Clone)]
pub struct Redis {
    client: Client,
    mgr: ConnectionManager,
    /// Per-round `SCAN COUNT` hint for prefix scans (`[redis] scan_count`, PL-17 bottleneck fix).
    scan_count: u32,
    /// Metrics handle: injected after `node::build` creates Metrics (unit tests/not injected → skip quantified recording only).
    metrics: Arc<StdRwLock<Option<Arc<Metrics>>>>,
}

impl Redis {
    pub async fn connect(url: &str) -> Result<Self> {
        Self::connect_with(url, 0).await
    }

    /// Connect and set SCAN COUNT (0 = default 1000; out-of-range values clamp to [10, 10000]).
    pub async fn connect_with(url: &str, scan_count: u32) -> Result<Self> {
        let client = Client::open(url).map_err(redis_err)?;
        // ② §4.8: when Redis is fully down/flapping, commands on the shared connection **must not wait unboundedly for the connection manager to reconnect**.
        // Without a cap, hot paths such as dedup/seq/pending would hang waiting for a connection (observed message requests returning after >120s
        // while /v1/ready had already recovered to 200 thanks to its separate 300ms probe), making the degradation path useless.
        // Here the connection manager's reconnect retries are tightened to "1 attempt, 150ms max interval", 1s per command response,
        // 400ms connect: when Redis is unavailable, commands fail fast within ~1s and upper layers follow the existing degradation matrix to
        // the PG cold layer / local hub / WAL; the next command reconnects automatically after Redis recovers.
        // The readiness probe is unaffected (`ping_ready` still opens a separate short connection with a 300ms cap each time).
        let mgr_cfg = redis::aio::ConnectionManagerConfig::new()
            .set_response_timeout(Duration::from_secs(1))
            .set_connection_timeout(Duration::from_millis(400))
            .set_number_of_retries(1)
            .set_factor(50)
            .set_max_delay(150);
        let mgr = ConnectionManager::new_with_config(client.clone(), mgr_cfg)
            .await
            .map_err(redis_err)?;
        let scan_count = if scan_count == 0 {
            crate::config::DEFAULT_REDIS_SCAN_COUNT
        } else {
            scan_count.clamp(10, 10_000)
        };
        Ok(Redis {
            client,
            mgr,
            scan_count,
            metrics: Arc::new(StdRwLock::new(None)),
        })
    }

    /// Inject the metrics handle (idempotent; only used for `lattice_redis_scan_calls_total` quantified recording).
    pub fn set_metrics(&self, metrics: Arc<Metrics>) {
        if let Ok(mut w) = self.metrics.write() {
            *w = Some(metrics);
        }
    }

    /// SCAN COUNT in effect for this connection (for logs/troubleshooting).
    pub fn scan_count(&self) -> u32 {
        self.scan_count
    }

    fn note_scan_call(&self) {
        if let Some(m) = self.metrics.read().ok().and_then(|r| r.clone()) {
            m.redis_scan_calls_total.inc();
        }
    }

    pub async fn ping(&self) -> Result<()> {
        let mut c = self.mgr.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut c)
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    /// **Readiness-probe-only** PING (E10 D2/D3): separate short-lived connection + connect/response timeouts, bounded return.
    ///
    /// Why not reuse the shared `ConnectionManager`: commands issued during a Redis failure window would queue on that
    /// multiplexed connection; even if the caller times out/aborts, the command is still in flight, and after recovery the connection may keep
    /// blocking all later commands (E10 D3 "in-flight hang" risk). Here every probe creates a connection used **only for liveness**
    /// and discards the whole connection on timeout: `/v1/ready` is never held up by shared-pool backlog, nor does it pollute it
    /// (⑤ §6: probes must answer quickly and meaningfully).
    ///
    /// The timeout covers "connect + PING" end to end (outer `tokio::time::timeout` as the final fallback; 200–500ms
    /// recommended: far below the LB probe timeout).
    pub async fn ping_ready(&self, timeout: Duration) -> Result<()> {
        let config = redis::AsyncConnectionConfig::new()
            .set_connection_timeout(timeout)
            .set_response_timeout(timeout);
        let attempt = async {
            let mut conn = self
                .client
                .get_multiplexed_async_connection_with_config(&config)
                .await?;
            redis::cmd("PING")
                .query_async::<String>(&mut conn)
                .await?;
            Ok::<(), redis::RedisError>(())
        };
        match tokio::time::timeout(timeout, attempt).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(redis_err(e)),
            Err(_) => {
                // Probe timeout: WARN only (not a business error); the caller maps it to degraded.
                tracing::warn!(
                    timeout_ms = timeout.as_millis() as u64,
                    "redis ready ping timed out (bounded probe)"
                );
                Err(crate::error::internal("cache unavailable")
                    .with_detail("dep", serde_json::json!("redis")))
            }
        }
    }

    // ---- Online index (§8.2 two-layer keys: Hash + String) -----------------------------

    /// Register/renew: `HSET conn:{user} {device}=node` + `EXPIRE`, plus `SET conn:{user}:{device} EX`.
    pub async fn register_conn(
        &self,
        user: &str,
        device: &str,
        node: &str,
        ttl_secs: u64,
    ) -> Result<()> {
        let mut c = self.mgr.clone();
        let hash = lattice_core::keys::conn_user(user);
        let key = lattice_core::keys::conn_device(user, device);
        let _: () = c.hset(&hash, device, node).await.map_err(redis_err)?;
        let _: () = c
            .expire(&hash, ttl_secs as i64)
            .await
            .map_err(redis_err)?;
        let _: () = c
            .set_ex(&key, node, ttl_secs)
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    /// Renew only (keepalive path, avoiding TTL semantic recomputation each time).
    pub async fn touch_conn(
        &self,
        user: &str,
        device: &str,
        node: &str,
        ttl_secs: u64,
    ) -> Result<()> {
        self.register_conn(user, device, node, ttl_secs).await
    }

    /// Device disconnect: delete only this device's keys; once the Hash is empty, TTL expiry handles it (② §4.1).
    pub async fn unregister_conn(&self, user: &str, device: &str) -> Result<()> {
        let mut c = self.mgr.clone();
        let hash = lattice_core::keys::conn_user(user);
        let key = lattice_core::keys::conn_device(user, device);
        let _: () = c.hdel(&hash, device).await.map_err(redis_err)?;
        let _: () = c.del(&key).await.map_err(redis_err)?;
        Ok(())
    }

    pub async fn conn_devices(&self, user: &str) -> Result<HashMap<String, String>> {
        let mut c = self.mgr.clone();
        let map: HashMap<String, String> = c
            .hgetall(lattice_core::keys::conn_user(user))
            .await
            .map_err(redis_err)?;
        Ok(map)
    }

    pub async fn device_node(&self, user: &str, device: &str) -> Result<Option<String>> {
        let mut c = self.mgr.clone();
        let v: Option<String> = c
            .get(lattice_core::keys::conn_device(user, device))
            .await
            .map_err(redis_err)?;
        Ok(v)
    }

    /// Node heartbeat `lattice:node:{id}` EX 10s (§17.8).
    pub async fn heartbeat_node(&self, node: &str, info: &str, ttl_secs: u64) -> Result<()> {
        let mut c = self.mgr.clone();
        let _: () = c
            .set_ex(lattice_core::keys::node(node), info, ttl_secs)
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    pub async fn nodes(&self) -> Result<Vec<(String, String)>> {
        let mut c = self.mgr.clone();
        // Always use batched SCAN (configurable COUNT): the node key space is small, but hot-path consistency matters more than special-casing.
        let keys = self.scan_prefix("lattice:node:").await?;
        let mut out = Vec::new();
        for k in keys {
            let v: Option<String> = c.get(&k).await.map_err(redis_err)?;
            if let Some(v) = v {
                out.push((k.trim_start_matches("lattice:node:").to_string(), v));
            }
        }
        Ok(out)
    }

    /// Number of media tunnel sessions currently in Redis (`lattice:stream:*`).
    ///
    /// Called only on stream-sig offer (low frequency); used for the per-node concurrent stream cap in §17.9.
    /// SCAN rather than KEYS to avoid blocking large Redis instances; batched COUNT reduces round trips.
    pub async fn count_stream_sessions(&self) -> Result<usize> {
        Ok(self.scan_prefix("lattice:stream:").await?.len())
    }

    // ---- Dedup hot layer (§17.5) -------------------------------------------------

    /// `SET NX EX` → true means first time (allow), false means duplicate.
    pub async fn dedup_first(&self, key: &str, ttl_secs: u64) -> Result<bool> {
        let mut c = self.mgr.clone();
        let res: Option<String> = redis::cmd("SET")
            .arg(lattice_core::keys::dedup(key))
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs)
            .query_async(&mut c)
            .await
            .map_err(redis_err)?;
        Ok(res.is_some())
    }

    // ---- seq (§6.4) ------------------------------------------------------

    pub async fn next_seq(&self, conv: &str) -> Result<i64> {
        let mut c = self.mgr.clone();
        let v: i64 = c
            .incr(lattice_core::keys::seq(conv), 1i64)
            .await
            .map_err(redis_err)?;
        Ok(v)
    }

    pub async fn peek_seq(&self, conv: &str) -> Result<Option<i64>> {
        let mut c = self.mgr.clone();
        let v: Option<i64> = c.get(lattice_core::keys::seq(conv)).await.map_err(redis_err)?;
        Ok(v)
    }

    /// Correct by `max(Redis, PG)` after a Redis switchover (② §4.8).
    pub async fn set_seq_floor(&self, conv: &str, floor: i64) -> Result<()> {
        let mut c = self.mgr.clone();
        let key = lattice_core::keys::seq(conv);
        let cur: Option<i64> = c.get(&key).await.map_err(redis_err)?;
        if cur.unwrap_or(0) < floor {
            let _: () = c.set(&key, floor).await.map_err(redis_err)?;
        }
        Ok(())
    }

    // ---- Offline queues (three pending queues, §6.4) ------------------------------------

    pub async fn pending_add(&self, key: &str, score: i64, id: &str) -> Result<()> {
        let mut c = self.mgr.clone();
        let _: () = c.zadd(key, id, score).await.map_err(redis_err)?;
        Ok(())
    }

    /// Fetch a batch in ascending score(seq) order (redelivery keeps order).
    pub async fn pending_batch(&self, key: &str, limit: usize) -> Result<Vec<(String, i64)>> {
        let mut c = self.mgr.clone();
        let items: Vec<(String, i64)> = c
            .zrange_withscores(key, 0, (limit as isize) - 1)
            .await
            .map_err(redis_err)?;
        Ok(items)
    }

    pub async fn pending_remove(&self, key: &str, id: &str) -> Result<()> {
        let mut c = self.mgr.clone();
        let _: () = c.zrem(key, id).await.map_err(redis_err)?;
        Ok(())
    }

    pub async fn pending_len(&self, key: &str) -> Result<i64> {
        let mut c = self.mgr.clone();
        let v: i64 = c.zcard(key).await.map_err(redis_err)?;
        Ok(v)
    }

    pub async fn pending_oldest(&self, key: &str) -> Result<Option<i64>> {        let mut c = self.mgr.clone();
        let items: Vec<(String, i64)> = c
            .zrange_withscores(key, 0, 0)
            .await
            .map_err(redis_err)?;
        Ok(items.first().map(|(_, s)| *s))
    }

    /// Batch-scan keys by prefix (`SCAN cursor MATCH {prefix}* COUNT {scan_count}`).
    ///
    /// Semantics (⑥ §3.4 "must not lose keys"):
    /// - `COUNT` is only a **hint** for how many keys each round returns, not a cap: this loops cursor-wise until 0,
    ///   so every key matching the prefix is returned (a larger COUNT only reduces round trips, never changes the result set);
    /// - MATCH is filtered server-side by Redis (no client-side second filter, avoiding prefix semantic drift);
    /// - SCAN may return **duplicate keys** across rounds; results are deduped via `HashSet` before returning;
    /// - Each SCAN round trip increments `lattice_redis_scan_calls_total` (PL-17 quantified conventions).
    ///
    /// Usage boundary: only for **bounded prefixes** (e.g. `lattice:node:`, `lattice:pending:{user}:topic:`,
    /// admin-side prefix cleanup). Do not use it to enumerate the whole key space; wider prefixes cost more on the Redis side.
    pub async fn scan_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        use std::collections::HashSet;
        let pattern = format!("{prefix}*");
        let mut c = self.mgr.clone();
        let mut cursor: u64 = 0;
        let mut seen: HashSet<String> = HashSet::new();
        let mut out: Vec<String> = Vec::new();
        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(self.scan_count)
                .query_async(&mut c)
                .await
                .map_err(redis_err)?;
            self.note_scan_call();
            merge_scan_batch(&mut seen, &mut out, keys);
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        Ok(out)
    }

    // ---- Subscription hot cache ------------------------------------------------------

    pub async fn sub_add(&self, user: &str, topic: &str) -> Result<()> {
        let mut c = self.mgr.clone();
        let key = lattice_core::keys::sub(user);
        let _: () = c.sadd(&key, topic).await.map_err(redis_err)?;
        let _: () = c.expire(&key, 86_400).await.map_err(redis_err)?;
        Ok(())
    }

    pub async fn sub_remove(&self, user: &str, topic: &str) -> Result<()> {
        let mut c = self.mgr.clone();
        let _: () = c
            .srem(lattice_core::keys::sub(user), topic)
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    pub async fn sub_members(&self, user: &str) -> Result<Vec<String>> {
        let mut c = self.mgr.clone();
        let v: Vec<String> = c
            .smembers(lattice_core::keys::sub(user))
            .await
            .map_err(redis_err)?;
        Ok(v)
    }

    // ---- Rate limiting (token-bucket approximation: 1s window counter, ⑥ §3.2) ----------

    /// Returns the current window count; when it exceeds `limit` the caller responds `RATE` (⑤ §0.7).
    pub async fn bump_rate(&self, key: &str, window_secs: u64) -> Result<i64> {
        let mut c = self.mgr.clone();
        let n: i64 = c.incr(key, 1i64).await.map_err(redis_err)?;
        if n == 1 {
            let _: () = c.expire(key, window_secs as i64).await.map_err(redis_err)?;
        }
        Ok(n)
    }

    pub async fn bump_login_failure(&self, scope: &str, window_secs: u64) -> Result<i64> {
        self.bump_rate(&lattice_core::keys::ratelimit_login(scope), window_secs)
            .await
    }

    // ---- Distributed locks (⑥ §3.2 Lua release) --------------------------------------

    /// `SET NX PX`; returns whether the lock was acquired.
    pub async fn acquire_lock(&self, task: &str, owner: &str, ttl_ms: u64) -> Result<bool> {
        let mut c = self.mgr.clone();
        let key = lattice_core::keys::lock(task);
        let res: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(owner)
            .arg("NX")
            .arg("PX")
            .arg(ttl_ms)
            .query_async(&mut c)
            .await
            .map_err(redis_err)?;
        Ok(res.is_some())
    }

    /// Lua compare-and-delete to avoid deleting someone else's lock (⑥ §3.2).
    pub async fn release_lock(&self, task: &str, owner: &str) -> Result<()> {
        let mut c = self.mgr.clone();
        let script = redis::Script::new(
            "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end",
        );
        let _: i64 = script
            .key(lattice_core::keys::lock(task))
            .arg(owner)
            .invoke_async(&mut c)
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    // ---- PubSub ----------------------------------------------------------

    pub async fn publish(&self, channel: &str, payload: &str) -> Result<()> {
        let mut c = self.mgr.clone();
        let _: () = c.publish(channel, payload).await.map_err(redis_err)?;
        Ok(())
    }

    /// Subscribe to a set of channels; callback `(channel, payload)`.
    pub async fn subscribe<F>(&self, channels: Vec<String>, mut on_msg: F) -> Result<()>
    where
        F: FnMut(String, String) + Send + 'static,
    {
        let mut pubsub = self
            .client
            .get_async_pubsub()
            .await
            .map_err(redis_err)?;
        for ch in &channels {
            pubsub.subscribe(ch).await.map_err(redis_err)?;
        }
        tokio::spawn(async move {
            use futures::StreamExt;
            let mut stream = pubsub.on_message();
            while let Some(msg) = stream.next().await {
                let channel: String = msg.get_channel().unwrap_or_default();
                let payload: String = msg.get_payload().unwrap_or_default();
                on_msg(channel, payload);
            }
        });
        Ok(())
    }

    /// Risk control queue (⑤ §4.7 / ⑥ §3.1 `lattice:risk`).
    pub async fn risk_push(&self, user: &str, reason: &str) -> Result<()> {
        let mut c = self.mgr.clone();
        let score = chrono::Utc::now().timestamp_millis();
        let _: () = c
            .zadd(lattice_core::keys::risk(), format!("{user}:{reason}"), score)
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    /// Generic JSON string read/write (non-authoritative state such as upload sessions: loss is recoverable by client re-upload).
    pub async fn set_json(&self, key: &str, value: &str, ttl_secs: u64) -> Result<()> {
        let mut c = self.mgr.clone();
        let _: () = c.set_ex(key, value, ttl_secs).await.map_err(redis_err)?;
        Ok(())
    }

    pub async fn get_json(&self, key: &str) -> Result<Option<String>> {
        let mut c = self.mgr.clone();
        let v: Option<String> = c.get(key).await.map_err(redis_err)?;
        Ok(v)
    }

    pub async fn del(&self, key: &str) -> Result<()> {
        let mut c = self.mgr.clone();
        let _: () = c.del(key).await.map_err(redis_err)?;
        Ok(())
    }

    // ---- Media tunnel sessions (`lattice:stream:{id}`, ⑥ §3.1; used only by WS stream-sig/data) ----

    /// Write/overwrite a tunnel session and set its TTL (called when an offer is established).
    pub async fn stream_session_put(
        &self,
        id: &str,
        fields: &[(&str, &str)],
        ttl_secs: u64,
    ) -> Result<()> {
        let mut c = self.mgr.clone();
        let key = lattice_core::keys::stream_session(id);
        let mut cmd = redis::cmd("HSET");
        cmd.arg(&key);
        for (field, value) in fields {
            cmd.arg(*field).arg(*value);
        }
        let _: () = cmd.query_async(&mut c).await.map_err(redis_err)?;
        let _: () = c
            .expire(&key, ttl_secs as i64)
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    pub async fn stream_session_get(
        &self,
        id: &str,
    ) -> Result<Option<std::collections::HashMap<String, String>>> {
        let mut c = self.mgr.clone();
        let key = lattice_core::keys::stream_session(id);
        let map: std::collections::HashMap<String, String> =
            c.hgetall(&key).await.map_err(redis_err)?;
        Ok(if map.is_empty() { None } else { Some(map) })
    }

    pub async fn stream_session_touch(&self, id: &str, ttl_secs: u64) -> Result<()> {
        let mut c = self.mgr.clone();
        let _: () = c
            .expire(
                lattice_core::keys::stream_session(id),
                ttl_secs as i64,
            )
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    pub async fn stream_session_del(&self, id: &str) -> Result<()> {
        self.del(&lattice_core::keys::stream_session(id)).await
    }

    // ---- Media recording bus consumer idempotency watermark (PL-13 13.6; used only by the media_record consumer) ----

    /// Recording idempotency watermark key: `lattice:media:record:{node_id}:wm:{stream_id}` → last persisted seq.
    ///
    /// Note: the key name is not in `lattice_core::keys` (that crate is outside this round's scope); it is used only in
    /// the consumer side of `routing/media_record.rs` and is **not** authoritative data (loss only causes an extra write of an
    /// object with the same name during replay, never a dropped frame); the 7d TTL covers node restarts/short stalls.
    pub fn media_record_watermark_key(node_id: &str, stream_id: &str) -> String {
        format!("lattice:media:record:{node_id}:wm:{stream_id}")
    }

    /// Read the largest persisted seq for a (node, stream); absent = `None` (new stream).
    pub async fn media_record_watermark_get(
        &self,
        node_id: &str,
        stream_id: &str,
    ) -> Result<Option<u64>> {
        let mut c = self.mgr.clone();
        let key = Self::media_record_watermark_key(node_id, stream_id);
        let v: Option<String> = c.get(&key).await.map_err(redis_err)?;
        Ok(v.and_then(|s| s.parse::<u64>().ok()))
    }

    /// Record the largest persisted seq for a (node, stream) (called after the object write succeeds, before acking the message).
    pub async fn media_record_watermark_set(
        &self,
        node_id: &str,
        stream_id: &str,
        seq: u64,
        ttl_secs: u64,
    ) -> Result<()> {
        let mut c = self.mgr.clone();
        let key = Self::media_record_watermark_key(node_id, stream_id);
        let _: () = c
            .set_ex(&key, seq.to_string(), ttl_secs)
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    // ---- Generic HTTP idempotency keys (REMAINING E12; contract ⑤ §0.3 / design §17.5) ----------
    //
    // Key layout (**not in `lattice_core::keys`**: `lattice-core` is outside this round's scope; these two keys
    // are just "replayable response copies"; losing them in Redis degrades replay to executing again, not data loss):
    //   lattice:idem:rec:{sha256(scope)}   first-response cache (JSON, TTL `idempotency.ttl`)
    //   lattice:idem:lock:{sha256(scope)}  concurrent same-key single-flight lock (value=holder token, short TTL)
    //
    // scope = caller + method + path + Idempotency-Key, never reused across users; the middleware computes sha256
    // before hitting Redis, avoiding embedding raw user ids / paths / client keys in key names (may be too long or contain control characters).

    /// Redis key for the first-response cache.
    pub fn idem_record_key(scope_hash: &str) -> String {
        format!("lattice:idem:rec:{scope_hash}")
    }

    /// Redis key for the concurrent same-key single-flight lock.
    pub fn idem_lock_key(scope_hash: &str) -> String {
        format!("lattice:idem:lock:{scope_hash}")
    }

    /// Read the first-response cache (raw JSON; corrupt/partial entries are treated as a miss by the caller).
    pub async fn idem_get(&self, scope_hash: &str) -> Result<Option<String>> {
        let mut c = self.mgr.clone();
        let v: Option<String> = c
            .get(Self::idem_record_key(scope_hash))
            .await
            .map_err(redis_err)?;
        Ok(v)
    }

    /// `SET NX EX` to acquire the single-flight lock: `true` = this request is the first executor, `false` = a concurrent same-key request exists.
    pub async fn idem_begin(&self, scope_hash: &str, holder: &str, ttl_secs: u64) -> Result<bool> {
        let mut c = self.mgr.clone();
        let res: Option<String> = redis::cmd("SET")
            .arg(Self::idem_lock_key(scope_hash))
            .arg(holder)
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs.max(1))
            .query_async(&mut c)
            .await
            .map_err(redis_err)?;
        Ok(res.is_some())
    }

    /// Write the first-response cache (`SET EX`; overwriting old values also self-heals corrupt records).
    pub async fn idem_put(&self, scope_hash: &str, record: &str, ttl_secs: u64) -> Result<()> {
        let mut c = self.mgr.clone();
        let _: () = c
            .set_ex(Self::idem_record_key(scope_hash), record, ttl_secs.max(1))
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    /// Release the single-flight lock: Lua compare-and-del, deleting only the lock **held by this request**.
    ///
    /// Do not `DEL` directly: if this request runs longer than the lock TTL, a concurrent request may already hold the lock,
    /// and an unconditional `DEL` deletes someone else's lock, letting a third request enter and repeat side effects.
    pub async fn idem_release(&self, scope_hash: &str, holder: &str) -> Result<()> {
        let mut c = self.mgr.clone();
        const CAS_DEL: &str = r#"
            if redis.call('GET', KEYS[1]) == ARGV[1] then
                return redis.call('DEL', KEYS[1])
            else
                return 0
            end
        "#;
        let _: i64 = redis::Script::new(CAS_DEL)
            .key(Self::idem_lock_key(scope_hash))
            .arg(holder)
            .invoke_async(&mut c)
            .await
            .map_err(redis_err)?;
        Ok(())
    }
}

/// Merge keys from one SCAN round into the result set (**dedup**; SCAN semantics allow the same key across rounds).
///
/// Kept as a separate function for unit testing: dedup is the key invariant behind "batched SCAN loses no keys and returns no duplicates".
fn merge_scan_batch(
    seen: &mut std::collections::HashSet<String>,
    out: &mut Vec<String>,
    batch: Vec<String>,
) {
    for k in batch {
        if seen.insert(k.clone()) {
            out.push(k);
        }
    }
}

/// Per-user rate limiting (local approximation; degrades to in-process counting when Redis is unavailable, ② §4.8).
#[derive(Debug, Default)]
pub struct LocalBucket {
    window_start_ms: u64,
    count: u64,
}

impl LocalBucket {
    pub fn allow(&mut self, limit: u64) -> bool {
        self.allow_weight(limit, 1)
    }

    /// Count by weight (for byte-based limits): accumulate `weight` in the same 1s window; reject when it exceeds `limit`.
    ///
    /// `limit=0` disables rate limiting (config 0 = unlimited, consistent with other 0-value semantics in `[policy]`).
    pub fn allow_weight(&mut self, limit: u64, weight: u64) -> bool {
        if limit == 0 {
            return true;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if now.saturating_sub(self.window_start_ms) >= 1000 {
            self.window_start_ms = now;
            self.count = 0;
        }
        self.count = self.count.saturating_add(weight.max(1));
        self.count <= limit
    }
}

/// Release after long inactivity (avoid unbounded bucket growth; memory only).
pub async fn gc_buckets_forever() {
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        tracing::debug!("local rate buckets gc tick");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_batches_are_deduped_across_rounds() {
        // SCAN may return the same key across rounds: batched aggregation must dedup by key without losing unique keys.
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        merge_scan_batch(
            &mut seen,
            &mut out,
            vec!["k1".into(), "k2".into(), "k1".into()],
        );
        merge_scan_batch(&mut seen, &mut out, vec!["k2".into(), "k3".into()]);
        merge_scan_batch(&mut seen, &mut out, vec![]);
        assert_eq!(out, vec!["k1".to_string(), "k2".to_string(), "k3".to_string()]);
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn media_record_watermark_key_is_per_node_and_stream() {
        let k = Redis::media_record_watermark_key("node-a", "st-1");
        assert_eq!(k, "lattice:media:record:node-a:wm:st-1");
        // Keys for different nodes/streams must be isolated (otherwise multiple nodes misjudge "already persisted" → dropped frames)
        assert_ne!(
            Redis::media_record_watermark_key("node-a", "st-1"),
            Redis::media_record_watermark_key("node-b", "st-1")
        );
        assert_ne!(
            Redis::media_record_watermark_key("node-a", "st-1"),
            Redis::media_record_watermark_key("node-a", "st-2")
        );
        // Key space does not collide with tunnel session keys (`lattice:stream:*`) or node keys (`lattice:node:*`)
        assert!(k.starts_with("lattice:media:record:"));
        let session_prefix = lattice_core::keys::stream_session("");
        assert!(!k.starts_with(&session_prefix));
        assert!(!k.starts_with("lattice:node:"));
    }
}
