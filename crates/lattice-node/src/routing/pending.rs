//! Offline queues and redelivery (② §4.2). Three queues that **must not be merged**:
//!
//! | Queue | When used | Dequeue semantics |
//! | --- | --- | --- |
//! | `lattice:pending:{user}` | all devices offline (§17.4-1) | consumed when any device comes online (not copied) |
//! | `lattice:pending:{user}:{device}` | `to_devices` targeting and that device is offline (§17.4-5) | consumed by that device only |
//! | `lattice:pending:{user}:topic:{t}` | broadcast while offline (§6.4) | consumed by `topic_offsets` watermark |
//!
//! Redelivery invariants: serial per device, ascending seq, per-user rate limit 200 msg/s (§17.13).
//!
//! Retransmission and dead letters (E17, ② §4.2):
//! - Each successful redelivery increments `delivery_log.attempts` (an existing column, ⑥ §2.3); dequeue after ACK;
//! - Unacked entries decide whether to redeliver on the next online/reconnect using backoff windows 1/2/4/8/16s; during backoff the queue **stops to preserve order**
//!   (later entries for this device must not overtake it);
//! - After 5 consecutive failed deliveries without ACK → `delivery_log.state=dlq` and dequeue, waiting for the admin
//!   `POST /v1/admin/replay` to replay (replay moves `dlq → routed` first, then re-enqueues; here
//!   [`enqueue_user`] resets attempts to zero, otherwise it would immediately become a dead letter again).
//!
//! Boundary (recorded honestly): retransmission is triggered by **online/reconnect events**; while a connection stays up there is no independent ACK-wait
//! timer (the ② §4.2 "wait 10s → redeliver" is not implemented as an in-connection timer loop); topic-level queues keep the
//! "dequeue on successful send + advance `topic_offsets`" at-most-once semantics and do not participate in retransmission counting.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lattice_core::{keys, Frame, WsCommand};

use crate::error::Result;
use crate::state::AppState;

/// Redelivery retransmission cap: reaching this many consecutive deliveries without ACK → dead letter (② §4.2 "limit 5").
pub const MAX_PENDING_ATTEMPTS: i32 = 5;

/// Backoff window after the `attempts`-th delivery (milliseconds): 1s / 2s / 4s / 8s / 16s (② §4.2).
pub fn retry_backoff_ms(attempts: i32) -> i64 {
    match attempts {
        a if a <= 0 => 0,
        1 => 1_000,
        2 => 2_000,
        3 => 4_000,
        4 => 8_000,
        _ => 16_000,
    }
}

/// Redelivery sends only messages with `messages.status='persisted'`: `expired`/`dropped` are terminal
/// (§17.3 subset), and `pending-clean` only advances PG state; queue entries are **lazily reclaimed** here,
/// guaranteeing that nothing "deleted is still being delivered".
pub fn deliverable_status(status: &str) -> bool {
    status == "persisted"
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Enqueue (small message payloads are already in PG; the ZSET stores only seq → msg_id).
pub async fn enqueue_user(state: &AppState, user: &str, seq: i64, msg_id: &str) -> Result<()> {
    // Dead-letter replay: the admin first flips the dlq row to routed, then calls this function (admin/mod.rs::replay).
    // Reset attempts here, otherwise the next drain immediately exceeds the limit again and sends it back to dlq (replay becomes useless).
    // On a normal offline enqueue this row usually does not exist yet (policy writes the persisted row after enqueue) → 0 rows affected.
    let _ = crate::store::pg::reset_delivery_attempts(&state.db, msg_id, user, MAX_PENDING_ATTEMPTS)
        .await;
    state
        .redis
        .pending_add(&keys::pending_user(user), seq, msg_id)
        .await
}

pub async fn enqueue_device(
    state: &AppState,
    user: &str,
    device: &str,
    seq: i64,
    msg_id: &str,
) -> Result<()> {
    let _ = crate::store::pg::reset_delivery_attempts(&state.db, msg_id, user, MAX_PENDING_ATTEMPTS)
        .await;
    state
        .redis
        .pending_add(&keys::pending_device(user, device), seq, msg_id)
        .await
}

pub async fn enqueue_topic(
    state: &AppState,
    user: &str,
    topic: &str,
    offset: i64,
    msg_id: &str,
) -> Result<()> {
    state
        .redis
        .pending_add(&keys::pending_topic(user, topic), offset, msg_id)
        .await
}

/// Dequeue after ack: delete only entries for this device/queue (multiple devices do not affect each other, §17.4-2).
pub async fn ack_remove(state: &AppState, user: &str, device: &str, msg_id: &str) {
    let _ = state
        .redis
        .pending_remove(&keys::pending_user(user), msg_id)
        .await;
    let _ = state
        .redis
        .pending_remove(&keys::pending_device(user, device), msg_id)
        .await;
    // The placeholder delivery row for the user-level queue has `to_device='*'` (written by policy on offline enqueue); a device-level ACK
    // updates only the real device row → the `'*'` row would stay persisted forever: §17.4-3 "acked from the sender's perspective"
    // is invisible in delivery_log, and reconcile keeps backfilling it as a queue ghost of an incomplete delivery.
    // Advance it together on ACK (missing target row = 0 rows affected; live delivery has no placeholder row).
    if let Err(e) = crate::store::pg::mark_delivery_state(&state.db, msg_id, "*", "acked").await {
        tracing::warn!(error = %e, msg_id, "delivery_log '*' ack update failed");
    }
    state.metrics.pending_depth.with_label_values(&["user", &crate::observe::Metrics::user_hash(user)]).set(
        state
            .redis
            .pending_len(&keys::pending_user(user))
            .await
            .unwrap_or(0),
    );
}

/// Queue depth (admin `GET /v1/admin/queue`, ⑤ §8.1).
pub async fn depth(state: &AppState, user: &str) -> (i64, Option<i64>) {
    let key = keys::pending_user(user);
    let len = state.redis.pending_len(&key).await.unwrap_or(0);
    let oldest = state.redis.pending_oldest(&key).await.ok().flatten();
    (len, oldest)
}

/// Redeliver: after coming online, send queued messages one by one (serial per device, rate limited to 200 msg/s, §17.13).
///
/// Dequeue and delivery are **not atomic**: a crash after delivery leaves the entry in the queue → duplicate delivery, with client-side dedup as the safety net
/// (⑥ §3.2: prefer duplicates over loss). See the module header for retransmission/backoff/dead letters.
pub async fn drain_device(state: &AppState, user: &str, device: &str) -> Result<usize> {
    let limit = state.cfg.policy.pending_rate_limit as usize;
    if limit == 0 {
        return Ok(0);
    }
    // Target interval per message (200 msg/s → 5ms); rate limit by **claiming a slot per message** (E17 defect fix:
    // the old implementation compared elapsed time from the drain start against a fixed budget, so only the first message slept).
    let interval = Duration::from_millis((1000 / limit.max(1)) as u64);
    let mut next_slot = Instant::now();
    let mut sent = 0usize;

    // Device-level queue before user-level queue; if any entry stops due to backoff/dead connection, both queues stop this round,
    // preserving per-device serialization and seq order (do not skip past a backing-off entry to deliver later ones).
    for (queue, row_device) in [
        (keys::pending_device(user, device), device.to_string()),
        (keys::pending_user(user), "*".to_string()),
    ] {
        let batch = match state.redis.pending_batch(&queue, limit).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "pending batch read failed");
                continue;
            }
        };
        let mut halt = false;
        for (msg_id, _seq) in batch {
            if halt {
                break;
            }
            let Some(msg) = crate::store::pg::message_by_id(&state.db, &msg_id).await? else {
                // Message expired/archived: dequeue directly to avoid zombie entries (IN5)
                let _ = state.redis.pending_remove(&queue, &msg_id).await;
                continue;
            };
            if !deliverable_status(&msg.status) {
                // expired/dropped are not redelivered: lazily clean the queue entry (guards against "deleted is still being delivered").
                let _ = state.redis.pending_remove(&queue, &msg_id).await;
                continue;
            }

            // Retransmission decision: read attempts/last_at/state of the matching delivery row for this queue.
            let retry = crate::store::pg::delivery_retry_row(&state.db, &msg_id, user, &row_device)
                .await
                .unwrap_or(None);
            if let Some(row) = &retry {
                if row.state == "dlq" {
                    // Already a dead letter (leftover from before replay): the redelivery loop must not send it again.
                    let _ = state.redis.pending_remove(&queue, &msg_id).await;
                    continue;
                }
                if row.attempts >= MAX_PENDING_ATTEMPTS {
                    if let Err(e) = crate::store::pg::mark_delivery_state(
                        &state.db,
                        &msg.id,
                        &row.to_device,
                        "dlq",
                    )
                    .await
                    {
                        tracing::warn!(error = %e, msg_id = %msg.id, "mark delivery dlq failed");
                    }
                    let _ = state.redis.pending_remove(&queue, &msg.id).await;
                    tracing::warn!(
                        msg_id = %msg.id,
                        user = %crate::observe::Metrics::user_hash(user),
                        device,
                        attempts = row.attempts,
                        "pending retransmit exhausted; moved to dlq"
                    );
                    continue;
                }
                if row.attempts > 0 {
                    if let Some(last) = row.last_at {
                        let due = last.timestamp_millis() + retry_backoff_ms(row.attempts);
                        if now_ms() < due {
                            // Within the backoff window: keep the entry (neither deliver nor delete) and stop this round to preserve order.
                            halt = true;
                            break;
                        }
                    }
                }
            }

            let env = lattice_core::Envelope {
                id: msg.id.clone(),
                r#type: msg.env_type.clone(),
                content_type: msg.content_type.clone().unwrap_or_default(),
                encoding: "utf8".into(),
                payload: msg.payload.clone().unwrap_or_default(),
                conv_id: msg.conv_id.clone(),
                seq: msg.seq as u64,
                sender: msg.sender.clone(),
                ttl_seconds: 0,
                ..Default::default()
            };
            let frame = Frame::new(WsCommand::Envelope, bytes::Bytes::from(env.encode_body()));
            if state.hub.send_to_device(user, device, frame) {
                sent += 1;
                // attempts increments only for retransmission/dead-letter diagnostics (existing delivery_log column, ⑥ §2.3).
                if let Err(e) = crate::store::pg::upsert_delivery(
                    &state.db,
                    &msg.id,
                    user,
                    &row_device,
                    lattice_core::protocol::DeliveryState::Routed.as_str(),
                    &state.node_id,
                    true,
                )
                .await
                {
                    tracing::warn!(error = %e, msg_id = %msg.id, "delivery attempt bump failed");
                }
                // Rate limit per message: claim the next send slot; do not catch up on sleep if processing took longer than the slot (avoid debt).
                next_slot += interval;
                let now = Instant::now();
                if next_slot > now {
                    tokio::time::sleep(next_slot - now).await;
                } else {
                    next_slot = now;
                }
            } else {
                // Connection no longer in hub (device just disconnected): keep the entry until the next online, stop to preserve order.
                halt = true;
                break;
            }
        }
        if halt {
            break;
        }
    }

    state
        .metrics
        .pending_depth
        .with_label_values(&["user", &crate::observe::Metrics::user_hash(user)])
        .set(state.redis.pending_len(&keys::pending_user(user)).await.unwrap_or(0));

    Ok(sent)
}

/// keepalive `seq_watermark` reconciliation: drop pending entries for that conversation already acked by the client (seq ≤ watermark).
///
/// Why needed: redelivery is at-least-once (dequeue and delivery are not atomic), so after a client reconnects it may still have leftovers in the queue
/// even if it already received some messages → duplicate delivery. The `{conv_id: seq}` the client reports every 25s is the authoritative
/// "I have received up to here" statement; clearing the queue per conversation shrinks the duplicate window to one keepalive period (⑤ §9.4).
///
/// Handles only user and device queues (topic queues are handled by [`drain_topics`] by offset).
pub async fn ack_through(
    state: &AppState,
    user: &str,
    device: &str,
    conv: &str,
    watermark: i64,
) -> usize {
    let mut removed = 0usize;
    for queue in [keys::pending_device(user, device), keys::pending_user(user)] {
        let Ok(batch) = state.redis.pending_batch(&queue, 500).await else {
            continue;
        };
        for (msg_id, seq) in batch {
            if seq > watermark || msg_id.is_empty() {
                continue;
            }
            // Delete only entries belonging to this conversation: the user queue shares the score space across conversations, so the seq value alone is not enough.
            let belongs = crate::store::pg::message_by_id_in_conv(&state.db, &msg_id, conv)
                .await
                .ok()
                .flatten()
                .is_some();
            if belongs && state.redis.pending_remove(&queue, &msg_id).await.is_ok() {
                removed += 1;
            }
        }
    }
    if removed > 0 {
        state
            .metrics
            .pending_depth
            .with_label_values(&["user", &crate::observe::Metrics::user_hash(user)])
            .set(state.redis.pending_len(&keys::pending_user(user)).await.unwrap_or(0));
    }
    removed
}

/// Topic offline queue redelivery: when the user has a WS device online, drain every `pending:{user}:topic:*` queue.
///
/// Difference from [`drain_device`]: topic queues sort by `offset/seq` and have no "device targeting" concept;
/// one broadcast only needs to go to one online device (other devices catch up by reading history/watermarks when they reconnect).
pub async fn drain_topics(state: &AppState, user: &str, device: &str) -> Result<usize> {
    let prefix = format!("{}:topic:", keys::pending_user(user));
    let Ok(queues) = state.redis.scan_prefix(&prefix).await else {
        return Ok(0);
    };
    let mut sent = 0usize;
    tracing::debug!(user, queues = queues.len(), "topic pending drain scan");
    for queue in queues {
        let Some(topic) = queue.strip_prefix(&prefix) else {
            continue;
        };
        let Ok(batch) = state.redis.pending_batch(&queue, 200).await else {
            continue;
        };
        for (msg_id, _offset) in batch {
            // An empty msg_id is the old pre-v0.15 topic offline enqueue format (the message was not yet persisted at enqueue time) and cannot be looked up → clear it
            if msg_id.is_empty() {
                let _ = state.redis.pending_remove(&queue, "").await;
                continue;
            }
            let Some(msg) = crate::store::pg::message_by_id(&state.db, &msg_id).await? else {
                let _ = state.redis.pending_remove(&queue, &msg_id).await;
                continue;
            };
            if !deliverable_status(&msg.status) {
                // Expired/dropped broadcasts are not redelivered (guards against "deleted is still being delivered", same as drain_device).
                let _ = state.redis.pending_remove(&queue, &msg_id).await;
                continue;
            }
            let env = lattice_core::Envelope {
                id: msg.id.clone(),
                r#type: msg.env_type.clone(),
                content_type: msg.content_type.clone().unwrap_or_default(),
                encoding: "utf8".into(),
                payload: msg.payload.clone().unwrap_or_default(),
                conv_id: msg.conv_id.clone(),
                seq: msg.seq as u64,
                sender: msg.sender.clone(),
                ttl_seconds: 0,
                ..Default::default()
            };
            let frame = Frame::new(WsCommand::Envelope, bytes::Bytes::from(env.encode_body()));
            if state.hub.send_to_device(user, device, frame) {
                sent += 1;
                let _ = state
                    .redis
                    .pending_remove(&queue, &msg_id)
                    .await;
                let _ = crate::store::pg::set_topic_offset(
                    &state.db,
                    user,
                    topic,
                    msg.seq as i64,
                )
                .await;
            } else {
                tracing::warn!(user, device, %queue, "topic pending drain: send_to_device=false");
                break; // Queue full/connection not in hub: retry on the next reconnect to avoid spinning
            }
        }
    }
    tracing::debug!(user, sent, "topic pending drain done");
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_budget_math() {
        // 200 msg/s → one every 5ms
        let limit = 200usize;
        let budget_ms = 1000 / limit.max(1);
        assert_eq!(budget_ms, 5);
        // Do not sleep when the rate limit is 0 (avoid division by zero)
        let limit0 = 0usize;
        assert_eq!(1000 / limit0.max(1), 1000);
    }

    #[test]
    fn retry_backoff_matches_doc_sequence() {
        // ② §4.2: 1/2/4/8/16s; beyond 5 attempts use the maximum window (the cap check actually runs before backoff)
        assert_eq!(retry_backoff_ms(0), 0);
        assert_eq!(retry_backoff_ms(1), 1_000);
        assert_eq!(retry_backoff_ms(2), 2_000);
        assert_eq!(retry_backoff_ms(3), 4_000);
        assert_eq!(retry_backoff_ms(4), 8_000);
        assert_eq!(retry_backoff_ms(5), 16_000);
        assert_eq!(retry_backoff_ms(9), 16_000);
    }

    #[test]
    fn only_persisted_messages_are_deliverable() {
        assert!(deliverable_status("persisted"));
        // §17.3 terminal states must not be redelivered ("deleted is still being delivered")
        assert!(!deliverable_status("expired"));
        assert!(!deliverable_status("dropped"));
        assert!(!deliverable_status("dlq"));
    }
}
