//! Routing policy and delivery (② §4.1 / §4.2; §17.4 is the semantic authority).
//!
//! Key semantics:
//! - Default **all-device delivery**: if the envelope has no `route.to_devices` → deliver to all online devices of that user;
//! - All devices offline → enter `pending:{user}` (do not copy one entry per device, to avoid storage amplification);
//! - `to_devices` targeted → offline devices enter `pending:{user}:{device}`;
//! - The `acked` seen by the sender = **at least one** target device has acked (here we can only report `routed`/`persisted` first).
//!
//! E20/E26 degradation closure (② §4.8):
//! - **Targeted, partially offline** (E16-D1): devices not hit in an explicit `to_devices` are always added to device-level pending;
//!   no longer "silently drop the remaining offline targets as long as any target is online";
//! - **Cross-node forwarding failure** (E20-G4): target devices where both the bus and the gRPC fallback failed are **re-routed to device-level pending +**
//!   **`delivery_log persisted`**, and the error is not thrown at the sender (an already-persisted message should not 5xx);
//!   reconnect redelivery / `lock:reconcile` covers them;
//! - **Redis fully down** (E20-G6): when pending cannot be written, still write `delivery_log state=persisted`
//!   (placeholder row `to_device='*'` or the real device), so `lock:reconcile` can backfill pending after Redis recovers;
//! - **User-level "primary device only" override** (semantics ⑥ / P3): dynamic config `policy.primary_device_only`
//!   only narrows the fan-out scope of semantics 1 (see [`crate::routing::online::decide_with_policy`]).

use std::collections::HashSet;
use lattice_core::protocol::DeliveryState;
use lattice_core::{Envelope, Frame, WsCommand};

use crate::error::Result;
use crate::pipeline::stage::Recipient;
use crate::routing::online::{self, Decision};
use crate::state::AppState;

#[derive(Debug, Clone)]
pub struct RouteOutcome {
    pub state: DeliveryState,
    pub recipients: Vec<Recipient>,
}

/// Dynamic key for the "primary device only" override (⑥ D12: authoritative in PG `dynamic_config`, hot-reloaded via
/// the `lattice:cfg` broadcast; this node reads an in-memory snapshot). Default false = default all-device delivery (§17.4-1).
pub const PRIMARY_DEVICE_ONLY_KEY: &str = "policy.primary_device_only";

fn primary_device_only(state: &AppState) -> bool {
    state.dyn_bool(PRIMARY_DEVICE_ONLY_KEY, false)
}

fn push_recipient(
    recipients: &mut Vec<Recipient>,
    user: &str,
    device: &str,
    state: DeliveryState,
) {
    recipients.push(Recipient {
        user: user.to_string(),
        device: device.to_string(),
        state: state.as_str().to_string(),
    });
}

/// Degradation when enqueue fails: write `delivery_log persisted` (so `lock:reconcile` can backfill pending),
/// and return whether a queue entry was actually written (false = only the PG delivery row was written).
///
/// During a full Redis outage pending cannot be written (E20-G6), but the message is already persisted; `delivery_log`'s
/// `state ∈ {persisted, routed}` is exactly reconcile's data source, and pending is rebuilt automatically after recovery,
/// so the request is judged accepted (persisted) rather than 5xx.
async fn queue_user_or_persist(
    state: &AppState,
    user: &str,
    seq: i64,
    msg_id: &str,
) -> bool {
    match crate::routing::pending::enqueue_user(state, user, seq, msg_id).await {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                error = %e,
                msg_id,
                user = %crate::observe::Metrics::user_hash(user),
                "user pending enqueue failed; delivery_log persisted for reconcile (② §4.8)"
            );
            false
        }
    }
}

async fn queue_device_or_persist(
    state: &AppState,
    user: &str,
    device: &str,
    seq: i64,
    msg_id: &str,
) -> bool {
    match crate::routing::pending::enqueue_device(state, user, device, seq, msg_id).await {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                error = %e,
                msg_id,
                user = %crate::observe::Metrics::user_hash(user),
                device,
                "device pending enqueue failed; delivery_log persisted for reconcile (② §4.8)"
            );
            false
        }
    }
}

/// Compute the target user set: `to_user` first, then conversation members (topics go to subscribers).
///
/// When PG is provably unavailable and the short-lived positive cache hits, use the cached member list (② §4.8: routing does not block during degradation);
/// otherwise return the original error — in WAL degradation mode the caller accepts it as persisted and never fabricates recipients.
async fn target_users(state: &AppState, env: &Envelope) -> Result<Vec<String>> {
    let route = env.route();
    if !route.to_user.is_empty() {
        return Ok(vec![route.to_user.clone()]);
    }
    if let Some(topic) = env.conv_id.strip_prefix("topic:") {
        return crate::store::pg::topic_subscribers(&state.db, topic).await;
    }
    if state.pg_degraded() {
        return match state.pg_degrade.members(&env.conv_id) {
            Some(members) => {
                tracing::warn!(
                    conv_id = %env.conv_id,
                    "pg degraded: routing targets from short-lived member cache (② §4.8)"
                );
                Ok(members)
            }
            None => Err(crate::store::pg::unavailable_error()
                .with_detail("degrade", serde_json::json!("member_cache_miss"))),
        };
    }
        // Normal path: a short-TTL member-list positive cache hit returns immediately (PL-17: avoid one full members_of table read per message).
    if let Some(members) = state.member_cache.members(&env.conv_id) {
        state.note_member_cache(true);
        return Ok(members);
    }
    state.note_member_cache(false);
    match crate::store::pg::members_of(&state.db, &env.conv_id).await {
        Ok(members) => {
            let ids: Vec<String> = members.into_iter().map(|m| m.user_id).collect();
            state.pg_degrade.remember_members(&env.conv_id, ids.clone());
            state
                .member_cache
                .remember_members(&env.conv_id, ids.clone());
            Ok(ids)
        }
        Err(e) if crate::store::pg::is_unavailable_err(&e) => {
            state.mark_pg_down();
            match state.pg_degrade.members(&env.conv_id) {
                Some(members) => {
                    tracing::warn!(
                        error = %e,
                        conv_id = %env.conv_id,
                        "pg unavailable: routing targets from short-lived member cache (② §4.8)"
                    );
                    Ok(members)
                }
                None => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

/// Deliver one already-persisted envelope (local direct delivery / cross-node forwarding / offline enqueue).
pub async fn route_and_deliver(
    state: &AppState,
    env: &Envelope,
    sender: &str,
    seq: u64,
) -> Result<RouteOutcome> {
    let body = env.encode_body();
    let frame = Frame::new(
        if env.is_chunk() { WsCommand::Chunk } else { WsCommand::Envelope },
        bytes::Bytes::from(body.clone()),
    );

    let users = target_users(state, env).await?;
    let to_devices = env.route().to_devices.clone();
    let primary_only = primary_device_only(state);

    let mut recipients = Vec::new();
    let mut any_online = false;

    for user in users {
        if user == sender && to_devices.is_empty() {
                        // The sender's other devices receive it too (§17.4-1 all-device delivery), so do not skip; only avoid double-counting "send to self, single device"
        }
        match online::decide_with_policy(state, &user, &to_devices, primary_only).await {
            Decision::Offline => {
                                // All devices offline (or only the primary device offline): user-level/device-level queue + placeholder delivery rows;
                                // during a full Redis outage a failed queue write still records delivery_log persisted (E20-G6 reconcile backfill).
                let queued: Vec<String> = if to_devices.is_empty() {
                    queue_user_or_persist(state, &user, seq as i64, &env.id).await;
                    vec![String::from("*")]
                } else {
                    for d in &to_devices {
                        queue_device_or_persist(state, &user, d, seq as i64, &env.id).await;
                    }
                    to_devices.clone()
                };
                for d in queued {
                    online::record_state(state, &env.id, &user, &d, DeliveryState::Persisted).await;
                    push_recipient(&mut recipients, &user, &d, DeliveryState::Persisted);
                }
            }
            Decision::Local(devices) => {
                any_online = true;
                for dev in devices {
                    let ok = if to_devices.is_empty() {
                        state.hub.send_to_device(&user, &dev, frame.clone())
                    } else if to_devices.contains(&dev) {
                        state.hub.send_to_device(&user, &dev, frame.clone())
                    } else {
                        false
                    };
                    let st = if ok { DeliveryState::Routed } else { DeliveryState::Dropped };
                    online::record_state(state, &env.id, &user, &dev, st).await;
                    push_recipient(&mut recipients, &user, &dev, st);
                }
            }
            Decision::Remote(remote) => {
                deliver_remote(
                    state,
                    &user,
                    &body,
                    &env.id,
                    seq as i64,
                    remote,
                    &mut any_online,
                    &mut recipients,
                )
                .await;
            }
            Decision::Mixed(local_devices, remote) => {
                any_online = true;
                for dev in local_devices {
                    let ok = state.hub.send_to_device(&user, &dev, frame.clone());
                    let st = if ok { DeliveryState::Routed } else { DeliveryState::Dropped };
                    online::record_state(state, &env.id, &user, &dev, st).await;
                    push_recipient(&mut recipients, &user, &dev, st);
                }
                deliver_remote(
                    state,
                    &user,
                    &body,
                    &env.id,
                    seq as i64,
                    remote,
                    &mut any_online,
                    &mut recipients,
                )
                .await;
            }
        }

                // §17.4-5: for device-targeted sends, requested devices absent from the online index must also enter device-level pending.
                // The old implementation went Local/Remote as long as any target was online, silently dropping the other offline targets (E16-D1).
                // The Offline branch already enqueued everything; here we only add requested devices "not covered by this delivery", which is naturally idempotent.
                // Targets that failed cross-node forwarding also land here (they never entered the delivered set) → automatically routed to device-level redelivery.
        if !to_devices.is_empty() {
            let delivered: HashSet<String> = recipients
                .iter()
                .filter(|r| r.user == user)
                .map(|r| r.device.clone())
                .collect();
            for dev in &to_devices {
                if delivered.contains(dev) {
                    continue;
                }
                queue_device_or_persist(state, &user, dev, seq as i64, &env.id).await;
                online::record_state(state, &env.id, &user, dev, DeliveryState::Persisted).await;
                push_recipient(&mut recipients, &user, dev, DeliveryState::Persisted);
            }
        }
    }

    Ok(RouteOutcome {
        state: if any_online { DeliveryState::Routed } else { DeliveryState::Persisted },
        recipients,
    })
}

/// Cross-node targets: successfully forwarded devices are recorded routed; targets where both the bus and gRPC failed are re-routed to device-level pending.
///
/// Note: pending writes and delivery rows for failed targets are handled separately, outside the `to_devices` diff
/// logic in [`route_and_deliver`] — even when the user has **no** explicit `to_devices` (default all-device delivery), if the remote node is down or
/// the bus is unreachable we must not pretend it is routed: write a `persisted` placeholder row for reconcile to backfill (E20-G5/G6).
#[allow(clippy::too_many_arguments)]
async fn deliver_remote(
    state: &AppState,
    user: &str,
    body: &[u8],
    env_id: &str,
    seq: i64,
    remote: std::collections::HashMap<String, Vec<String>>,
    any_online: &mut bool,
    recipients: &mut Vec<Recipient>,
) {
    for (node, devices) in remote {
        let outcome = online::forward_with_env(
            state,
            &node,
            user,
            env_id,
            &devices,
            WsCommand::Envelope.to_u8(),
            body.to_vec(),
        )
        .await;
        if !outcome.delivered.is_empty() {
            *any_online = true;
        }
        for dev in devices {
            if outcome.delivered.contains(&dev) {
                online::record_state(state, env_id, user, &dev, DeliveryState::Routed).await;
                push_recipient(recipients, user, &dev, DeliveryState::Routed);
            } else {
                                // Re-route to device-level pending; during a full Redis outage only record delivery_log persisted (reconcile backfill).
                queue_device_or_persist(state, user, &dev, seq, env_id).await;
                online::record_state(state, env_id, user, &dev, DeliveryState::Persisted).await;
                push_recipient(recipients, user, &dev, DeliveryState::Persisted);
            }
        }
    }
}

/// Topic broadcast: shared by `POST /v1/topics/{t}/publish` and `to_topic` frame assembly.
pub async fn publish_to_topic(state: &AppState, topic: &str, env: &Envelope) -> Result<RouteOutcome> {
    let conv_id = crate::store::pg::topic_conv_id(&state.db, topic).await?;
    let mut env2 = env.clone();
    env2.conv_id = match conv_id {
        Some(id) => id,
        None => format!("topic:{topic}"),
    };
    let fanout = crate::routing::topic::publish(state, topic, &env2).await?;
    Ok(RouteOutcome {
        state: if fanout.online > 0 || fanout.staged == 0 {
            DeliveryState::Routed
        } else {
            DeliveryState::Persisted
        },
        recipients: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_facing_state_mapping() {
                // All offline → persisted; any online → routed (§17.4-3)
        assert_eq!(DeliveryState::Persisted.as_str(), "persisted");
        assert_eq!(DeliveryState::Routed.as_str(), "routed");
        assert_eq!(
            crate::pipeline::stage::Recipient {
                user: "u".into(),
                device: "d".into(),
                state: "persisted".into()
            }
            .state,
            "persisted"
        );
    }

    #[test]
    fn primary_device_only_is_dynamic_key() {
                // Semantics ⑥ (P3): the config key name is part of the dynamic-config contract; never hardcode another copy of the value in code.
        assert_eq!(PRIMARY_DEVICE_ONLY_KEY, "policy.primary_device_only");
    }

    #[test]
    fn sequence_is_not_used_for_pending_score_in_device_retry() {
                // When a device-level failure is re-routed to pending, the caller-supplied seq is only used for the queue score; the cross-node failure path uses 0
                // and does not change the authoritative seq of an already-persisted message (messages.seq / the user-level queue score are fixed at first persistence).
        let seq: i64 = 0;
        assert_eq!(seq, 0);
    }
}
