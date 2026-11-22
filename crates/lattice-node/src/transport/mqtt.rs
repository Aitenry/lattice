//! MQTT gateway (P3, ⑤ §11 / ② §3.4): a **minimal usable subset** of MQTT 3.1.1 (protocol level 4) and MQTT 5 (level 5).
//!
//! Mapping rules (⑤ §11, must not be deviated from):
//! - Topic: `lattice/{topic}/{device}` ↔ Lattice `Topic` (the device segment must equal the connected device; the topic path
//!   may contain `/` to form levels for wildcard matching; `$share` follows shared-subscription semantics, see below);
//! - Payload → envelope: `type=custom:iot`, `encoding=raw` by default; when the MQTT 5 `Content-Type` property is present, map by MIME
//!   (allowlisted properties: `Content-Type` / `Correlation-Data` / `User-Property` with the `lx-` prefix; everything else is dropped, ⑤ I5);
//! - Inbound: build an `Envelope` → [`crate::routing::topic::publish`] (reusing the existing topic fan-out/offline queue) →
//!   then PUBLISH the same envelope bytes to the Redis channel [`lattice_core::keys::channel_mqtt`] (cross-node realtime downlink);
//! - Outbound: one Redis pubsub task per subscription, with messages multiplexed via mpsc onto this connection's write socket;
//! - Auth: PSK token (the `CONNECT` password is the refresh token, matching `devices.token_hash`);
//! - QoS1 is at-least-once; QoS2 is unsupported (it duplicates effectively-once, so it is rejected);
//! - 10 msg/s per device (per connection) (design §17.13); over the limit: MQTT 5 `0x97 Quota exceeded` / 3.1.1 disconnect.
//!
//! ## Reliability semantics (completed in PL-11; the implementation is the contract — do not read this as full MQTT semantics)
//!
//! - **Inbound persistence**: PUBLISH → a valid `Envelope` (`type=custom:iot`/`encoding=raw`, mapped via MIME when MQTT 5
//!   `Content-Type` is present) → the same `pipeline::ingest` path as WS `envelope` frames
//!   (`messages`/`seq`/`message_dedup`/routing all apply) → **PUBACK is sent only after persistence succeeds**.
//!   On failure, MQTT 5 QoS1 replies a failure reason (e.g. `0x97`/`0x80`, mapping in `ingest_failure_reason`);
//!   MQTT 3.1.1 has no failure reason (no ACK, disconnect directly; the client reconnects and retries, and dedup absorbs duplicates).
//!   Inbound QoS1 **retransmission on the same connection** (same packet id + DUP=1 + same payload) reuses the envelope id allocated first,
//!   so `pipeline`'s `message_dedup` dedups it (no separate dedup layer, PL-11 §6);
//! - **Publish implies subscribe**: `pipeline::ingest` requires conversation membership; MQTT devices have no separate publish ACL, so
//!   the first publish to a topic idempotently adds `routing::topic::subscribe` (equivalent to SUBSCRIBE first,
//!   granting no more permission than SUBSCRIBE), then caches it for the connection (topic → conv_id);
//! - **QoS1 outbound retransmission**: each outbound PUBLISH gets a packet id (1..=65535 cyclically; 0 is invalid) and enters the
//!   pending map; PUBACK clears it; on timeout (`[mqtt] retransmit_ms`, 10s by default) it is resent with DUP=1,
//!   at most `max_retransmits` (default 3) times, and the connection is closed over the limit, counting
//!   `lattice_mqtt_publish_retransmit_total{result=exhausted}`;
//! - **clean session semantics**: CONNACK `session_present=0`, no persistent session; the pending map is destroyed with the
//!   connection (reconnect clears pending), and the client resends unacknowledged uplinks at-least-once after reconnecting;
//! - **Offline pending redelivery**: after a successful SUBSCRIBE in an MQTT session (i.e. at subscribe time after CONNECT;
//!   SUBACK first, then redelivery, to avoid sending PUBLISH to a client that "has not locally subscribed yet"), consume
//!   `pending:{user}:topic:*` for that topic: delivered in ascending offset/seq order at 10 msg/s per device,
//!   and **only dequeued and `topic_offsets` advanced after PUBACK** (at-least-once; entries unacknowledged at disconnect
//!   stay in the queue and are redelivered on the next reconnect, duplicating at most one message). Subscriptions granted QoS0 are delivered at QoS0 (no ACK;
//!   the watermark advances immediately after enqueueing = at-most-once, as the MQTT protocol itself defines).
//!
//! ## QoS2 / persistent sessions / WILL / retained (the rest of PL-11; the implementation is the contract)
//!
//! - **Inbound QoS2** (3.1.1 and 5): on PUBLISH(QoS2) → stash the packet by packet id (a repeated PUBLISH with the same packet id
//!   only replies PUBREC, without re-persisting or re-looping) → reply PUBREC. Only after PUBREL does it go through
//!   `pipeline::ingest` to persist (**PUBCOMP is sent only after persistence succeeds**; a repeated PUBREL that hits a "completed" record
//!   only replies PUBCOMP without persisting again). Stashed entries are persisted with the session when clean=false (so a reconnect can still
//!   complete delivery with PUBREL); the entry cap is [`INBOUND_QOS2_CAP`], and exceeding it closes the connection.
//!   Failure semantics: MQTT 5 cannot reply a failure reason at the PUBREL stage (PUBCOMP only has 0x00/0x92), so a persistence
//!   failure is handled as a connection-level error (unfinished entries stay in the session; MQTT 5 replies DISCONNECT then closes, 3.1.1
//!   just closes), and the client can resend PUBREL after reconnecting; **PUBCOMP is never sent without persistence**.
//! - **Outbound QoS2**: after allocating a packet id the write task sends PUBLISH → receives PUBREC → sends PUBREL → receives PUBCOMP and cleans up;
//!   a timeout before PUBREC resends PUBLISH(DUP=1), and a timeout after PUBREL resends PUBREL; the retransmission cap follows the QoS1
//!   config. With clean=false, unfinished outbound QoS2 is persisted with the session, and after reconnect the original packet id is resent with DUP=1
//!   as PUBLISH (or PUBREL is resent). A PUBREC for an unknown packet id (MQTT 5) replies PUBREL(0x92) and counts
//!   `lattice_mqtt_qos2_total{phase=error}`.
//! - **Persistent session**: with clean_session=false (3.1.1) or MQTT 5 Session Expiry Interval > 0, the
//!   **subscription table / inbound QoS2 stash / offline topic redelivery watermark / outbound QoS2 pending** are written to Redis
//!   (key layout in [`session_state_key`]/[`session_outbound_key`], with TTL
//!   `[mqtt] session_ttl_secs`, 3600s by default; for MQTT 5 the CONNECT/DISCONNECT Session Expiry
//!   Interval wins and is clamped to `[mqtt] session_expiry_max_secs`). On reconnect with `session_present=1`,
//!   subscriptions are restored and the topic queue is redelivered after CONNACK; clean=true (MQTT 5 clean_start=1) deletes the old session
//!   at CONNECT (`lattice_mqtt_session_total{result=cleaned}`). When Redis is unavailable or
//!   `session_ttl_secs=0`, it degrades to no persistent session (`session_present` always 0) without affecting existing QoS0/1 behavior.
//! - **WILL**: the CONNECT will topic/payload/qos/retain (including MQTT 5 Will Delay / Content-Type)
//!   is saved with the connection; on an **abnormal disconnect** (IO break, keepalive timeout, protocol error, server-side close — anything but DISCONNECT)
//!   it is published through the same `pipeline::ingest` pipeline (counted in the existing topic fan-out/realtime loop), and not on a normal DISCONNECT;
//!   MQTT 5 `DISCONNECT(reason=0x04)` (Disconnect with Will Message) does publish it. When Will Delay>0 publication is delayed
//!   and cancelled on a **reconnect with the same client_id** via the `lattice:mqtt:will:*` marker (minimal implementation).
//! - **retained**: after publishing retain=1 and persisting successfully, one entry is saved per `lattice/{topic}/{device}` (Redis
//!   `lattice:mqtt:retained:*`, TTL `[mqtt] retained_ttl_secs`, 30 days by default); a retain=1 publish with an empty payload
//!   deletes that entry. A subscription (including after SUBACK) returns the one retained message matching that filter (retain flag
//!   set to 1, QoS=min(retained qos, granted qos)); **session restore does not resend retained** (MQTT semantics: sent only on
//!   a new subscription). A wildcard subscription returns **all** matching retained messages (one per topic), see the next section.
//!
//! ## Wildcards / shared subscriptions / Topic Alias (PL-11 continued; the implementation is the contract)
//!
//! - **Topic namespace**: publishing still uses `lattice/{topic}/{device}` (the device segment = the connected device, the last segment;
//!   the topic path **may contain `/` to form levels**, e.g. `lattice/site/a/temp/{device}` → Lattice Topic
//!   `site/a/temp`). The old behavior for single-segment topics is completely unchanged. `matches(filter, topic)` is a pure function of MQTT 4.7
//!   semantics (`+` one level, `#` multi-level and must be last, a topic starting with `$` is not matched by `#`/`+`).
//! - **Wildcard subscription**: when the SUBSCRIBE filter contains `+`/`#`, it is validated per MQTT filter syntax (`#` only at the end
//!   and on its own level, `+` must occupy a whole level, length ≤65535, no NUL; invalid → SUBACK `0x8F`). A filter
//!   is matched against the **Lattice topic path**: an optional `lattice/` prefix is stripped (`lattice/site/#`
//!   is equivalent to `site/#`), and `t`/`#` match by level. The device dimension is implicit for subscriptions (the downlink topic is always
//!   `lattice/{matched topic}/{this connection's device}`), so there is no cross-device privilege escalation. After a successful subscription, Redis is used to
//!   `PSUBSCRIBE lattice:mqtt:<literal prefix>*` to receive candidate messages, which are then precisely re-filtered with `matches()`;
//!   wildcard subscriptions **do not** write `routing::topic::subscribe` (no concrete topic, so no PG membership row) and
//!   **do not** perform offline pending redelivery (online realtime semantics; rebuilt when the session is restored). Retained rules:
//!   when multiple filters of the same client match the same message, it is delivered only once (Redis messages are deduped by envelope id within a window),
//!   and the QoS is the **maximum** of the values granted by all matching filters (MQTT 3.1.1 §3.8.4 overlapping-subscription convention).
//! - **Shared subscription** `$share/{group}/{filter}`: the group contains no `/`/`+`/`#`, and the inner filter must be a legal wildcard filter
//!   containing `+`/`#` (shared subscriptions on exact filters are unimplemented, SUBACK `0x8F` — preserving the existing
//!   smoke contract); within a group, **each matching message goes to only one active subscriber** (in-process round robin; `try_send` before sending,
//!   members whose connection is closed are removed, members with a full/stuck queue are skipped and the next one is tried, and if all are unavailable the message is dropped and counted as
//!   `lattice_mqtt_shared_total{result=skipped}`); different groups each receive it once. `$share` does not participate in
//!   normal filter matching (`#` does not match a `$share/...` subscription itself, and the publish side does not allow `$` topics).
//!   **Cross-node boundary**: the round-robin state lives in the node process (each node picks one local member), not a cluster-wide single delivery;
//!   cluster-wide single delivery would need a shared coordinator (not done). Shared subscriptions do not send retained (subscribing only sets up the group round robin).
//! - **retained wildcards**: when the subscription contains `+`/`#`, SCAN `lattice:mqtt:retained:*` and for each matching
//!   Lattice topic deliver its retained message once (with multiple publishers on the same topic, take the one with the latest `stored_at`)
//!   (retain=1, QoS=min(retained, granted)); sent after SUBACK; overlapping filters within the same SUBSCRIBE
//!   send the same retained topic only once. Publishing an empty payload (retain=1) still deletes that entry.
//! - **Topic Alias (MQTT 5)**: when the client CONNECT declares `Topic Alias Maximum`, CONNACK uses the property
//!   `Topic Alias Maximum(0x22)` to fill in `[mqtt] topic_alias_max` (default 16, 0 = not accepted; older clients that do not declare it
//!   keep the 3-byte CONNACK shape); the client declaration in CONNECT is also parsed and saved for the negotiation record. The inbound PUBLISH `Topic Alias(0x23)` property supports two uses:
//!   non-empty topic + alias = create/update the session-level mapping (`alias_total{result=set}`), empty topic + alias =
//!   use the mapping (`used`, MQTT 5 §3.3.2.3.4). All errors are MQTT 5 `DISCONNECT(0x94 Topic Alias
//!   invalid)` followed by a disconnect: alias=0, alias > the declared cap, using an unknown alias with an empty topic, or an alias already mapped to
//!   another non-empty topic (this gateway is strict: "one alias maps to exactly one topic"). 3.1.1 has no property block and is
//!   completely unaffected. The mapping is cleaned up on disconnect (not restored with a persistent session — MQTT 5 semantics: aliases are Network
//!   Connection scoped).
//!
//! ## MQTT 5 flow control / Subscription Identifier / outbound Topic Alias (the rest of PL-11; the implementation is the contract)
//!
//! - **Receive Maximum (outbound → client)**: the CONNECT `Receive Maximum(0x21)` (default 65535,
//!   **0 is invalid** → CONNACK `0x82 Protocol Error` rejects the connection) is the client's allowance for server→client
//!   QoS1/2 in-flight PUBLISH messages. The write task uses the pending map size as the in-flight count (released only on PUBACK, PUBCOMP,
//!   or a failed PUBREC); when the limit is reached, that PUBLISH enters a **connection-level bounded FIFO queue**
//!   ([`OUTBOUND_RECEIVE_QUEUE`]; QoS0 also queues when the queue is non-empty, to preserve ordering), and is sent in order once an ACK releases capacity;
//!   queue overflow (the client does not ACK/consume for a long time) → close the connection (`receive_max_total{throttled}` already counted).
//!   Counting: `lattice_mqtt_receive_max_total{result=allowed|throttled|violation}`.
//! - **Receive Maximum (inbound ← client)**: the server fills 0x21 in CONNACK with
//!   `[mqtt] receive_maximum` (default 32; 0 = fill 65535). **Compatibility rule**: it fills it only when the client CONNECT
//!   itself also declares Receive Maximum (when undeclared, omit it = MQTT 5 default 65535, keeping the existing
//!   smoke/E2E CONNACK shape contract); while filling it, the client's inbound QoS1/2 in-flight count is validated
//!   (QoS2 counts as "PUBREC replied, PUBREL not yet persisted"; a repeated PUBLISH does not take quota twice); over the limit →
//!   `DISCONNECT(0x93 Receive Maximum exceeded)` and disconnect, counting `violation`.
//! - **Subscription Identifier (MQTT 5)**: the SUBSCRIBE `Subscription Identifier(0x0B)` property is a
//!   variable-length integer 1..=268435455 (0 / repeated within one SUBSCRIBE → protocol error, MQTT 5 replies DISCONNECT 0x82;
//!   3.1.1 has no property block and ignores it). All filters within one SUBSCRIBE share that id, but **each subscription stores it separately**:
//!   outbound PUBLISH carries the identifiers of **all matching subscriptions** (deduped + ascending, multiple 0x0B properties);
//!   when overlapping filters dedup a delivery, ids are aggregated over the full matching set as well. A clean session clears it with the connection; for clean=false /
//!   MQTT 5 Session Expiry persistent sessions the id is persisted with the subscription table (and unfinished outbound QoS2 packets),
//!   and keeps being carried after reconnect and subscription restore. retained / offline-redelivered PUBLISH messages also carry the corresponding subscription's id.
//!   Counting: `lattice_mqtt_sub_id_total` (number of subscriptions granted successfully with an identifier).
//! - **Outbound Topic Alias**: enabled when `[mqtt] outbound_topic_alias=true` (default) + the client CONNECT
//!   `Topic Alias Maximum > 0` (per connection, connection-scoped; client cap = 0 or the switch off → no compression).
//!   The first occurrence of a downlink topic creates the mapping (`out_alias_total{result=set}`) and carries the full topic + alias;
//!   subsequent occurrences of the same topic use **empty topic + alias** (`used`); aliases are allocated in order 1..=the client cap,
//!   and once the space is full new topics are no longer compressed (old mappings still work), with no LRU replacement. Cleared on disconnect, not across persistent sessions.
//!   When the client cap = 0 or the switch is off, every downlink PUBLISH counts `disabled`.
//!
//! ## Explicitly unimplemented boundaries (do not conclude support from this)
//!
//! - Session persistence is in Redis only (short TTL, not a WAL): if Redis loses/expires it there is no session, and **no cluster session migration** is done;
//! - Inbound QoS2 persists only at PUBREL ("stash then delayed delivery"), not "persist on PUBLISH";
//! - Offline redelivery consumes only the **topic-level queue** `pending:{user}:topic:*` (the PL-11 11.11 convention).
//!   After MQTT inbound is routed through `pipeline::ingest`, offline receivers land in the user-level/device-level queues
//!   `pending:{user}` / `pending:{user}:{device}` (the same policy as WS uplinks), consumed when that user's WS devices come online;
//!   the user-level queue of an MQTT-only receiver is outside this gateway's redelivery scope (a known boundary, see ② §3.4).
//!   The inbound path **no longer calls** the old `routing::topic::publish`, so it does not write the same message into the topic-level queue
//!   as a duplicate pending entry (offline enqueue happens only in `pipeline::ingest`); the topic-level queue is written only by
//!   the broadcast path of `POST /v1/topics/{t}/publish`;
//! - When multiple MQTT devices of the same user subscribe to the same topic concurrently, each device gets its own batch of pending messages
//!   it read (no cross-device redelivery mutex): at-least-once allows duplicates and the monotonically advancing offset loses nothing;
//! - Wildcard/shared subscriptions have **online realtime** semantics: they create no PG topic membership and neither write nor read the topic-level pending
//!   queue (no history redelivery on reconnect), and a restored session only rebuilds subscriptions without resending retained;
//! - Shared subscriptions support only inner filters **containing wildcards** (`$share/{group}/a/#`); shared subscriptions on an exact topic
//!   are unimplemented (SUBACK `0x8F`, preserving the existing smoke contract); the in-group round robin is **in-process** state (with multiple nodes,
//!   each node delivers to one local member; cluster-wide "single delivery" is not done); retained delivery for `$share` is unsupported;
//! - Topic Alias caps/mappings apply only to a **single Network Connection**: no cross-session/cluster alias recovery;
//!   outbound aliases have no LRU replacement (new topics are not compressed once the space is full);
//! - Receive Maximum outbound queueing lives only in write-task memory (lost on disconnect, not stored in Redis); inbound validation applies only to connections
//!   whose CONNACK really declared 0x21 (otherwise MQTT 5's default 65535 is assumed, keeping only the
//!   [`INBOUND_QOS2_CAP`] defensive cap);
//! - The Subscription Identifier variable-length integer cap is 268435455 (a varint over 4 bytes is a protocol error);
//!   in outbound PUBLISH properties the identifier is ascending and Topic Alias follows it (a fixed order helps assertions/retransmission reproduction);
//! - retained has only a single Redis entry (no WAL/cluster sync); it disappears when the retained TTL expires;
//! - logs never print payload/cert/private keys (only lengths/topic/id/identity hashes).
//!
//! ## TLS listener + client certificates (mTLS/X.509 identity, completed in PL-11)
//!
//! - **Configuration**: when `[mqtt] tls_enabled=true`, an extra listener is bound on `tls_bind` (default `0.0.0.0:8883`),
//!   `tls_cert`/`tls_key` are the server certificate chain/private key PEM, and `client_ca` is the client certificate trust anchor.
//!   **Off by default**: the plaintext `bind` (dev 1883) behavior is completely unchanged; TLS and plaintext are two independent listeners,
//!   and a TLS load/bind failure only WARNs, while the node stays ready and the plaintext gateway keeps working (② §7.2).
//! - **Protocol**: tokio-rustls/rustls (ring provider; TLS1.2/1.3), with ALPN advertising `mqtt`.
//!   With `require_client_cert=true` (default), `WebPkiClientVerifier` enforces client certificate chain validation
//!   (trust anchor = `client_ca`; no certificate/bad chain/expired/wrong CA disconnect at the handshake stage and count
//!   `lattice_mqtt_tls_auth_total{result=no_cert|bad_cert}`); with `false`, connections without a client certificate are allowed
//!   and fall back to the original PSK/JWT semantics, but **a presented certificate is still validated against `client_ca`** (bad certificates are still rejected).
//! - **X.509 identity mapping**: extract from the client certificate SAN URI/email (preferred) or Subject CN
//!   `lattice://user/<id>/device/<id>` or `<user>@<device>` (a CN may also contain only the device id;
//!   the user is then looked up in PG); then validate against PG: user/device exist, the device belongs to that user, the device is not revoked,
//!   and the user is active. Any step failing disconnects and counts `device_mismatch`/`unknown_identity`.
//! - **Anti-impersonation**: after certificate identity auth succeeds, the MQTT `CONNECT` username must match the certificate identity
//!   (device id / user id / username / `<user>@<device>`), otherwise disconnect and count `device_mismatch`;
//!   the certificate path **does not use** the CONNECT password as a credential (the certificate is the credential). The plaintext path **does not enable** certificate identity,
//!   and the original JWT/PSK semantics are unchanged.
//! - **Metrics**: `lattice_mqtt_tls_connections_total{result=ok|fail}` (TLS handshake result),
//!   `lattice_mqtt_tls_auth_total{result=ok|no_cert|bad_cert|unknown_identity|device_mismatch}`.
//! - **Still not done**: certificate revocation lists (CRL/OCSP; currently only PG device.revoked_at), hot certificate rotation
//!   (changing the certificate requires a node restart), topic ACL restriction by certificate SAN (still device-scoped), MQTT 5
//!   cluster session migration (sessions live only in a single node's Redis).
//!
//! Resource and failure semantics: one tokio task per connection; keepalive = 1.5× the client-declared value (0 means never disconnect);
//! connections ≤ `cfg.mqtt.max_connections` (0 = unlimited; plaintext/TLS are counted separately); any protocol/IO/dependency error
//! only warns and closes that connection, a listen failure only warns, and **node startup is never blocked** (② §7.2).

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;

// TLS/mTLS (PL-11): rustls is reused via tokio-rustls (same rustls version, ring provider).
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

use lattice_core::keys;
use lattice_core::protocol::ErrorCode;
use lattice_core::Envelope;

use crate::error::{LatticeError, Result as LatticeResult};
use crate::state::AppState;
use crate::store::redis::LocalBucket;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Device-level rate limit (§17.13: MQTT 10 msg/s per device).
pub const DEVICE_MSG_PER_SEC: u32 = 10;
/// MQTT 5 Quota exceeded reason code.
pub const REASON_QUOTA_EXCEEDED: u8 = 0x97;
/// MQTT 5 Receive Maximum exceeded (the client's inbound in-flight count exceeds the server CONNACK limit).
pub const REASON_RECEIVE_MAXIMUM_EXCEEDED: u8 = 0x93;
/// Production listen port (TLS, terminated by a front proxy); dev uses 1883 plaintext (the `mqtt.bind` config wins).
pub const LISTEN_PORT: u16 = 8883;

/// Single-packet cap 1MiB: matching the inline envelope threshold, so one connection cannot hog memory (§17.13 backpressure rationale).
pub const MAX_PACKET_BYTES: usize = 1024 * 1024;
/// CONNECT must arrive within 10s (preventing slow handshakes from holding resources).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The TLS handshake must complete within 10s (preventing slow TLS handshakes from holding connection quota for long; same convention as CONNECT_TIMEOUT).
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// TLS ALPN protocol name (⑤ §11: the ALPN for MQTT over TLS is fixed to `mqtt`).
pub const TLS_ALPN: &[u8] = b"mqtt";
/// Downlink queue capacity per connection.
const OUT_QUEUE: usize = 256;
/// Window to wait for the write task to flush on disconnect.
const WRITER_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

// ---- QoS1/QoS2 reliability (PL-11) -----------------------------------------

/// Default retransmission timeout when an outbound QoS1/QoS2 misses PUBACK/PUBREC (`[mqtt] retransmit_ms` can override).
pub const DEFAULT_RETRANSMIT_MS: u64 = 10_000;
/// Default maximum retransmissions for outbound QoS1/QoS2 (the connection is closed once reached); `[mqtt] max_retransmits` can override.
pub const DEFAULT_MAX_RETRANSMITS: u32 = 3;
/// Default rate limit for offline pending redelivery (msg/s per device); `[mqtt] replay_rate_per_sec` can override.
pub const DEFAULT_REPLAY_RATE_PER_SEC: u32 = 10;
/// Default TTL for persistent sessions (seconds); `[mqtt] session_ttl_secs` can override; 0 = session persistence off.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 3_600;
/// Default cap for the MQTT 5 Session Expiry Interval (seconds); `[mqtt] session_expiry_max_secs` can override.
pub const DEFAULT_SESSION_EXPIRY_MAX_SECS: u64 = 86_400;
/// Default TTL for retained messages (seconds); `[mqtt] retained_ttl_secs` can override (a 30-day leak guard).
pub const DEFAULT_RETAINED_TTL_SECS: u64 = 30 * 24 * 3_600;
/// Default MQTT 5 Topic Alias cap (`[mqtt] topic_alias_max` can override; 0 = do not accept aliases).
pub const DEFAULT_TOPIC_ALIAS_MAX: u16 = 16;
/// Default MQTT 5 server Receive Maximum (`[mqtt] receive_maximum` can override).
///
/// The CONNACK 0x21 property value is capped at u16; a config of 0 means fill the MQTT 5 default 65535 (unlimited).
pub const DEFAULT_RECEIVE_MAXIMUM: u16 = 32;
/// MQTT 5 default Receive Maximum (property default = 65535).
pub const MAX_RECEIVE_MAXIMUM: u16 = u16::MAX;
/// MQTT 5 Subscription Identifier cap (the maximum value a variable-length integer allows, MQTT 5 §3.8.2.1.2).
pub const MAX_SUBSCRIPTION_ID: u32 = 268_435_455;
/// Bounded queueing capacity for outbound Receive Maximum: once the client's Receive Maximum is used up, at most this many more
/// QoS1/2 outbound PUBLISH messages are buffered; overflowing still closes the connection (`lattice_mqtt_receive_max_total{result=throttled}`
/// is already counted per queueing/overflow), avoiding unbounded memory or silent reordering.
const OUTBOUND_RECEIVE_QUEUE: usize = 256;
/// Redis channel prefix (consistent with `lattice_core::keys::channel_mqtt`; wildcard subscriptions strip channel names by it).
pub const MQTT_CHANNEL_PREFIX: &str = "lattice:mqtt:";
/// Dedup window for multiple filters of the same client matching: the time spread of concurrent pubsub tasks receiving the same message is far below this value.
const DELIVERY_DEDUPE_WINDOW: Duration = Duration::from_secs(3);
/// Maximum records within the dedup window (when exceeded, expired items are cleared first; if still over the limit everything is cleared, so abnormal traffic cannot blow up memory).
const DELIVERY_DEDUPE_CAP: usize = 4_096;
/// Cap protection for multiple-publisher entries per topic during retained scans (only the latest entry per topic is delivered).
const RETAINED_SCAN_LIMIT: usize = 10_000;

/// Redelivery batch size (aligned with 200 in WS `drain_topics`; paged, continuing on the next reconnect).
const REPLAY_BATCH: usize = 200;
/// Upper bound for waiting on a PUBACK for one redelivered message (PUBCOMP for QoS2); the writer gives up and closes the connection when retransmissions are exhausted, so this is only a fallback.
const REPLAY_ACK_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap of the inbound QoS1 retransmission dedup table (per connection; cleared entirely when exceeded, keeping memory bounded).
const INBOUND_QOS1_DEDUP_CAP: usize = 512;
/// Stash cap for unfinished inbound QoS2 (PUBLISH received, PUBREL not yet); over the limit the connection is closed (counted as quota).
const INBOUND_QOS2_CAP: usize = 512;
/// Maximum number of packets serialized into a single session JSON (preventing an abnormal client from blowing up Redis with its session).
const SESSION_INBOUND_MAX: usize = 256;
pub const SESSION_OUTBOUND_MAX: usize = 256;
/// Sleep cap of the write-task timer when the pending map is empty (an incoming message/a due timer wakes it immediately).
const PENDING_IDLE_WAKE: Duration = Duration::from_secs(3600);

/// MQTT control packet types (MQTT 3.1.1 §2.2.1 / MQTT 5 §2.1.2).
pub const PACKET_CONNECT: u8 = 1;
pub const PACKET_CONNACK: u8 = 2;
pub const PACKET_PUBLISH: u8 = 3;
pub const PACKET_PUBACK: u8 = 4;
pub const PACKET_PUBREC: u8 = 5;
pub const PACKET_PUBREL: u8 = 6;
pub const PACKET_PUBCOMP: u8 = 7;
pub const PACKET_SUBSCRIBE: u8 = 8;
pub const PACKET_SUBACK: u8 = 9;
pub const PACKET_UNSUBSCRIBE: u8 = 10;
pub const PACKET_UNSUBACK: u8 = 11;
pub const PACKET_PINGREQ: u8 = 12;
pub const PACKET_PINGRESP: u8 = 13;
pub const PACKET_DISCONNECT: u8 = 14;

/// MQTT 5 reason codes (only those used by this gateway).
pub const REASON_SUCCESS: u8 = 0x00;
/// `Disconnect with Will Message` of `DISCONNECT` (MQTT 5 §3.14.2.1).
pub const REASON_DISCONNECT_WITH_WILL: u8 = 0x04;
pub const REASON_NO_SUBSCRIPTION_EXISTED: u8 = 0x11;
pub const REASON_UNSPECIFIED_ERROR: u8 = 0x80;
pub const REASON_PROTOCOL_ERROR: u8 = 0x82;
pub const REASON_UNSUPPORTED_PROTOCOL_VERSION: u8 = 0x84;
/// `Client Identifier not valid` (MQTT 5 §3.2.2.2).
pub const REASON_CLIENT_ID_INVALID: u8 = 0x85;
pub const REASON_BAD_CREDENTIALS: u8 = 0x86;
pub const REASON_NOT_AUTHORIZED: u8 = 0x87;
pub const REASON_SERVER_UNAVAILABLE: u8 = 0x88;
pub const REASON_TOPIC_FILTER_INVALID: u8 = 0x8f;
pub const REASON_TOPIC_NAME_INVALID: u8 = 0x90;
/// `Packet Identifier in use` (used as needed when a packet id conflicts within the same inbound QoS2 flow).
pub const REASON_PACKET_ID_IN_USE: u8 = 0x91;
/// `Packet Identifier not found` (PUBREL/PUBCOMP cannot find the corresponding packet id).
pub const REASON_PACKET_ID_NOT_FOUND: u8 = 0x92;
/// MQTT 5 `Topic Alias invalid` (§3.3.2.3.4: alias=0/over the cap/unknown alias/conflicting mapping).
pub const REASON_TOPIC_ALIAS_INVALID: u8 = 0x94;
/// MQTT 5 `QoS not supported` (kept: QoS3 is a protocol error and is no longer used for QoS2).
pub const REASON_QOS_NOT_SUPPORTED: u8 = 0x9b;

/// MQTT 3.1.1 CONNACK return codes (⑤ §11 / MQTT 3.1.1 §3.2.2.3).
pub const CONNACK_ACCEPTED: u8 = 0x00;
pub const CONNACK_BAD_PROTOCOL: u8 = 0x01;
pub const CONNACK_IDENTIFIER_REJECTED: u8 = 0x02;
pub const CONNACK_SERVER_UNAVAILABLE: u8 = 0x03;
pub const CONNACK_BAD_CREDENTIALS: u8 = 0x04;
pub const CONNACK_NOT_AUTHORIZED: u8 = 0x05;

// ---------------------------------------------------------------------------
// Redis keys (MQTT session/retained/WILL)
// ---------------------------------------------------------------------------
//
// Note: `lattice-core/src/keys.rs` is the authoritative location for key names in this repo, but this task's write scope covers only
// `transport/mqtt.rs` (plus config/metrics/e2e scripts), so **this MQTT-specific key group is assembled in this module**
// and pinned by unit tests; if the write scope expands later it should be migrated to `keys.rs` wholesale (key names/semantics unchanged).
//
// The naming only distinguishes semantics and is never parsed as a string: every segment is supplied by the caller (user/device are server-generated ids,
// client_id comes from the client), and `:` is only a separator — because fields are never parsed back out of a key, a client_id containing ':' cannot collide.

/// Session "reader state" Redis key: subscription table + inbound QoS2 stash + offline redelivery watermark (JSON string).
pub fn session_state_key(user: &str, device: &str, client_id: &str) -> String {
    format!("lattice:mqtt:sess:{user}:{device}:{client_id}:state")
}

/// Session "writer state" Redis key: unfinished outbound QoS2 pending (JSON string, written exclusively by the write task).
pub fn session_outbound_key(user: &str, device: &str, client_id: &str) -> String {
    format!("lattice:mqtt:sess:{user}:{device}:{client_id}:out")
}

/// retained message key prefix (wildcard subscriptions SCAN by prefix to match all retained messages).
pub const RETAINED_KEY_PREFIX: &str = "lattice:mqtt:retained:";

/// retained message key: exactly one per `lattice/{topic}/{device}` (**without** MQTT wildcard semantics).
pub fn retained_key(topic: &str, device: &str) -> String {
    format!("{RETAINED_KEY_PREFIX}{topic}:{device}")
}

/// Cancellation marker key for a delayed WILL (deleted on reconnect with the same client_id → cancels the not-yet-published will).
pub fn will_key(user: &str, device: &str, client_id: &str) -> String {
    format!("lattice:mqtt:will:{user}:{device}:{client_id}")
}


// ---------------------------------------------------------------------------
// Packet codec (fixed header + variable-length integer + UTF-8 strings)
// ---------------------------------------------------------------------------

/// One MQTT control packet (the variable header and payload are placed in `body`, interpreted by each packet parser).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub kind: u8,
    pub flags: u8,
    pub body: Vec<u8>,
}

impl Packet {
    pub fn new(kind: u8, flags: u8, body: Vec<u8>) -> Self {
        Packet { kind, flags, body }
    }
}

fn invalid_data(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Write an MQTT variable-length integer (1–4 bytes, at most 268435455).
pub fn write_varint(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Parse an MQTT variable-length integer, returning `(value, bytes consumed)`; truncated or invalid (>4 bytes) returns `None`.
pub fn decode_varint(buf: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    let mut multiplier = 1usize;
    for (i, &b) in buf.iter().take(4).enumerate() {
        value += ((b & 0x7f) as usize) * multiplier;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
        if i == 3 {
            return None;
        }
        multiplier *= 128;
    }
    None
}

/// Encode a complete packet (first fixed-header byte + variable remaining length + body).
pub fn encode_packet(packet: &Packet) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + packet.body.len());
    out.push((packet.kind << 4) | (packet.flags & 0x0f));
    write_varint(packet.body.len(), &mut out);
    out.extend_from_slice(&packet.body);
    out
}

/// Read one packet from `AsyncRead`; returns `Ok(None)` if the peer closes cleanly before a packet boundary.
pub async fn read_packet<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Packet>> {
    let mut first = [0u8; 1];
    match reader.read_exact(&mut first).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let kind = first[0] >> 4;
    let flags = first[0] & 0x0f;

    let mut remaining = 0usize;
    let mut multiplier = 1usize;
    for i in 0..4 {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b).await?;
        remaining += ((b[0] & 0x7f) as usize) * multiplier;
        if b[0] & 0x80 == 0 {
            break;
        }
        if i == 3 {
            return Err(invalid_data("mqtt remaining length malformed"));
        }
        multiplier *= 128;
    }
    if remaining > MAX_PACKET_BYTES {
        return Err(invalid_data(format!(
            "mqtt packet too large: {remaining} > {MAX_PACKET_BYTES}"
        )));
    }
    let mut body = vec![0u8; remaining];
    if remaining > 0 {
        reader.read_exact(&mut body).await?;
    }
    Ok(Some(Packet { kind, flags, body }))
}

/// Write one packet (no flush; the caller/write task decides).
pub async fn write_packet<W: AsyncWrite + Unpin>(writer: &mut W, packet: &Packet) -> io::Result<()> {
    writer.write_all(&encode_packet(packet)).await
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    debug_assert!(value.len() <= u16::MAX as usize, "mqtt string too long");
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

/// Read-only cursor over the packet body (slice reads with length validation).
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.buf.len() {
            return Err(format!(
                "truncated mqtt body: need {n}, {} left",
                self.remaining()
            ));
        }
        let buf: &'a [u8] = self.buf;
        let out = &buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn varint(&mut self) -> Result<usize, String> {
        if self.remaining() == 0 {
            return Err("truncated mqtt varint".into());
        }
        let rest: &'a [u8] = self.buf;
        let (value, used) = decode_varint(&rest[self.pos..])
            .ok_or_else(|| "malformed mqtt varint".to_string())?;
        self.pos += used;
        Ok(value)
    }

    fn bytes_prefixed(&mut self) -> Result<&'a [u8], String> {
        let len = self.u16()? as usize;
        self.take(len)
    }

    fn string(&mut self) -> Result<String, String> {
        let raw = self.bytes_prefixed()?;
        std::str::from_utf8(raw)
            .map(|s| s.to_string())
            .map_err(|_| "mqtt string is not valid utf-8".to_string())
    }

    /// Skip MQTT 5 properties: variable-length length prefix + property bytes (CONNECT/SUBSCRIBE etc. only skip them).
    fn skip_properties(&mut self) -> Result<(), String> {
        let len = self.varint()?;
        self.take(len)?;
        Ok(())
    }

    fn rest(&mut self) -> &'a [u8] {
        let buf: &'a [u8] = self.buf;
        let out = &buf[self.pos..];
        self.pos = buf.len();
        out
    }
}

// ---------------------------------------------------------------------------
// CONNECT / CONNACK
// ---------------------------------------------------------------------------

/// MQTT 5 CONNECT property fields this gateway cares about (the rest are parsed per protocol then discarded).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectProps {
    /// Session Expiry Interval (seconds): 0 = the session ends on disconnect; absent is treated as 0 (MQTT 5 §3.1.2.11.2).
    pub session_expiry: Option<u32>,
    pub receive_maximum: Option<u16>,
    pub maximum_packet_size: Option<u32>,
    /// Client-declared `Topic Alias Maximum` (the server→client direction cap): this gateway conservatively does not use aliases outbound,
    /// only parsing and saving it for the negotiation record (MQTT 5 §3.1.2.11.3).
    pub topic_alias_maximum: Option<u16>,
}

/// WILL-related properties (MQTT 5 §3.1.3.2; always empty for 3.1.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WillProps {
    /// Will Delay Interval (seconds): >0 means delayed publication, cancellable by a reconnect with the same client_id.
    pub delay_secs: Option<u32>,
    /// Message Expiry Interval (seconds): this gateway does not forward it for now (the envelope ttl only applies uplink); parsed only.
    pub message_expiry: Option<u32>,
    pub content_type: Option<String>,
    pub payload_format: Option<u8>,
}

/// Parsed CONNECT (3.1.1 / 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    pub level: u8,
    /// 3.1.1 clean_session; MQTT 5 clean_start (same name reused, semantics interpreted by level).
    pub clean_session: bool,
    pub keepalive_secs: u16,
    pub client_id: String,
    pub username: Option<String>,
    pub password: Option<Vec<u8>>,
    pub will: bool,
    pub will_qos: u8,
    pub will_retain: bool,
    pub will_topic: Option<String>,
    pub will_payload: Option<Vec<u8>>,
    pub will_props: WillProps,
    pub props: ConnectProps,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// The protocol name/level is unsupported (level 3 is MQTT 3.1, 6+ are unknown versions).
    UnsupportedProtocol(u8),
    Malformed(String),
}

/// Parse the MQTT 5 CONNECT property block (without the length prefix, MQTT 5 §3.1.2.11).
///
/// Unknown/misplaced properties are rejected as protocol errors (§2.2.2.2); only the fields this gateway needs are kept.
pub fn parse_connect_properties(buf: &[u8]) -> Result<ConnectProps, String> {
    let mut r = Reader::new(buf);
    let mut props = ConnectProps::default();
    while r.remaining() > 0 {
        match r.varint()? {
            0x11 => props.session_expiry = Some(r.u32()?),
            0x21 => props.receive_maximum = Some(r.u16()?),
            0x22 => props.topic_alias_maximum = Some(r.u16()?),
            0x23 => {
                let _ = r.u8()?; // Request Response Information
            }
            0x24 => {
                let _ = r.u8()?; // Request Problem Information
            }
            0x26 => {
                let _ = r.string()?; // User Property: skip both key and value
                let _ = r.string()?;
            }
            0x27 => props.maximum_packet_size = Some(r.u32()?),
            0x28 => {
                let _ = r.string()?; // Authentication Method (extended auth not enabled)
            }
            0x29 => {
                let _ = r.bytes_prefixed()?; // Authentication Data
            }
            other => return Err(format!("unknown connect property 0x{other:02x}")),
        }
    }
    Ok(props)
}

/// Parse the MQTT 5 WILL property block (without the length prefix, MQTT 5 §3.1.3.2).
pub fn parse_will_properties(buf: &[u8]) -> Result<WillProps, String> {
    let mut r = Reader::new(buf);
    let mut props = WillProps::default();
    while r.remaining() > 0 {
        match r.varint()? {
            0x18 => props.delay_secs = Some(r.u32()?),
            0x01 => props.payload_format = Some(r.u8()?),
            0x02 => props.message_expiry = Some(r.u32()?),
            0x03 => props.content_type = Some(r.string()?),
            0x08 => {
                let _ = r.string()?; // Will Response Topic: responses are not forwarded
            }
            0x09 => {
                let _ = r.bytes_prefixed()?; // Will Correlation Data: only passed through on uplink PUBLISH
            }
            0x26 => {
                let _ = r.string()?;
                let _ = r.string()?;
            }
            other => return Err(format!("unknown will property 0x{other:02x}")),
        }
    }
    Ok(props)
}

/// Parse the CONNECT variable header and payload (MQTT 3.1.1 §3.1 / MQTT 5 §3.1).
pub fn parse_connect(body: &[u8]) -> Result<Connect, ConnectError> {
    let mut r = Reader::new(body);
    let protocol = r.string().map_err(ConnectError::Malformed)?;
    let level = r.u8().map_err(ConnectError::Malformed)?;
    if !(protocol == "MQTT" || (protocol == "MQIsdp" && level == 3)) {
        return Err(ConnectError::Malformed(format!(
            "unknown protocol name {protocol:?}"
        )));
    }
    if level != 4 && level != 5 {
        return Err(ConnectError::UnsupportedProtocol(level));
    }

    let flags = r.u8().map_err(ConnectError::Malformed)?;
    if flags & 0x01 != 0 {
        return Err(ConnectError::Malformed("reserved connect flag bit set".into()));
    }
    let clean_session = flags & 0x02 != 0;
    let will = flags & 0x04 != 0;
    let will_qos = (flags >> 3) & 0x03;
    let will_retain = flags & 0x20 != 0;
    let password_flag = flags & 0x40 != 0;
    let username_flag = flags & 0x80 != 0;
    if !will && (will_qos != 0 || will_retain) {
        return Err(ConnectError::Malformed("will flags set without will".into()));
    }
    if will && will_qos == 3 {
        return Err(ConnectError::Malformed("invalid will qos 3".into()));
    }
    // MQTT-3.1.2-22: when the password flag is 1, the username flag must also be 1.
    if password_flag && !username_flag {
        return Err(ConnectError::Malformed("password without username".into()));
    }

    let keepalive_secs = r.u16().map_err(ConnectError::Malformed)?;
    let props = if level == 5 {
        let len = r.varint().map_err(ConnectError::Malformed)?;
        parse_connect_properties(r.take(len).map_err(ConnectError::Malformed)?)
            .map_err(ConnectError::Malformed)?
    } else {
        ConnectProps::default()
    };
    let client_id = r.string().map_err(ConnectError::Malformed)?;
    let (will_topic, will_payload, will_props) = if will {
        let will_props = if level == 5 {
            let len = r.varint().map_err(ConnectError::Malformed)?;
            parse_will_properties(r.take(len).map_err(ConnectError::Malformed)?)
                .map_err(ConnectError::Malformed)?
        } else {
            WillProps::default()
        };
        let will_topic = r.string().map_err(ConnectError::Malformed)?;
        let will_payload = r.bytes_prefixed().map_err(ConnectError::Malformed)?.to_vec();
        (Some(will_topic), Some(will_payload), will_props)
    } else {
        (None, None, WillProps::default())
    };
    let username = if username_flag {
        Some(r.string().map_err(ConnectError::Malformed)?)
    } else {
        None
    };
    let password = if password_flag {
        Some(r.bytes_prefixed().map_err(ConnectError::Malformed)?.to_vec())
    } else {
        None
    };
    if r.remaining() != 0 {
        return Err(ConnectError::Malformed("trailing connect bytes".into()));
    }
    Ok(Connect {
        level,
        clean_session,
        keepalive_secs,
        client_id,
        username,
        password,
        will,
        will_qos,
        will_retain,
        will_topic,
        will_payload,
        will_props,
        props,
    })
}

/// Parse an MQTT 5 DISCONNECT packet (MQTT 5 §3.14): returns `(reason_code, session_expiry, props_len)`.
///
/// A 3.1.1 DISCONNECT has a remaining length of 0 (no return code). An empty body is treated as reason=0 (normal disconnect).
pub fn parse_disconnect(body: &[u8]) -> Result<(u8, Option<u32>), String> {
    if body.is_empty() {
        return Ok((REASON_SUCCESS, None));
    }
    let reason = body[0];
    if body.len() == 1 {
        return Ok((reason, None));
    }
    let mut r = Reader::new(&body[1..]);
    let len = r.varint()?;
    let props = r.take(len)?;
    let mut pr = Reader::new(props);
    let mut session_expiry = None;
    while pr.remaining() > 0 {
        match pr.varint()? {
            0x11 => session_expiry = Some(pr.u32()?),
            0x1f => {
                let _ = pr.string()?; // Reason String
            }
            0x26 => {
                let _ = pr.string()?;
                let _ = pr.string()?;
            }
            other => return Err(format!("unknown disconnect property 0x{other:02x}")),
        }
    }
    Ok((reason, session_expiry))
}

/// CONNACK: 3.1.1 = `[session_present, code]`; MQTT 5 = `[session_present, reason, properties_len=0]`.
pub fn connack(level: u8, session_present: bool, code: u8) -> Packet {
    let mut body = vec![session_present as u8, code];
    if level == 5 {
        body.push(0);
    }
    Packet::new(PACKET_CONNACK, 0, body)
}

/// Negotiated properties of a successful MQTT 5 CONNACK: `Receive Maximum(0x21)` and `Topic Alias Maximum(0x22)`.
///
/// Both properties are optional (their MQTT 5 defaults are 65535 / 0 respectively):
/// - `receive_maximum`: the inbound QoS1/2 in-flight limit the server accepts from the client; `None` = do not advertise (the client assumes the
///   default 65535). This gateway advertises it only when the client CONNECT also declared Receive Maximum, keeping the CONNACK
///   shape unchanged for clients that did not declare it (the existing smoke/E2E contract);
/// - `alias_max`: the inbound Topic Alias cap the server accepts; `None` = do not advertise (= do not accept aliases).
///   This gateway advertises it only when the client declared Topic Alias Maximum (same rationale).
pub fn connack_with_props(
    level: u8,
    session_present: bool,
    code: u8,
    receive_maximum: Option<u16>,
    alias_max: Option<u16>,
) -> Packet {
    let mut body = vec![session_present as u8, code];
    if level == 5 {
        let mut props = Vec::with_capacity(6);
        if let Some(max) = receive_maximum {
            props.push(0x21);
            props.extend_from_slice(&max.to_be_bytes());
        }
        if let Some(max) = alias_max {
            props.push(0x22);
            props.extend_from_slice(&max.to_be_bytes());
        }
        write_varint(props.len(), &mut body);
        body.extend_from_slice(&props);
    }
    Packet::new(PACKET_CONNACK, 0, body)
}

/// CONNACK advertising only `Topic Alias Maximum(0x22)` (kept for the old entry point; equivalent to [`connack_with_props`]
/// with `receive_maximum = None`).
pub fn connack_with_alias_max(level: u8, session_present: bool, code: u8, alias_max: u16) -> Packet {
    connack_with_props(level, session_present, code, None, Some(alias_max))
}


// ---------------------------------------------------------------------------
// PUBLISH / PUBACK
// ---------------------------------------------------------------------------

/// MQTT 5 PUBLISH properties this gateway cares about (⑤ I5 allowlist).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublishProps {
    pub payload_format: Option<u8>,
    pub content_type: Option<String>,
    pub ttl_secs: Option<u32>,
    pub correlation_data: Option<Vec<u8>>,
    pub user_properties: Vec<(String, String)>,
    /// `Topic Alias` (MQTT 5 §3.3.2.3.4): session-level alias→topic mapping, used only in the inbound direction.
    pub topic_alias: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    pub topic: String,
    pub qos: u8,
    pub dup: bool,
    pub retain: bool,
    pub packet_id: Option<u16>,
    pub props: PublishProps,
    pub payload: Vec<u8>,
}

/// Parse the MQTT 5 PUBLISH property block (without the length prefix).
///
/// Only property ids allowed in PUBLISH are recognized; an unknown or misplaced property is rejected as a protocol error (MQTT 5 §2.2.2.2).
pub fn parse_publish_properties(buf: &[u8]) -> Result<PublishProps, String> {
    let mut r = Reader::new(buf);
    let mut props = PublishProps::default();
    while r.remaining() > 0 {
        match r.varint()? {
            0x01 => props.payload_format = Some(r.u8()?),
            0x02 => props.ttl_secs = Some(r.u32()?),
            0x03 => props.content_type = Some(r.string()?),
            0x08 => {
                // Response Topic: this gateway does not forward responses, so drop it.
                let _ = r.string()?;
            }
            0x09 => props.correlation_data = Some(r.bytes_prefixed()?.to_vec()),
            0x0b => {
                // Subscription Identifier is only allowed in the server→client direction; a client-sent one is ignored.
                let _ = r.varint()?;
            }
            0x23 => {
                // Topic Alias (MQTT 5 §3.3.2.3.4): validated against the CONNACK-advertised cap, see handle_publish.
                props.topic_alias = Some(r.u16()?);
            }
            0x26 => {
                let key = r.string()?;
                let value = r.string()?;
                props.user_properties.push((key, value));
            }
            other => return Err(format!("unknown publish property 0x{other:02x}")),
        }
    }
    Ok(props)
}

/// Parse PUBLISH (MQTT 3.1.1 §3.3 / MQTT 5 §3.3); QoS2 is parsed too, and the caller is responsible for rejecting it.
pub fn parse_publish(flags: u8, body: &[u8], level: u8) -> Result<Publish, String> {
    let qos = (flags >> 1) & 0x03;
    if qos == 3 {
        return Err("invalid publish qos 3".into());
    }
    let dup = flags & 0x08 != 0;
    let retain = flags & 0x01 != 0;
    let mut r = Reader::new(body);
    let topic = r.string()?;
    let packet_id = if qos > 0 {
        let id = r.u16()?;
        if id == 0 {
            return Err("publish packet id 0".into());
        }
        Some(id)
    } else {
        None
    };
    let props = if level == 5 {
        let len = r.varint()?;
        parse_publish_properties(r.take(len)?)?
    } else {
        PublishProps::default()
    };
    let payload = r.rest().to_vec();
    Ok(Publish { topic, qos, dup, retain, packet_id, props, payload })
}

/// Encode an outbound PUBLISH (QoS is the granted value; the packet id is used only for QoS>0; retain is set to 1 only when delivering retained on subscribe).
pub fn encode_publish(level: u8, topic: &str, payload: &[u8], qos: u8, packet_id: u16) -> Packet {
    encode_publish_ex(level, topic, payload, qos, packet_id, false, false)
}

/// Encode the full form of an outbound PUBLISH (dup/retain controllable; QoS0 ignores the packet id).
pub fn encode_publish_ex(
    level: u8,
    topic: &str,
    payload: &[u8],
    qos: u8,
    packet_id: u16,
    dup: bool,
    retain: bool,
) -> Packet {
    encode_publish_with_props(
        level,
        topic,
        payload,
        qos,
        packet_id,
        dup,
        retain,
        &OutPublishProps::default(),
    )
}

/// MQTT 5 properties of an outbound PUBLISH (automatically ignored on 3.1.1): Subscription Identifier list + Topic Alias.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutPublishProps {
    /// Subscription Identifiers (an outbound PUBLISH carries the ids of all matching subscriptions; ascending, deduped).
    pub sub_ids: Vec<u32>,
    /// Outbound Topic Alias (`Some(alias)` = property 0x23; with an empty topic it means "use the mapping").
    pub topic_alias: Option<u16>,
}

impl OutPublishProps {
    fn is_empty(&self) -> bool {
        self.sub_ids.is_empty() && self.topic_alias.is_none()
    }
}

/// Encode an outbound PUBLISH (including the MQTT 5 property block).
///
/// Property order is fixed: first write Subscription Identifier(0x0B) ascending (deduped), then Topic Alias(0x23),
/// guaranteeing the packet is reproducible in the same state (friendly to retransmission/E2E assertions). When `level != 5`, `props` is ignored entirely and
/// the body is byte-identical to the old [`encode_publish_ex`].
pub fn encode_publish_with_props(
    level: u8,
    topic: &str,
    payload: &[u8],
    qos: u8,
    packet_id: u16,
    dup: bool,
    retain: bool,
    props: &OutPublishProps,
) -> Packet {
    let mut body = Vec::with_capacity(topic.len() + payload.len() + 16);
    write_string(&mut body, topic);
    if qos > 0 {
        body.extend_from_slice(&packet_id.to_be_bytes());
    }
    if level == 5 {
        if props.is_empty() {
            body.push(0);
        } else {
            let mut raw = Vec::with_capacity(props.sub_ids.len() * 5 + 3);
            let mut last: Option<u32> = None;
            for id in &props.sub_ids {
                if Some(*id) == last {
                    continue;
                }
                last = Some(*id);
                raw.push(0x0b);
                write_varint(*id as usize, &mut raw);
            }
            if let Some(alias) = props.topic_alias {
                raw.push(0x23);
                raw.extend_from_slice(&alias.to_be_bytes());
            }
            write_varint(raw.len(), &mut body);
            body.extend_from_slice(&raw);
        }
    }
    body.extend_from_slice(payload);
    let mut flags = (qos & 0x03) << 1;
    if dup {
        flags |= 0x08;
    }
    if retain {
        flags |= 0x01;
    }
    Packet::new(PACKET_PUBLISH, flags, body)
}

/// QoS ACK packets (shared encoding for PUBACK/PUBREC/PUBREL/PUBCOMP):
/// 3.1.1 = `packet_id`; for MQTT 5 success the reason may be omitted (remaining length 2), while failure/non-zero carries a reason (remaining length 3).
///
/// `flags`: the PUBREL fixed header must be 0b0010 (MQTT 3.1.1 §3.6.1 / MQTT 5 §3.6.1); other ACKs use 0.
pub fn qos_ack(level: u8, kind: u8, flags: u8, packet_id: u16, reason: u8) -> Packet {
    let mut body = packet_id.to_be_bytes().to_vec();
    if level == 5 && reason != REASON_SUCCESS {
        body.push(reason);
    }
    Packet::new(kind, flags, body)
}

/// PUBACK.
pub fn puback(level: u8, packet_id: u16, reason: u8) -> Packet {
    qos_ack(level, PACKET_PUBACK, 0, packet_id, reason)
}

/// PUBREC (acknowledgement of the first inbound QoS2 step).
pub fn pubrec(level: u8, packet_id: u16, reason: u8) -> Packet {
    qos_ack(level, PACKET_PUBREC, 0, packet_id, reason)
}

/// PUBREL (release after receiving PUBREC for outbound QoS2; the fixed-header flags must be 0b0010).
pub fn pubrel(level: u8, packet_id: u16, reason: u8) -> Packet {
    qos_ack(level, PACKET_PUBREL, 0x02, packet_id, reason)
}

/// PUBCOMP (completion acknowledgement of inbound QoS2).
pub fn pubcomp(level: u8, packet_id: u16, reason: u8) -> Packet {
    qos_ack(level, PACKET_PUBCOMP, 0, packet_id, reason)
}

/// Parse an inbound QoS ACK into `(packet_id, reason)` (MQTT 5 properties are ignored; the default reason=0).
pub fn parse_qos_ack(body: &[u8]) -> Option<(u16, u8)> {
    if body.len() < 2 {
        return None;
    }
    let packet_id = u16::from_be_bytes([body[0], body[1]]);
    if packet_id == 0 {
        return None;
    }
    let reason = body.get(2).copied().unwrap_or(REASON_SUCCESS);
    Some((packet_id, reason))
}

/// Parse the packet id of an inbound PUBACK (the MQTT 5 reason/properties are not needed and are ignored).
pub fn parse_puback(body: &[u8]) -> Option<u16> {
    parse_qos_ack(body).map(|(packet_id, _)| packet_id)
}


// ---------------------------------------------------------------------------
// SUBSCRIBE / UNSUBSCRIBE
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeRequest {
    pub packet_id: u16,
    /// `(topic filter, requested QoS)`
    pub filters: Vec<(String, u8)>,
    /// MQTT 5 `Subscription Identifier(0x0B)`: shared by all filters in this SUBSCRIBE;
    /// always None on 3.1.1 (no property block). Legal range 1..=268435455 (0 is invalid → protocol error).
    pub subscription_id: Option<u32>,
}

/// MQTT 5 SUBSCRIBE property fields this gateway cares about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubscribeProps {
    /// `Subscription Identifier(0x0B)` (variable-length integer 1..=268435455; 0 is invalid).
    pub subscription_id: Option<u32>,
}

/// Parse the MQTT 5 SUBSCRIBE property block (without the length prefix, MQTT 5 §3.8.2.1).
pub fn parse_subscribe_properties(buf: &[u8]) -> Result<SubscribeProps, String> {
    let mut r = Reader::new(buf);
    let mut props = SubscribeProps::default();
    while r.remaining() > 0 {
        match r.varint()? {
            0x0b => {
                if props.subscription_id.is_some() {
                    // MQTT 5 §3.8.2.1.2: Subscription Identifier may appear only once within one SUBSCRIBE.
                    return Err("duplicate subscription identifier".into());
                }
                let id = r.varint()?;
                if id == 0 || id > MAX_SUBSCRIPTION_ID as usize {
                    return Err(format!("invalid subscription identifier {id}"));
                }
                props.subscription_id = Some(id as u32);
            }
            0x26 => {
                // User Property: skip both key and value (same convention as CONNECT/WILL).
                let _ = r.string()?;
                let _ = r.string()?;
            }
            other => return Err(format!("unknown subscribe property 0x{other:02x}")),
        }
    }
    Ok(props)
}

/// Parse SUBSCRIBE; for MQTT 5 the property block parses `Subscription Identifier` (other properties are validated per protocol then dropped),
/// and only QoS is taken from the options (the other flags are not relied on by this gateway).
pub fn parse_subscribe(body: &[u8], level: u8) -> Result<SubscribeRequest, String> {
    let mut r = Reader::new(body);
    let packet_id = r.u16()?;
    if packet_id == 0 {
        return Err("subscribe packet id 0".into());
    }
    let subscription_id = if level == 5 {
        let len = r.varint()?;
        let props = parse_subscribe_properties(r.take(len)?)?;
        props.subscription_id
    } else {
        None
    };
    // MQTT 5 subscription options: bits 0-1 QoS, bit2 NL, bit3 RAP, bit4 RH, bits 5-7 reserved;
    // 3.1.1: bits 0-1 QoS, bits 2-7 reserved. A non-zero reserved bit is a protocol error.
    let reserved_mask = if level == 5 { 0xe0 } else { 0xfc };
    let mut filters = Vec::new();
    while r.remaining() > 0 {
        let filter = r.string()?;
        let options = r.u8()?;
        let qos = options & 0x03;
        if qos == 0x03 {
            return Err("invalid subscription qos 3".into());
        }
        if options & reserved_mask != 0 {
            return Err("invalid subscription option bits".into());
        }
        filters.push((filter, qos));
    }
    if filters.is_empty() {
        return Err("subscribe without topic filters".into());
    }
    Ok(SubscribeRequest { packet_id, filters, subscription_id })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsubscribeRequest {
    pub packet_id: u16,
    pub filters: Vec<String>,
}

pub fn parse_unsubscribe(body: &[u8], level: u8) -> Result<UnsubscribeRequest, String> {
    let mut r = Reader::new(body);
    let packet_id = r.u16()?;
    if packet_id == 0 {
        return Err("unsubscribe packet id 0".into());
    }
    if level == 5 {
        r.skip_properties()?;
    }
    let mut filters = Vec::new();
    while r.remaining() > 0 {
        filters.push(r.string()?);
    }
    if filters.is_empty() {
        return Err("unsubscribe without topic filters".into());
    }
    Ok(UnsubscribeRequest { packet_id, filters })
}

/// A 3.1.1 SUBACK has only four return codes: 0x00/0x01/0x02/0x80; MQTT 5 reason codes are passed through directly.
pub fn suback_code(level: u8, reason: u8) -> u8 {
    if level == 5 || reason <= 2 {
        reason
    } else {
        REASON_UNSPECIFIED_ERROR
    }
}

pub fn suback(level: u8, packet_id: u16, codes: &[u8]) -> Packet {
    let mut body = packet_id.to_be_bytes().to_vec();
    if level == 5 {
        body.push(0);
    }
    body.extend_from_slice(codes);
    Packet::new(PACKET_SUBACK, 0, body)
}

/// UNSUBACK: 3.1.1 has only the packet id; MQTT 5 appends a reason list.
pub fn unsuback(level: u8, packet_id: u16, codes: &[u8]) -> Packet {
    let mut body = packet_id.to_be_bytes().to_vec();
    if level == 5 {
        body.push(0);
        body.extend_from_slice(codes);
    }
    Packet::new(PACKET_UNSUBACK, 0, body)
}

pub fn pingresp() -> Packet {
    Packet::new(PACKET_PINGRESP, 0, Vec::new())
}

pub fn disconnect(reason: u8) -> Packet {
    Packet::new(PACKET_DISCONNECT, 0, vec![reason, 0])
}

// ---------------------------------------------------------------------------
// Topic mapping and validation (⑤ §11: `lattice/{topic}/{device}`; the topic path may contain `/` to form levels)
// ---------------------------------------------------------------------------

/// `lattice/{topic}/{device}` → `(topic, device)`.
///
/// Structure: starts with `lattice/`, **the last segment** is the device segment, and the middle is the Lattice topic path (which may contain `/`;
/// every segment must be non-empty and free of `+`/`#`/`$`/NUL). Wildcards, a `$` prefix, and empty segments are rejected.
pub fn parse_topic(mapping: &str) -> Option<(String, String)> {
    let rest = mapping.strip_prefix("lattice/")?;
    let (topic, device) = rest.rsplit_once('/')?;
    if !valid_topic_path(topic) || !valid_segment(device) {
        return None;
    }
    Some((topic.to_string(), device.to_string()))
}

/// Lattice topic path: non-empty, layered by `/`, with every layer a legal segment (e.g. `site/a/temp`).
fn valid_topic_path(path: &str) -> bool {
    !path.is_empty() && path.split('/').all(valid_segment)
}

fn valid_segment(segment: &str) -> bool {
    !segment.is_empty() && !segment.contains(['+', '#', '$', '\0'])
}

/// Rebuild the MQTT wire topic from the Lattice topic path and the device (the topic field of a downlink PUBLISH).
fn wire_topic(topic: &str, device: &str) -> String {
    format!("lattice/{topic}/{device}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopicError {
    /// Not `lattice/{topic}/{device}` (contains a wildcard / `$share` / structural error).
    Invalid,
    /// The device segment in the topic does not match the connection identity's device.
    DeviceMismatch,
}

/// Map an MQTT topic to a Lattice Topic and validate device ownership.
pub fn map_topic(mapping: &str, device_id: &str) -> Result<String, TopicError> {
    if mapping.starts_with('$') {
        return Err(TopicError::Invalid);
    }
    let (topic, device) = parse_topic(mapping).ok_or(TopicError::Invalid)?;
    if device != device_id {
        return Err(TopicError::DeviceMismatch);
    }
    Ok(topic)
}

impl TopicError {
    /// How an inbound PUBLISH is rejected: MQTT 5 uses DISCONNECT (there is no 3.1.1 equivalent packet).
    fn disconnect_reason(self) -> u8 {
        match self {
            TopicError::Invalid => REASON_TOPIC_NAME_INVALID,
            TopicError::DeviceMismatch => REASON_NOT_AUTHORIZED,
        }
    }

    /// The SUBACK reason code when a subscription fails.
    fn suback_reason(self) -> u8 {
        match self {
            TopicError::Invalid => REASON_TOPIC_FILTER_INVALID,
            TopicError::DeviceMismatch => REASON_NOT_AUTHORIZED,
        }
    }
}

// ---------------------------------------------------------------------------
// Pure logic for wildcard filters / shared subscriptions / Topic Alias (all unit-testable)
// ---------------------------------------------------------------------------

/// Whether the filter contains an MQTT wildcard (`+`/`#`).
pub fn filter_has_wildcard(filter: &str) -> bool {
    filter.contains('+') || filter.contains('#')
}

/// Validate MQTT topic filter syntax (MQTT 3.1.1 §4.7 / MQTT 5 §4.7):
/// - non-empty, ≤65535 bytes, no NUL;
/// - `#` must occupy a whole level and can only be the last level (`a/#`, `#` are legal; `a/#/b`, `a#` are illegal);
/// - `+` must occupy a whole level (`a/+/b` is legal; `a+`, `a+/b` are illegal).
pub fn validate_topic_filter(filter: &str) -> Result<(), String> {
    if filter.is_empty() {
        return Err("empty topic filter".into());
    }
    if filter.len() > 65_535 {
        return Err("topic filter too long".into());
    }
    if filter.contains('\0') {
        return Err("null character in topic filter".into());
    }
    let levels: Vec<&str> = filter.split('/').collect();
    for (index, level) in levels.iter().enumerate() {
        if level.contains('#') {
            if *level != "#" {
                return Err("'#' must occupy a whole level".into());
            }
            if index + 1 != levels.len() {
                return Err("'#' must be the last level".into());
            }
        }
        if level.contains('+') && *level != "+" {
            return Err("'+' must occupy a whole level".into());
        }
    }
    Ok(())
}

/// MQTT 4.7 wildcard matching: whether `filter` matches `topic` (**the match target is the Lattice topic path**;
/// the device segment does not participate; the downlink topic is assembled from the subscriber's own device).
///
/// - `+` matches exactly one level (empty levels allowed; MQTT permits zero-length levels);
/// - `#` matches all remaining levels, and `a/#` also matches the parent level `a`;
/// - a topic starting with `$` is not matched by filters starting with `#`/`+` (MQTT 4.7.1 §4.7.2).
pub fn matches(filter: &str, topic: &str) -> bool {
    if filter.is_empty() || topic.is_empty() {
        return false;
    }
    if topic.starts_with('$') && (filter.starts_with('#') || filter.starts_with('+')) {
        return false;
    }
    let filter_levels: Vec<&str> = filter.split('/').collect();
    let topic_levels: Vec<&str> = topic.split('/').collect();
    let mut index = 0usize;
    for level in &filter_levels {
        if *level == "#" {
            return true;
        }
        let Some(topic_level) = topic_levels.get(index) else {
            return false;
        };
        if *level != "+" && *level != *topic_level {
            return false;
        }
        index += 1;
    }
    index == topic_levels.len()
}

/// Decompose a shared-subscription filter: `$share/{group}/{filter}` → `(group, filter)`; returns None when invalid.
///
/// The group must be non-empty and free of `/`/`+`/`#`/`$`/NUL; the inner filter must be a legal MQTT filter and must not itself be a
/// shared subscription (MQTT 5 §4.8.2).
pub fn parse_shared_filter(raw: &str) -> Option<(String, String)> {
    let rest = raw.strip_prefix("$share/")?;
    let (group, filter) = rest.split_once('/')?;
    if group.is_empty() || group.contains(['/', '+', '#', '$', '\0']) {
        return None;
    }
    if filter.is_empty() || filter.starts_with("$share/") {
        return None;
    }
    validate_topic_filter(filter).ok()?;
    Some((group.to_string(), filter.to_string()))
}

/// Normalize a subscription filter to a "Lattice topic path pattern": strip the optional `lattice/` namespace prefix.
///
/// Example: `lattice/site/#` / `site/#` both normalize to `site/#`; `#` stays unchanged.
pub fn normalize_filter(filter: &str) -> String {
    match filter.strip_prefix("lattice/") {
        Some(rest) => rest.to_string(),
        None => filter.to_string(),
    }
}

/// Turn a Lattice topic path pattern into a candidate channel pattern for Redis `PSUBSCRIBE`.
///
/// Used only to narrow the candidate set: take the literal prefix before the first wildcard level (escaping glob special characters);
/// actual matching is decided by [`matches`], so an over-broad candidate set cannot cause misdelivery.
pub fn redis_channel_pattern(normalized_filter: &str) -> String {
    let mut literal_levels: Vec<&str> = Vec::new();
    for level in normalized_filter.split('/') {
        if level == "+" || level == "#" {
            break;
        }
        literal_levels.push(level);
    }
    let prefix = literal_levels.join("/");
    let mut escaped = String::with_capacity(prefix.len());
    for ch in prefix.chars() {
        // Redis glob metacharacters: * ? [ ] \; escaped so they are matched literally.
        if matches!(ch, '*' | '?' | '[' | ']' | '\\') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    format!("{MQTT_CHANNEL_PREFIX}{escaped}*")
}

/// Topic Alias resolution outcome (MQTT 5 §3.3.2.3.4; pure logic for easy unit testing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasOutcome {
    /// No alias and a non-empty topic: a normal publish.
    None,
    /// Non-empty topic + alias: after the topic passes validation, create/update the session-level mapping (metric=set).
    Set,
    /// Empty topic + known alias: restore the topic from the mapping (metric=used).
    Used(String),
    /// Protocol error: MQTT 5 replies `DISCONNECT(0x94)` and disconnects.
    Error(AliasError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasError {
    /// alias = 0 (MQTT 5 protocol error).
    Zero,
    /// alias > the `Topic Alias Maximum` advertised by the server CONNACK (or the cap is 0).
    AboveMax,
    /// An empty topic uses an alias that has not been established yet.
    Unknown,
    /// The alias is already mapped to another topic (this gateway is strict: one alias can map to only one topic).
    Conflict,
    /// Empty topic without an alias (the topic cannot be located).
    EmptyTopicWithoutAlias,
}

impl AliasError {
    fn reason(self) -> u8 {
        match self {
            AliasError::EmptyTopicWithoutAlias => REASON_PROTOCOL_ERROR,
            _ => REASON_TOPIC_ALIAS_INVALID,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            AliasError::Zero => "alias-zero",
            AliasError::AboveMax => "alias-above-max",
            AliasError::Unknown => "alias-unknown",
            AliasError::Conflict => "alias-conflict",
            AliasError::EmptyTopicWithoutAlias => "empty-topic-without-alias",
        }
    }
}

/// Resolve the alias of an inbound PUBLISH (read-only; `Set` requires the caller to write the mapping after topic validation).
pub fn resolve_topic_alias(
    aliases: &HashMap<u16, String>,
    max: u16,
    alias: Option<u16>,
    topic: &str,
) -> AliasOutcome {
    let Some(alias) = alias else {
        return if topic.is_empty() {
            AliasOutcome::Error(AliasError::EmptyTopicWithoutAlias)
        } else {
            AliasOutcome::None
        };
    };
    if alias == 0 {
        return AliasOutcome::Error(AliasError::Zero);
    }
    if max == 0 || alias > max {
        return AliasOutcome::Error(AliasError::AboveMax);
    }
    if topic.is_empty() {
        return match aliases.get(&alias) {
            Some(mapped) => AliasOutcome::Used(mapped.clone()),
            None => AliasOutcome::Error(AliasError::Unknown),
        };
    }
    match aliases.get(&alias) {
        Some(mapped) if mapped != topic => AliasOutcome::Error(AliasError::Conflict),
        _ => AliasOutcome::Set,
    }
}

/// Loopback delivery dedup window: when multiple filters of the same client match one Redis message, deliver it only once.
///
/// The key looks like `{lattice_topic}\u{0}{envelope_id}`; old records outside the window are lazily cleaned up on write.
struct DeliveryDedupe {
    seen: HashMap<String, Instant>,
    window: Duration,
}

impl DeliveryDedupe {
    fn new(window: Duration) -> Self {
        DeliveryDedupe { seen: HashMap::new(), window }
    }

    /// Returns true on the first occurrence (should deliver) and false for a duplicate within the window.
    fn claim(&mut self, key: String) -> bool {
        let now = Instant::now();
        if self.seen.len() >= DELIVERY_DEDUPE_CAP {
            self.seen.retain(|_, at| now.duration_since(*at) < self.window);
            if self.seen.len() >= DELIVERY_DEDUPE_CAP {
                self.seen.clear();
            }
        }
        if let Some(at) = self.seen.get(&key) {
            if now.duration_since(*at) < self.window {
                return false;
            }
        }
        self.seen.insert(key, now);
        true
    }
}

/// Match information for a normal subscription (describing exact and wildcard uniformly), used for overlapping-filter dedup, max-QoS selection, and aggregating
/// Subscription Identifier.
#[derive(Debug, Clone)]
struct PlainFilter {
    /// The client's original filter (used for exact matching on UNSUBSCRIBE).
    raw: String,
    /// Exact subscription: the Lattice topic path; None for a wildcard subscription.
    exact_topic: Option<String>,
    /// Wildcard subscription: the normalized Lattice topic path pattern; None for an exact subscription.
    pattern: Option<String>,
    /// Granted QoS.
    qos: u8,
    /// MQTT 5 Subscription Identifier (SUBSCRIBE property 0x0B; None on 3.1.1/when not carried).
    sub_id: Option<u32>,
}

impl PlainFilter {
    fn exact(raw: String, topic: String, qos: u8, sub_id: Option<u32>) -> Self {
        PlainFilter { raw, exact_topic: Some(topic), pattern: None, qos, sub_id }
    }

    fn wildcard(raw: String, pattern: String, qos: u8, sub_id: Option<u32>) -> Self {
        PlainFilter { raw, exact_topic: None, pattern: Some(pattern), qos, sub_id }
    }

    fn matches_topic(&self, topic: &str) -> bool {
        match (&self.exact_topic, &self.pattern) {
            (Some(exact), _) => exact == topic,
            (None, Some(pattern)) => matches(pattern, topic),
            (None, None) => false,
        }
    }
}

/// Normal-subscription match result for one message (by Lattice topic path): `(downlink QoS, Subscription Identifiers)`.
///
/// - QoS = the maximum of the values granted by all matching normal filters (MQTT 3.1.1 §3.8.4 overlapping-subscription convention);
/// - identifiers = the MQTT 5 Subscription Identifiers of all matching filters: deduped + ascending, keeping the outbound
///   PUBLISH property order stable; when multiple subscriptions of the same client match one message, the PUBLISH carries **all** ids
///   (the normalized convention of MQTT 5 §3.8.2.1.2).
///
/// Returning None = no normal filter matched (e.g. a just-unsubscribed task not yet aborted) → do not deliver.
fn matching_delivery(
    filters: &Arc<Mutex<Vec<PlainFilter>>>,
    topic: &str,
) -> Option<(u8, Vec<u32>)> {
    let guard = filters.lock().ok()?;
    let mut qos: Option<u8> = None;
    let mut ids: Vec<u32> = Vec::new();
    for filter in guard.iter().filter(|f| f.matches_topic(topic)) {
        qos = Some(qos.map_or(filter.qos, |current| current.max(filter.qos)));
        if let Some(id) = filter.sub_id {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    let qos = qos?;
    ids.sort_unstable();
    Some((qos, ids))
}

/// Take the id from the envelope bytes (the Redis realtime downlink delivers `Envelope::encode_body` bytes);
/// on decode failure, degrade to a payload fingerprint (dedup still works, just with lower discrimination).
fn delivery_dedupe_key(topic: &str, payload: &[u8]) -> String {
    let id = match Envelope::decode_body(payload) {
        Ok(envelope) => envelope.id,
        Err(_) => format!("fp:{:x}", payload_fingerprint(payload)),
    };
    format!("{topic}\u{0}{id}")
}


// ---------------------------------------------------------------------------
// Request → envelope (⑤ §11 / ⑤ I5)
// ---------------------------------------------------------------------------

/// Default envelope type when the MIME is unrecognized (⑤ §11: `type=custom:iot`, `encoding=raw`).
pub const DEFAULT_ENVELOPE_TYPE: &str = "custom:iot";
pub const DEFAULT_ENCODING: &str = "raw";
/// MQTT 5 `User-Property`: only keys with this prefix are passed through (⑤ I5).
pub const USER_PROPERTY_PREFIX: &str = "lx-";

/// MIME → `(Envelope.type, Envelope.encoding)` (⑤ §11: map by MIME when the `Content-Type` property is present).
pub fn mime_envelope_type(content_type: &str) -> (&'static str, &'static str) {
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if mime.is_empty() {
        return (DEFAULT_ENVELOPE_TYPE, DEFAULT_ENCODING);
    }
    if mime.starts_with("text/") {
        if mime.ends_with("xml") {
            return ("xml", "utf8");
        }
        return ("text", "utf8");
    }
    if mime == "application/json" || mime.ends_with("+json") {
        return ("json", "utf8");
    }
    if mime == "application/xml" || mime.ends_with("+xml") {
        return ("xml", "utf8");
    }
    if mime.contains("protobuf") {
        return ("proto", DEFAULT_ENCODING);
    }
    if mime.contains("msgpack") {
        return ("msgpack", DEFAULT_ENCODING);
    }
    if mime.starts_with("image/") {
        return ("image", DEFAULT_ENCODING);
    }
    if mime.starts_with("audio/") || mime.starts_with("video/") {
        return ("media", DEFAULT_ENCODING);
    }
    ("binary", DEFAULT_ENCODING)
}

/// Build a Lattice `Envelope` from an MQTT PUBLISH (type/encoding per the module comment and ⑤ §11).
pub fn envelope_from_publish(topic: &str, sender: &str, publish: &Publish) -> Envelope {
    let (env_type, encoding) = match publish.props.content_type.as_deref() {
        Some(ct) if !ct.trim().is_empty() => mime_envelope_type(ct),
        _ => (DEFAULT_ENVELOPE_TYPE, DEFAULT_ENCODING),
    };
    let mut env = Envelope {
        id: lattice_core::ids::new_id(),
        r#type: env_type.to_string(),
        content_type: publish.props.content_type.clone().unwrap_or_default(),
        encoding: encoding.to_string(),
        payload: publish.payload.clone(),
        conv_id: format!("topic:{topic}"),
        sender: sender.to_string(),
        created_at: chrono::Utc::now().timestamp() as u64,
        ttl_seconds: publish.props.ttl_secs.unwrap_or(0),
        route: Some(lattice_core::RouteInfo {
            to_topic: topic.to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    if let Some(data) = &publish.props.correlation_data {
        env.metadata.insert(
            "correlation-data".into(),
            format!("b64:{}", lattice_core::envelope::base64_encode(data)),
        );
    }
    for (key, value) in &publish.props.user_properties {
        if key.starts_with(USER_PROPERTY_PREFIX) {
            env.metadata.insert(key.clone(), value.clone());
        }
    }
    env
}

// ---------------------------------------------------------------------------
// Pure decisions for rate limiting, keepalive, and connection caps (unit-testable)
// ---------------------------------------------------------------------------

/// QoS allowlist: QoS0/1/2 are all supported (PL-11 completed QoS2; QoS3 is an illegal protocol value).
pub fn qos_supported(qos: u8) -> bool {
    matches!(qos, 0 | 1 | 2)
}

/// The value this gateway grants for a requested QoS: no downgrade anymore now that QoS2 is supported (kept for reuse by the subscription grant path).
pub fn granted_qos(requested: u8) -> u8 {
    requested.min(2)
}

/// Rate-limit decision: reject once the count within the window exceeds the cap (§17.13: 10 msg/s per device).
pub fn quota_exceeded(count: i64, limit: u32) -> bool {
    count > limit as i64
}

/// keepalive timeout = 1.5× the client-declared value (MQTT 3.1.1 §3.1.2.10); 0 = never times out.
pub fn keepalive_timeout(secs: u16) -> Option<Duration> {
    if secs == 0 {
        None
    } else {
        Some(Duration::from_millis(secs as u64 * 1500))
    }
}

/// Effective value of the configured Receive Maximum: 0 = fill the MQTT 5 default 65535 (unlimited); otherwise the configured value.
///
/// Server semantics: the inbound QoS1/2 in-flight cap advertised to the client in CONNACK property 0x21 (1..=65535).
pub fn effective_receive_maximum(configured: u16) -> u16 {
    if configured == 0 {
        MAX_RECEIVE_MAXIMUM
    } else {
        configured
    }
}

/// Acquire a connection slot via CAS (`max_connections = 0` means unlimited).
fn try_acquire(active: &AtomicUsize, max: usize) -> bool {
    if max == 0 {
        active.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    let mut current = active.load(Ordering::Relaxed);
    loop {
        if current >= max {
            return false;
        }
        match active.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

/// Release a connection slot (RAII: the count is decremented when the connection task ends).
struct ActiveGuard {
    active: Arc<AtomicUsize>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Redis connection (binary-safe PUBLISH + dynamic subscription lifecycle)
// ---------------------------------------------------------------------------
//
// Why the `store::Redis` wrapper is not used: the envelope is protobuf binary, and `Redis::publish` accepts only `&str`
// (`from_utf8_lossy` would corrupt the payload); also, one pubsub task per subscription must be abortable on unsubscribe/disconnect, and
// the wrapper has neither a binary interface nor a task-handle return. Here the `redis` crate is used directly (it is already a dependency of this crate).

#[derive(Clone)]
struct RedisLink {
    client: redis::Client,
    publish_mgr: redis::aio::ConnectionManager,
}

impl RedisLink {
    async fn connect(url: &str) -> Option<Self> {
        let client = match redis::Client::open(url) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "mqtt gateway redis client init failed (realtime fanout disabled)");
                return None;
            }
        };
        match redis::aio::ConnectionManager::new(client.clone()).await {
            Ok(publish_mgr) => Some(RedisLink { client, publish_mgr }),
            Err(e) => {
                tracing::warn!(error = %e, "mqtt gateway redis connect failed (realtime fanout disabled)");
                None
            }
        }
    }

    /// PUBLISH envelope bytes in a binary-safe way (cross-node gateway realtime downlink).
    async fn publish(&self, channel: &str, payload: &[u8]) -> Result<(), redis::RedisError> {
        let mut conn = self.publish_mgr.clone();
        let _: i64 = redis::cmd("PUBLISH")
            .arg(channel)
            .arg(payload)
            .query_async(&mut conn)
            .await?;
        Ok(())
    }
}

/// Exact-subscription task: subscribes to a single `lattice:mqtt:{topic}` channel; messages are multiplexed to the connection write task via mpsc.
///
/// It adds two steps over the old implementation (needed once wildcards were added): take the max QoS over all matching filters in the session;
/// and dedup by envelope id in a session-level window (the same message may match both an exact and a wildcard subscription).
fn spawn_exact_subscription(
    redis: Option<&RedisLink>,
    topic: &str,
    device: &str,
    filters: Arc<Mutex<Vec<PlainFilter>>>,
    dedupe: Arc<Mutex<DeliveryDedupe>>,
    tx: mpsc::Sender<Outbound>,
) -> Option<JoinHandle<()>> {
    let link = redis?;
    let client = link.client.clone();
    let channel = keys::channel_mqtt(topic);
    let topic = topic.to_string();
    let device = device.to_string();
    Some(tokio::spawn(async move {
        use futures::StreamExt;
        let mut pubsub = match client.get_async_pubsub().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, channel = %channel, "mqtt pubsub connect failed");
                return;
            }
        };
        if let Err(e) = pubsub.subscribe(&channel).await {
            tracing::warn!(error = %e, channel = %channel, "mqtt pubsub subscribe failed");
            return;
        }
        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            let payload = msg.get_payload_bytes().to_vec();
            let Some((qos, sub_ids)) = matching_delivery(&filters, &topic) else {
                continue;
            };
            let key = delivery_dedupe_key(&topic, &payload);
            let first = dedupe.lock().map(|mut d| d.claim(key)).unwrap_or(true);
            if !first {
                continue;
            }
            let outbound = Outbound::Publish {
                topic: wire_topic(&topic, &device),
                payload,
                qos,
                retain: false,
                ack: None,
                sub_ids,
            };
            if tx.send(outbound).await.is_err() {
                break;
            }
        }
    }))
}

/// Wildcard-subscription task: `PSUBSCRIBE` a candidate channel pattern, then re-filter with [`matches`].
///
/// The subscription target is the Lattice topic path (the device dimension is implicit for subscriptions); the downlink topic is
/// `lattice/{topic}/{device}` assembled from this connection's device. Match counts go to `lattice_mqtt_wildcard_total{result=match|mismatch}`.
fn spawn_wildcard_subscription(
    redis: Option<&RedisLink>,
    pattern: &str,
    device: &str,
    filters: Arc<Mutex<Vec<PlainFilter>>>,
    dedupe: Arc<Mutex<DeliveryDedupe>>,
    tx: mpsc::Sender<Outbound>,
    metrics: Arc<crate::observe::Metrics>,
) -> Option<JoinHandle<()>> {
    let link = redis?;
    let client = link.client.clone();
    let channel_pattern = redis_channel_pattern(pattern);
    let pattern = pattern.to_string();
    let device = device.to_string();
    Some(tokio::spawn(async move {
        use futures::StreamExt;
        let mut pubsub = match client.get_async_pubsub().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, pattern = %channel_pattern, "mqtt wildcard pubsub connect failed");
                return;
            }
        };
        if let Err(e) = pubsub.psubscribe(&channel_pattern).await {
            tracing::warn!(error = %e, pattern = %channel_pattern, "mqtt wildcard psubscribe failed");
            return;
        }
        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            let channel = msg.get_channel_name().to_string();
            let Some(topic) = channel.strip_prefix(MQTT_CHANNEL_PREFIX) else {
                continue;
            };
            if !matches(&pattern, topic) {
                // The candidate pattern is broader than the MQTT filter (Redis glob cannot express levels) → discard on re-filter.
                metrics
                    .mqtt_wildcard_total
                    .with_label_values(&["mismatch"])
                    .inc();
                continue;
            }
            let payload = msg.get_payload_bytes().to_vec();
            let Some((qos, sub_ids)) = matching_delivery(&filters, topic) else {
                continue;
            };
            let key = delivery_dedupe_key(topic, &payload);
            let first = dedupe.lock().map(|mut d| d.claim(key)).unwrap_or(true);
            if !first {
                continue;
            }
            metrics
                .mqtt_wildcard_total
                .with_label_values(&["match"])
                .inc();
            let outbound = Outbound::Publish {
                topic: wire_topic(topic, &device),
                payload,
                qos,
                retain: false,
                ack: None,
                sub_ids,
            };
            if tx.send(outbound).await.is_err() {
                break;
            }
        }
    }))
}

// ---------------------------------------------------------------------------
// Shared subscription `$share/{group}/{filter}` (in-process round-robin registry)
// ---------------------------------------------------------------------------

/// Shared-subscription group key: `(group, normalized filter)`. Members of the same group share one Redis candidate subscription task.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SharedKey {
    group: String,
    filter: String,
}

struct SharedMember {
    id: u64,
    out: mpsc::Sender<Outbound>,
    /// The member's own device (the downlink topic is assembled from each member's device).
    device: String,
    /// The QoS granted to the member (may differ per member within a group).
    qos: u8,
    /// The member's MQTT 5 Subscription Identifier (shared subscriptions can also carry 0x0B; the selected member decides the id).
    sub_id: Option<u32>,
}

struct SharedGroup {
    members: Vec<SharedMember>,
    /// Round-robin cursor (a `usize` used modulo the member count on insert/remove; it need not map one-to-one to member indices long term).
    cursor: usize,
    /// The group's Redis candidate subscription task (started when the first member registers, aborted when the last member unregisters).
    task: Option<JoinHandle<()>>,
}

fn shared_registry() -> &'static Mutex<HashMap<SharedKey, SharedGroup>> {
    static REGISTRY: OnceLock<Mutex<HashMap<SharedKey, SharedGroup>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_SHARED_MEMBER_ID: AtomicU64 = AtomicU64::new(1);

/// Register a shared-subscription member; the first member of the group triggers the Redis `PSUBSCRIBE` task. Returns the member id.
///
/// Returns None when Redis is unavailable (no realtime downlink channel, matching the exact-subscription degradation behavior).
fn shared_register(
    redis: Option<&RedisLink>,
    metrics: &Arc<crate::observe::Metrics>,
    group: &str,
    filter: &str,
    device: &str,
    qos: u8,
    sub_id: Option<u32>,
    out: mpsc::Sender<Outbound>,
) -> Option<u64> {
    let link = redis?.clone();
    let member_id = NEXT_SHARED_MEMBER_ID.fetch_add(1, Ordering::Relaxed);
    let key = SharedKey { group: group.to_string(), filter: filter.to_string() };
    let mut registry = shared_registry().lock().ok()?;
    let entry = registry.entry(key.clone()).or_insert_with(|| SharedGroup {
        members: Vec::new(),
        cursor: 0,
        task: None,
    });
    entry.members.push(SharedMember {
        id: member_id,
        out,
        device: device.to_string(),
        qos: qos.min(2),
        sub_id,
    });
    if entry.task.is_none() {
        let channel_pattern = redis_channel_pattern(filter);
        entry.task = Some(spawn_shared_group_task(
            link,
            key,
            channel_pattern,
            metrics.clone(),
        ));
    }
    Some(member_id)
}

/// Unregister a shared-subscription member; when the group has no members, abort the group's pubsub task and remove the registry entry.
fn shared_unregister(group: &str, filter: &str, member_id: u64) {
    let key = SharedKey { group: group.to_string(), filter: filter.to_string() };
    let mut to_abort: Option<JoinHandle<()>> = None;
    if let Ok(mut registry) = shared_registry().lock() {
        if let Some(entry) = registry.get_mut(&key) {
            entry.members.retain(|m| m.id != member_id);
            if entry.members.is_empty() {
                to_abort = entry.task.take();
                registry.remove(&key);
            }
        }
    }
    if let Some(task) = to_abort {
        task.abort();
    }
}

/// Attempt order over the candidate members of a shared-subscription group: one full round robin starting at the cursor (pure logic, easy to unit test).
fn shared_candidate_order(cursor: usize, len: usize) -> Vec<usize> {
    if len == 0 {
        return Vec::new();
    }
    let start = cursor % len;
    (0..len).map(|offset| (start + offset) % len).collect()
}

/// Candidate subscription task of a shared-subscription group: each matching message round-robins to one **active** member within the group (`try_send`).
///
/// - Members whose connection is closed (`is_closed`) are removed first;
/// - A selected member with a full queue (stuck/backpressure) → skip and try the next one;
/// - All unavailable → drop the message and count `lattice_mqtt_shared_total{result=skipped}`.
fn spawn_shared_group_task(
    link: RedisLink,
    key: SharedKey,
    channel_pattern: String,
    metrics: Arc<crate::observe::Metrics>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        use futures::StreamExt;
        let mut pubsub = match link.client.get_async_pubsub().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, pattern = %channel_pattern, "mqtt shared pubsub connect failed");
                return;
            }
        };
        if let Err(e) = pubsub.psubscribe(&channel_pattern).await {
            tracing::warn!(error = %e, pattern = %channel_pattern, "mqtt shared psubscribe failed");
            return;
        }
        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            let channel = msg.get_channel_name().to_string();
            let Some(topic) = channel.strip_prefix(MQTT_CHANNEL_PREFIX) else {
                continue;
            };
            if !matches(&key.filter, topic) {
                continue;
            }
            let payload = msg.get_payload_bytes().to_vec();
            let mut registry = match shared_registry().lock() {
                Ok(registry) => registry,
                Err(_) => break,
            };
            let Some(group) = registry.get_mut(&key) else {
                break;
            };
            group.members.retain(|member| !member.out.is_closed());
            if group.members.is_empty() {
                metrics
                    .mqtt_shared_total
                    .with_label_values(&["skipped"])
                    .inc();
                continue;
            }
            let len = group.members.len();
            let mut chosen: Option<usize> = None;
            for index in shared_candidate_order(group.cursor, len) {
                let member = &group.members[index];
                let outbound = Outbound::Publish {
                    topic: wire_topic(topic, &member.device),
                    payload: payload.clone(),
                    qos: member.qos,
                    retain: false,
                    ack: None,
                    sub_ids: member.sub_id.into_iter().collect(),
                };
                // try_send: one stuck connection in the group (full downlink queue) must not hold up delivery for the whole group → skip to the next member.
                if member.out.try_send(outbound).is_ok() {
                    chosen = Some(index);
                    break;
                }
            }
            match chosen {
                Some(index) => {
                    group.cursor = (index + 1) % len;
                    metrics
                        .mqtt_shared_total
                        .with_label_values(&["delivered"])
                        .inc();
                }
                None => {
                    metrics
                        .mqtt_shared_total
                        .with_label_values(&["skipped"])
                        .inc();
                    tracing::warn!(
                        group = %key.group,
                        filter = %key.filter,
                        topic = %topic,
                        "mqtt shared subscription: no available member, message dropped"
                    );
                }
            }
        }
        // pubsub disconnect (Redis failure etc.): clear the task handle so a later member registration can rebuild the subscription task.
        if let Ok(mut registry) = shared_registry().lock() {
            if let Some(group) = registry.get_mut(&key) {
                group.task = None;
            }
        }
    })
}


// ---------------------------------------------------------------------------
// Connection session
// ---------------------------------------------------------------------------

/// What the write task sends: control packets, outbound PUBLISH messages, and QoS ACKs forwarded from the read loop.
enum Outbound {
    Raw(Packet),
    /// Outbound PUBLISH: the write task allocates the packet id; QoS1 enters the pending map waiting for PUBACK, QoS2 follows the
    /// PUBLISH→PUBREC→PUBREL→PUBCOMP state machine.
    /// A non-empty `ack` = the confirmation the offline-redelivery task needs (triggered when PUBACK for QoS1 / PUBCOMP for QoS2 arrives).
    /// `retain` is set to 1 only when "delivering a retained message on subscribe" (realtime downlink must be 0, MQTT 3.1.1 §3.3.1.3).
    Publish {
        topic: String,
        payload: Vec<u8>,
        qos: u8,
        retain: bool,
        ack: Option<oneshot::Sender<()>>,
        /// MQTT 5 Subscription Identifiers: the write task carries all of them in ascending order in the PUBLISH property block
        /// (automatically ignored on 3.1.1). Empty = this subscription carries no identifier.
        sub_ids: Vec<u32>,
    },
    /// PUBACK received by the read loop: clears the pending QoS1 packet by packet id.
    PubAck { packet_id: u16 },
    /// PUBREC received by the read loop (outbound QoS2): enters the PUBREL stage or drops it per the reason.
    PubRec { packet_id: u16, reason: u8 },
    /// PUBCOMP received by the read loop (outbound QoS2): clears pending.
    PubComp { packet_id: u16 },
}

impl Outbound {
    /// Normal outbound (realtime subscription delivery): needs no redelivery confirmation and carries no retain flag.
    #[allow(dead_code)]
    fn publish(topic: impl Into<String>, payload: Vec<u8>, qos: u8) -> Self {
        Outbound::Publish {
            topic: topic.into(),
            payload,
            qos,
            retain: false,
            ack: None,
            sub_ids: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Outbound Receive Maximum queueing + outbound Topic Alias (write-task exclusive, connection-level state)
// ---------------------------------------------------------------------------

/// Outbound PUBLISH messages queued because the client's Receive Maximum is used up, waiting for an ACK to free quota.
///
/// The queue is bounded ([`OUTBOUND_RECEIVE_QUEUE`]) and strictly FIFO: guarantees the relative order of QoS1/2 packets matches
/// the first delivery (including QoS0: QoS0 also queues when the queue is non-empty, avoiding cross-QoS reordering).
struct QueuedPublish {
    topic: String,
    payload: Vec<u8>,
    qos: u8,
    retain: bool,
    ack: Option<oneshot::Sender<()>>,
    sub_ids: Vec<u32>,
}

impl QueuedPublish {
    fn from_outbound(
        topic: String,
        payload: Vec<u8>,
        qos: u8,
        retain: bool,
        ack: Option<oneshot::Sender<()>>,
        sub_ids: Vec<u32>,
    ) -> Self {
        QueuedPublish { topic, payload, qos, retain, ack, sub_ids }
    }
}

/// Single decision for outbound Topic Alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutAliasDecision {
    /// Not enabled (config off / client Topic Alias Maximum=0 / 3.1.1): full topic, no alias.
    Disabled,
    /// First mapping: full topic + alias (the client establishes the mapping from it).
    New { alias: u16 },
    /// Existing mapping hit: empty topic + alias.
    Reuse { alias: u16 },
}

/// Outbound Topic Alias state (write-task exclusive; MQTT 5 connection-scoped, cleared on disconnect and not restored across sessions).
#[derive(Debug)]
struct OutboundAlias {
    enabled: bool,
    /// Topic Alias Maximum declared in the client CONNECT (1..=65535; 0 = the client accepts no aliases).
    max: u16,
    /// The next alias to allocate (1..=max, monotonically increasing; only grows, never reclaimed, and no new ones once max is used up).
    next: u16,
    /// topic (MQTT wire topic) → alias.
    topics: HashMap<String, u16>,
}

impl OutboundAlias {
    fn new(config_enabled: bool, client_max: u16) -> Self {
        OutboundAlias {
            enabled: config_enabled && client_max > 0,
            max: client_max,
            next: 1,
            topics: HashMap::new(),
        }
    }

    /// Choose an alias decision for one outbound topic; `New` registers the mapping (the mapping lives for the connection's lifetime).
    fn assign(&mut self, topic: &str) -> OutAliasDecision {
        if !self.enabled {
            return OutAliasDecision::Disabled;
        }
        if let Some(alias) = self.topics.get(topic) {
            return OutAliasDecision::Reuse { alias: *alias };
        }
        if self.next <= self.max {
            let alias = self.next;
            self.next = self.next.saturating_add(1);
            self.topics.insert(topic.to_string(), alias);
            return OutAliasDecision::New { alias };
        }
        // The client-provided alias space is exhausted: stop compressing (full topics remain usable, no need to replace old mappings).
        OutAliasDecision::Disabled
    }
}

/// Encode and write one outbound PUBLISH: compress the topic alias as needed, carry Subscription Identifiers,
/// allocate a packet id and register pending for QoS>0 (QoS2 also persists the session).
///
/// The caller guarantees the Receive Maximum quota check has already passed (for QoS>0, `pending.len() < receive_max`).
async fn send_outbound_publish<W: AsyncWrite + Unpin>(
    writer: &mut W,
    level: u8,
    pending: &mut PendingPublishes,
    alias: &mut OutboundAlias,
    out_store: &Option<SessionStore>,
    metrics: &Arc<crate::observe::Metrics>,
    msg: QueuedPublish,
) -> Result<(), CloseReason> {
    let QueuedPublish { topic, payload, qos, retain, ack, sub_ids } = msg;
    let mut props = OutPublishProps { sub_ids: sub_ids.clone(), topic_alias: None };
    let mut wire_topic = topic.clone();
    match alias.assign(&topic) {
        OutAliasDecision::Disabled => {
            metrics
                .mqtt_out_alias_total
                .with_label_values(&["disabled"])
                .inc();
        }
        OutAliasDecision::New { alias: id } => {
            props.topic_alias = Some(id);
            metrics
                .mqtt_out_alias_total
                .with_label_values(&["set"])
                .inc();
        }
        OutAliasDecision::Reuse { alias: id } => {
            props.topic_alias = Some(id);
            wire_topic.clear();
            metrics
                .mqtt_out_alias_total
                .with_label_values(&["used"])
                .inc();
        }
    }
    if qos == 0 {
        let packet =
            encode_publish_with_props(level, &wire_topic, &payload, 0, 0, false, retain, &props);
        if let Err(e) = write_packet(writer, &packet).await {
            tracing::debug!(error = %e, "mqtt writer failed");
            return Err(CloseReason::ConnectionLost);
        }
        // QoS0 has no ACK: the redelivery task needs no wait, so "sent" is triggered immediately.
        if let Some(ack) = ack {
            let _ = ack.send(());
        }
        return Ok(());
    }
    let Some(packet_id) = pending.alloc_free_packet_id() else {
        tracing::warn!("mqtt pending map full (65535 unacked), closing connection");
        return Err(CloseReason::PublishRetryExhausted);
    };
    let packet =
        encode_publish_with_props(level, &wire_topic, &payload, qos, packet_id, false, retain, &props);
    if let Err(e) = write_packet(writer, &packet).await {
        tracing::debug!(error = %e, "mqtt writer failed");
        return Err(CloseReason::ConnectionLost);
    }
    metrics
        .mqtt_receive_max_total
        .with_label_values(&["allowed"])
        .inc();
    pending.register(
        packet_id,
        packet,
        qos,
        topic,
        payload,
        sub_ids,
        ack,
        Instant::now(),
    );
    if qos == 2 {
        persist_outbound(out_store, pending).await;
    }
    Ok(())
}

/// Flush the outbound queue in FIFO order: send one item when the head is QoS0 or the current in-flight count < the client's Receive Maximum.
///
/// In-flight count = pending map size (QoS1/2 PUBLISH messages without PUBACK / PUBCOMP or a failed PUBREC;
/// consistent with the quota definition in MQTT 5 §3.1.2.11.3). Stop immediately when quota is insufficient (head-of-line blocking, preserving order).
async fn flush_outbound_queue<W: AsyncWrite + Unpin>(
    writer: &mut W,
    level: u8,
    pending: &mut PendingPublishes,
    queue: &mut std::collections::VecDeque<QueuedPublish>,
    alias: &mut OutboundAlias,
    receive_max: u16,
    out_store: &Option<SessionStore>,
    metrics: &Arc<crate::observe::Metrics>,
) -> Result<(), CloseReason> {
    loop {
        let Some(front) = queue.front() else {
            return Ok(());
        };
        if front.qos > 0 && pending.len() >= receive_max as usize {
            return Ok(());
        }
        let Some(msg) = queue.pop_front() else {
            return Ok(());
        };
        send_outbound_publish(writer, level, pending, alias, out_store, metrics, msg).await?;
    }
}

// ---------------------------------------------------------------------------
// Subscription/delivery tasks (exact / wildcard / shared)
// ---------------------------------------------------------------------------

/// QoS stage of an outbound packet (write-task exclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishPhase {
    /// QoS1: PUBLISH sent, waiting for PUBACK.
    AwaitPuback,
    /// QoS2: PUBLISH sent, waiting for PUBREC.
    AwaitPubrec,
    /// QoS2: PUBREL sent, waiting for PUBCOMP.
    AwaitPubcomp,
}

impl PublishPhase {
    fn as_str(self) -> &'static str {
        match self {
            PublishPhase::AwaitPuback => "await_puback",
            PublishPhase::AwaitPubrec => "await_pubrec",
            PublishPhase::AwaitPubcomp => "await_pubcomp",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "await_puback" => Some(PublishPhase::AwaitPuback),
            "await_pubrec" => Some(PublishPhase::AwaitPubrec),
            "await_pubcomp" => Some(PublishPhase::AwaitPubcomp),
            _ => None,
        }
    }

    fn is_qos2(self) -> bool {
        matches!(self, PublishPhase::AwaitPubrec | PublishPhase::AwaitPubcomp)
    }
}

/// One outbound packet waiting for an ACK (retransmission needs the original encoded packet and the packet id).
struct PendingPublish {
    /// The first encoded PUBLISH (flags without DUP; the DUP bit is set on a copy for retransmission).
    packet: Packet,
    qos: u8,
    phase: PublishPhase,
    /// Original fields for session persistence (MQTT wire topic = subscription filter, envelope payload bytes).
    filter: String,
    payload: Vec<u8>,
    /// MQTT 5 Subscription Identifiers (re-encoded into the property block when the session is restored and resent; empty = none).
    sub_ids: Vec<u32>,
    retries: u32,
    due: Instant,
    /// Notification channel for the offline-redelivery task; triggered when PUBACK/PUBCOMP arrives.
    ack: Option<oneshot::Sender<()>>,
}

/// Expired-retransmission decision (pure state, making packet-id wraparound/retransmission caps easy to unit test).
#[derive(Debug, PartialEq, Eq)]
enum Retransmit {
    /// Resend: PUBLISH with DUP=1; PUBREL is resent as-is (PUBREL has no DUP bit).
    Resend(Packet),
    /// Cap reached: close the connection
    Exhausted,
}

/// Write-task action after receiving PUBREC (pure state, making the state machine easy to unit test).
#[derive(Debug, PartialEq, Eq)]
enum PubRecAction {
    /// Enter the PUBREL stage: write PUBREL.
    SendPubRel(Packet),
    /// MQTT 5 failure reason (>=0x80): drop that packet (no redelivery success notification).
    Rejected { reason: u8 },
    /// Illegal state machine (a PUBREC for a QoS1 packet/a packet already in PUBREL).
    ProtocolError,
    /// Unknown packet id: MQTT 5 replies PUBREL(0x92); 3.1.1 replies PUBREL (the peer should ignore it).
    Unknown,
}

/// Write-task action after receiving PUBCOMP.
#[derive(Debug, PartialEq, Eq)]
enum PubCompAction {
    /// Clear normally and trigger the redelivery confirmation.
    Completed,
    /// Unknown/mismatched packet id (protocol-wise ignorable; counted as error).
    Unknown,
}

/// Outbound QoS1/QoS2 packet-id allocation and ACK tracking (write-task exclusive, lock-free, unit-testable).
struct PendingPublishes {
    level: u8,
    next_packet_id: u16,
    timeout: Duration,
    max_retransmits: u32,
    entries: HashMap<u16, PendingPublish>,
}

impl PendingPublishes {
    fn new(level: u8, timeout: Duration, max_retransmits: u32) -> Self {
        PendingPublishes {
            level,
            next_packet_id: 1,
            timeout,
            max_retransmits,
            entries: HashMap::new(),
        }
    }

    /// Next packet id: 1..=65535 cyclically (0 is an illegal id, skipped on wraparound).
    fn alloc_packet_id(&mut self) -> u16 {
        let id = self.next_packet_id;
        self.next_packet_id = if id == u16::MAX { 1 } else { id + 1 };
        id
    }

    /// Allocate a packet id **not currently in use** (defending against the extreme case of >65535 unacked packets);
    /// returns None when all ids are pending (the caller disconnects on this, avoiding overwriting an unacknowledged packet).
    fn alloc_free_packet_id(&mut self) -> Option<u16> {
        for _ in 0..=u16::MAX {
            let id = self.alloc_packet_id();
            if !self.entries.contains_key(&id) {
                return Some(id);
            }
        }
        None
    }

    fn max_retransmits(&self) -> u32 {
        self.max_retransmits
    }

    /// Register a packet that has been written; `now` is passed by the caller (for unit testing). QoS0 does not enter the map.
    #[allow(clippy::too_many_arguments)]
    fn register(
        &mut self,
        packet_id: u16,
        packet: Packet,
        qos: u8,
        filter: String,
        payload: Vec<u8>,
        sub_ids: Vec<u32>,
        ack: Option<oneshot::Sender<()>>,
        now: Instant,
    ) {
        let phase = match qos {
            1 => PublishPhase::AwaitPuback,
            _ => PublishPhase::AwaitPubrec,
        };
        let due = now + self.timeout;
        self.entries.insert(
            packet_id,
            PendingPublish { packet, qos, phase, filter, payload, sub_ids, retries: 0, due, ack },
        );
    }

    /// On PUBACK: clear and trigger the redelivery notification; returns whether the entry existed.
    fn ack(&mut self, packet_id: u16) -> bool {
        match self.entries.remove(&packet_id) {
            Some(entry) => {
                if let Some(ack) = entry.ack {
                    let _ = ack.send(());
                }
                true
            }
            None => false,
        }
    }

    /// On PUBREC (the first outbound QoS2 step).
    fn on_pubrec(&mut self, packet_id: u16, reason: u8, now: Instant) -> PubRecAction {
        let timeout = self.timeout;
        let phase = match self.entries.get(&packet_id) {
            Some(entry) => entry.phase,
            None => return PubRecAction::Unknown,
        };
        if phase != PublishPhase::AwaitPubrec {
            return PubRecAction::ProtocolError;
        }
        // MQTT 5: a PUBREC failure reason (>=0x80) means the receiver rejected it, so the sender drops the packet.
        if reason >= 0x80 {
            self.entries.remove(&packet_id);
            return PubRecAction::Rejected { reason };
        }
        if let Some(entry) = self.entries.get_mut(&packet_id) {
            entry.phase = PublishPhase::AwaitPubcomp;
            entry.retries = 0;
            entry.due = now + timeout;
        }
        PubRecAction::SendPubRel(pubrel(self.level, packet_id, REASON_SUCCESS))
    }

    /// On PUBCOMP (outbound QoS2 complete): clear and trigger the redelivery notification.
    fn on_pubcomp(&mut self, packet_id: u16) -> PubCompAction {
        match self.entries.get(&packet_id) {
            Some(entry) if entry.phase == PublishPhase::AwaitPubcomp => {
                self.ack(packet_id);
                PubCompAction::Completed
            }
            _ => PubCompAction::Unknown,
        }
    }

    /// Expired (`now >= due`) packet ids, returned ascending (stable retransmission order).
    fn due_ids(&self, now: Instant) -> Vec<u16> {
        let mut ids: Vec<u16> = self
            .entries
            .iter()
            .filter(|(_, e)| e.due <= now)
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// The next instant the write task must be woken (None when there are no entries).
    fn next_due(&self) -> Option<Instant> {
        self.entries.values().map(|e| e.due).min()
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Expiry retransmission: below the cap → return the packet to resend and advance retries/due; at the cap → Exhausted.
    ///
    /// - Waiting for PUBACK/PUBREC: resend PUBLISH with DUP=1 (same packet id/body);
    /// - Waiting for PUBCOMP: resend PUBREL as-is (the PUBREL fixed header has no DUP bit).
    fn retransmit(&mut self, packet_id: u16, now: Instant) -> Option<Retransmit> {
        let timeout = self.timeout;
        let max_retransmits = self.max_retransmits;
        let level = self.level;
        let entry = self.entries.get_mut(&packet_id)?;
        if entry.retries >= max_retransmits {
            return Some(Retransmit::Exhausted);
        }
        entry.retries += 1;
        entry.due = now + timeout;
        if entry.phase == PublishPhase::AwaitPubcomp {
            return Some(Retransmit::Resend(pubrel(level, packet_id, REASON_SUCCESS)));
        }
        let mut packet = entry.packet.clone();
        // DUP flag (MQTT 3.1.1 §3.3.1.1 / MQTT 5 §3.3.1.1): fixed-header bit3.
        packet.flags |= 0x08;
        Some(Retransmit::Resend(packet))
    }

    /// Session persistence snapshot: persist only **QoS2** unfinished packets (QoS1 keeps the existing "reconnect clears pending" semantics).
    fn snapshot(&self) -> Vec<PersistedOutbound> {
        let mut out: Vec<PersistedOutbound> = self
            .entries
            .iter()
            .filter(|(_, e)| e.qos == 2)
            .map(|(id, e)| PersistedOutbound {
                packet_id: *id,
                filter: e.filter.clone(),
                payload_b64: lattice_core::envelope::base64_encode(&e.payload),
                qos: e.qos,
                phase: e.phase.as_str().to_string(),
                sub_ids: e.sub_ids.clone(),
            })
            .collect();
        out.sort_by_key(|e| e.packet_id);
        out
    }

    /// Restore outbound QoS2 packets of a persistent session (called at write-task startup; returns the packets to resend immediately).
    fn restore(&mut self, restored: &[PersistedOutbound], now: Instant) -> Vec<Packet> {
        let level = self.level;
        let timeout = self.timeout;
        let mut resend = Vec::with_capacity(restored.len());
        for item in restored.iter().take(SESSION_OUTBOUND_MAX) {
            let Some(payload) = lattice_core::envelope::base64_decode(&item.payload_b64) else {
                continue;
            };
            let Some(phase) = PublishPhase::from_str(&item.phase) else {
                continue;
            };
            if !phase.is_qos2() || self.entries.contains_key(&item.packet_id) {
                continue;
            }
            // Continue with the original packet id after reconnect: waiting for PUBREC → resend PUBLISH(DUP=1); waiting for PUBCOMP → resend PUBREL.
            // Subscription Identifiers are persisted with the session and re-encoded into the PUBLISH properties on resend (alias is not restored:
            // Topic Alias is connection-level state, cleared on reconnect, so a resend must use the full topic).
            let packet = encode_publish_with_props(
                level,
                &item.filter,
                &payload,
                item.qos.min(2),
                item.packet_id,
                phase == PublishPhase::AwaitPubrec,
                false,
                &OutPublishProps {
                    sub_ids: item.sub_ids.clone(),
                    topic_alias: None,
                },
            );
            if phase == PublishPhase::AwaitPubcomp {
                resend.push(pubrel(level, item.packet_id, REASON_SUCCESS));
            } else {
                let mut publish = packet.clone();
                publish.flags |= 0x08;
                resend.push(publish);
            }
            self.entries.insert(
                item.packet_id,
                PendingPublish {
                    packet,
                    qos: item.qos.min(2),
                    phase,
                    filter: item.filter.clone(),
                    payload,
                    sub_ids: item.sub_ids.clone(),
                    retries: 0,
                    due: now + timeout,
                    ack: None,
                },
            );
        }
        resend
    }
}

// ---------------------------------------------------------------------------
// Persistent session (clean=false / MQTT 5 Session Expiry) and retained / WILL
// ---------------------------------------------------------------------------

/// A persisted subscription entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct PersistedSub {
    filter: String,
    topic: String,
    qos: u8,
    /// MQTT 5 Subscription Identifier (absent in older session JSON → None, backward compatible).
    #[serde(default)]
    sub_id: Option<u32>,
}

/// A persisted inbound QoS2 stash entry (before PUBREL; `done=true` means persisted but the PUBCOMP may have been lost).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedInboundQos2 {
    packet_id: u16,
    filter: String,
    topic: String,
    payload_b64: String,
    content_type: Option<String>,
    ttl_secs: Option<u32>,
    #[serde(default)]
    retain: bool,
    env_id: String,
    done: bool,
}

/// Session "reader state" snapshot (subscription table + inbound QoS2 stash + offline redelivery watermark).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct PersistedSessionState {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    subs: Vec<PersistedSub>,
    #[serde(default)]
    inbound_qos2: Vec<PersistedInboundQos2>,
    #[serde(default)]
    replay_offsets: HashMap<String, u64>,
}

/// Persisted entry for an unfinished outbound QoS2 packet.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedOutbound {
    packet_id: u16,
    filter: String,
    payload_b64: String,
    qos: u8,
    phase: String,
    /// MQTT 5 Subscription Identifiers (absent in older session JSON → empty, backward compatible).
    #[serde(default)]
    sub_ids: Vec<u32>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct PersistedOutboundState {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    pending: Vec<PersistedOutbound>,
}

/// Session persistence handle (reader-state/writer-state keys are written separately so read/write tasks do not overwrite each other).
#[derive(Clone)]
struct SessionStore {
    redis: crate::store::Redis,
    state_key: String,
    out_key: String,
    ttl_secs: u64,
}

impl SessionStore {
    fn new(
        redis: crate::store::Redis,
        user: &str,
        device: &str,
        client_id: &str,
        ttl_secs: u64,
    ) -> Self {
        SessionStore {
            redis,
            state_key: session_state_key(user, device, client_id),
            out_key: session_outbound_key(user, device, client_id),
            ttl_secs,
        }
    }

    async fn load_state(&self) -> PersistedSessionState {
        match self.redis.get_json(&self.state_key).await {
            Ok(Some(raw)) => serde_json::from_str(&raw).unwrap_or_else(|e| {
                tracing::warn!(error = %e, key = %self.state_key, "mqtt session state decode failed, treat as empty");
                PersistedSessionState::default()
            }),
            Ok(None) => PersistedSessionState::default(),
            Err(e) => {
                tracing::warn!(error = %e, "mqtt session state read failed (degraded: no restore)");
                PersistedSessionState::default()
            }
        }
    }

    async fn load_outbound(&self) -> PersistedOutboundState {
        match self.redis.get_json(&self.out_key).await {
            Ok(Some(raw)) => serde_json::from_str(&raw).unwrap_or_else(|e| {
                tracing::warn!(error = %e, key = %self.out_key, "mqtt session outbound decode failed, treat as empty");
                PersistedOutboundState::default()
            }),
            Ok(None) => PersistedOutboundState::default(),
            Err(e) => {
                tracing::warn!(error = %e, "mqtt session outbound read failed (degraded: no restore)");
                PersistedOutboundState::default()
            }
        }
    }

    /// Read the session: `(state, outbound, present)`; present = at least one key exists.
    async fn load(&self) -> (PersistedSessionState, PersistedOutboundState, bool) {
        let state_present = matches!(self.redis.get_json(&self.state_key).await, Ok(Some(_)));
        let out_present = matches!(self.redis.get_json(&self.out_key).await, Ok(Some(_)));
        (
            self.load_state().await,
            self.load_outbound().await,
            state_present || out_present,
        )
    }

    async fn save_state(&self, state: &PersistedSessionState) {
        let Ok(raw) = serde_json::to_string(state) else {
            return;
        };
        if let Err(e) = self.redis.set_json(&self.state_key, &raw, self.ttl_secs).await {
            tracing::warn!(error = %e, "mqtt session state save failed");
        }
    }

    async fn save_outbound(&self, pending: &[PersistedOutbound]) {
        let state = PersistedOutboundState { version: 1, pending: pending.to_vec() };
        let Ok(raw) = serde_json::to_string(&state) else {
            return;
        };
        if let Err(e) = self.redis.set_json(&self.out_key, &raw, self.ttl_secs).await {
            tracing::warn!(error = %e, "mqtt session outbound save failed");
        }
    }

    /// Update only one filter's offline redelivery watermark (read-modify-write, best-effort; a concurrent window only affects the redelivery dedup hint).
    async fn patch_replay_offset(&self, filter: &str, offset: u64) {
        let mut state = self.load_state().await;
        state.replay_offsets.insert(filter.to_string(), offset);
        self.save_state(&state).await;
    }

    /// Delete both session keys; returns "whether a session really existed before deletion" (for accurate `session_total{result=cleaned}` counting).
    async fn clear(&self) -> bool {
        let state_exists = matches!(self.redis.get_json(&self.state_key).await, Ok(Some(_)));
        let out_exists = if state_exists {
            true
        } else {
            matches!(self.redis.get_json(&self.out_key).await, Ok(Some(_)))
        };
        let _ = self.redis.del(&self.state_key).await;
        let _ = self.redis.del(&self.out_key).await;
        state_exists || out_exists
    }
}

/// Message dispatch note: `retained` stores the latest entry per filter as a Redis string (JSON).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RetainedMessage {
    payload_b64: String,
    qos: u8,
    content_type: Option<String>,
    ttl_secs: Option<u32>,
    /// The publisher's user id (retained is globally visible; used only for logs/troubleshooting, never returned to clients).
    #[serde(default)]
    sender: String,
    #[serde(default)]
    stored_at: u64,
}

impl RetainedMessage {
    fn from_publish(publish: &Publish, sender: &str) -> Self {
        RetainedMessage {
            payload_b64: lattice_core::envelope::base64_encode(&publish.payload),
            qos: publish.qos.min(2),
            content_type: publish.props.content_type.clone(),
            ttl_secs: publish.props.ttl_secs,
            sender: sender.to_string(),
            stored_at: chrono::Utc::now().timestamp() as u64,
        }
    }

    fn decode_payload(&self) -> Option<Vec<u8>> {
        lattice_core::envelope::base64_decode(&self.payload_b64)
    }
}

/// retained save/clear (a retain=1 publish with an empty payload means delete).
async fn retained_store(
    state: &AppState,
    filter: &str,
    topic: &str,
    publish: &Publish,
    sender: &str,
) {
    if publish.payload.is_empty() {
        let key = retained_key(topic, &device_of_filter(filter));
        match state.redis.del(&key).await {
            Ok(()) => {
                state
                    .metrics
                    .mqtt_retained_total
                    .with_label_values(&["deleted"])
                    .inc();
            }
            Err(e) => tracing::warn!(error = %e, "mqtt retained delete failed"),
        }
        return;
    }
    let key = retained_key(topic, &device_of_filter(filter));
    let meta = RetainedMessage::from_publish(publish, sender);
    let Ok(raw) = serde_json::to_string(&meta) else {
        return;
    };
    let ttl = state.cfg.mqtt.retained_ttl_secs.max(1);
    match state.redis.set_json(&key, &raw, ttl).await {
        Ok(()) => {
            state
                .metrics
                .mqtt_retained_total
                .with_label_values(&["stored"])
                .inc();
        }
        Err(e) => tracing::warn!(error = %e, "mqtt retained save failed"),
    }
}

/// Take the device segment from `lattice/{topic}/{device}` (already validated by `map_topic` before the call, so it always exists).
fn device_of_filter(filter: &str) -> String {
    filter.rsplit('/').next().unwrap_or_default().to_string()
}

/// Read one retained entry (missing/corrupt → None).
async fn retained_load(state: &AppState, filter: &str, topic: &str) -> Option<(RetainedMessage, Vec<u8>)> {
    let key = retained_key(topic, &device_of_filter(filter));
    let raw = match state.redis.get_json(&key).await {
        Ok(Some(raw)) => raw,
        Ok(None) => return None,
        Err(e) => {
            tracing::warn!(error = %e, "mqtt retained read failed");
            return None;
        }
    };
    let meta: RetainedMessage = match serde_json::from_str(&raw) {
        Ok(meta) => meta,
        Err(e) => {
            tracing::warn!(error = %e, "mqtt retained decode failed");
            return None;
        }
    };
    let payload = meta.decode_payload()?;
    Some((meta, payload))
}

/// WILL connection-level state (saved at CONNECT; published on abnormal disconnect; discarded on a normal DISCONNECT).
#[derive(Debug, Clone)]
struct WillState {
    /// MQTT wire topic (`lattice/{topic}/{device}`, used for PUBLISH and the retained key).
    filter: String,
    /// Lattice topic (the `map_topic` result).
    topic: String,
    payload: Vec<u8>,
    qos: u8,
    retain: bool,
    props: WillProps,
    delay_secs: u32,
}


/// Session-end reason (only for logs and debugging; also decides whether to publish the WILL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseReason {
    /// The client sent a normal DISCONNECT (no WILL).
    ClientDisconnect,
    /// MQTT 5 `DISCONNECT(reason=0x04)`: a normal disconnect that **requires publishing the WILL** (MQTT 5 §3.14.2.1).
    ClientDisconnectWithWill,
    KeepAliveTimeout,
    ConnectionLost,
    ProtocolError,
    TopicInvalid,
    TopicNotAuthorized,
    QuotaExceeded,
    /// Outbound QoS1/QoS2 reached the maximum retransmissions without an ACK (triggered by the write task; the read loop disconnects on it).
    PublishRetryExhausted,
    /// Inbound persistence failed (MQTT 3.1.1 has no failure reason: no ACK, just disconnect; the client reconnects and retries).
    IngestFailed,
}

impl CloseReason {
    fn as_str(self) -> &'static str {
        match self {
            CloseReason::ClientDisconnect => "client-disconnect",
            CloseReason::ClientDisconnectWithWill => "client-disconnect-with-will",
            CloseReason::KeepAliveTimeout => "keepalive-timeout",
            CloseReason::ConnectionLost => "connection-lost",
            CloseReason::ProtocolError => "protocol-error",
            CloseReason::TopicInvalid => "topic-invalid",
            CloseReason::TopicNotAuthorized => "topic-not-authorized",
            CloseReason::QuotaExceeded => "quota-exceeded",
            CloseReason::PublishRetryExhausted => "publish-retry-exhausted",
            CloseReason::IngestFailed => "ingest-failed",
        }
    }

    /// Whether this counts as an "abnormal disconnect" (which requires publishing the WILL): only DISCONNECT (except reason=0x04) does not.
    fn abnormal(self) -> bool {
        !matches!(
            self,
            CloseReason::ClientDisconnect | CloseReason::ClientDisconnectWithWill
        )
    }

    /// Whether to publish the WILL: an abnormal disconnect, or an explicit MQTT 5 Disconnect with Will.
    fn publish_will(self) -> bool {
        self.abnormal() || self == CloseReason::ClientDisconnectWithWill
    }
}


/// Connection identity after successful auth (⑤ §11: PSK token ↔ devices.token_hash).
#[derive(Debug, Clone)]
struct Identity {
    user_id: String,
    device_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthFailure {
    BadCredentials,
    NotAuthorized,
    Unavailable,
}

impl AuthFailure {
    /// `(MQTT 3.1.1 CONNACK code, MQTT 5 reason code)`
    fn codes(self) -> (u8, u8) {
        match self {
            AuthFailure::BadCredentials => (CONNACK_BAD_CREDENTIALS, REASON_BAD_CREDENTIALS),
            AuthFailure::NotAuthorized => (CONNACK_NOT_AUTHORIZED, REASON_NOT_AUTHORIZED),
            AuthFailure::Unavailable => (CONNACK_SERVER_UNAVAILABLE, REASON_SERVER_UNAVAILABLE),
        }
    }
}

fn connack_code(level: u8, failure: AuthFailure) -> u8 {
    let (v311, v5) = failure.codes();
    if level == 5 {
        v5
    } else {
        v311
    }
}

/// Dedup record for inbound QoS1 retransmission on the same connection (same packet id + DUP=1 + same payload → reuse the envelope id).
#[derive(Debug, Clone)]
struct InboundQos1 {
    env_id: String,
    topic: String,
    payload_hash: u64,
    payload_len: usize,
}

fn payload_fingerprint(payload: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    payload.hash(&mut hasher);
    hasher.finish()
}

/// Inbound QoS2 stash entry: PUBLISH received (PUBREC replied), persisted only at PUBREL.
#[derive(Debug, Clone)]
struct InboundQos2 {
    /// MQTT wire topic (`lattice/{topic}/{device}`, used for logs and the loopback topic).
    filter: String,
    /// Lattice topic (the `map_topic` result).
    topic: String,
    payload: Vec<u8>,
    props: PublishProps,
    retain: bool,
    /// Envelope id pre-allocated at PUBLISH time: reused on reconnect/a repeated PUBREL → `message_dedup` dedups it.
    env_id: String,
    /// Already persisted (the PUBCOMP may have been lost): a repeated PUBREL only replies PUBCOMP without persisting again.
    done: bool,
}

/// Subscription type (the delivery path must be distinguished after adding wildcards / shared subscriptions).
enum SubKind {
    /// Exact subscription `lattice/{topic}/{device}`: has a concrete Lattice topic and participates in PG membership + offline redelivery.
    Exact { topic: String },
    /// Wildcard subscription: the normalized Lattice topic path pattern (online realtime; no PG membership/redelivery).
    Wildcard { pattern: String },    /// Shared subscription `$share/{group}/{filter}`: normalized pattern + in-group member id (used for unregistering).
    Shared { group: String, pattern: String, member_id: Option<u64> },
}

/// A subscription within a session (pubsub task + the offline redelivery task for that filter).
struct Subscription {
    kind: SubKind,
    qos: u8,
    /// MQTT 5 Subscription Identifier (the 0x0B property of this subscription's SUBSCRIBE; None on 3.1.1/when not carried).
    sub_id: Option<u32>,
    task: Option<JoinHandle<()>>,
    replay: Option<JoinHandle<()>>,
}

impl Subscription {
    /// The Lattice topic an exact subscription maps to (None for wildcard/shared).
    fn exact_topic(&self) -> Option<&str> {
        match &self.kind {
            SubKind::Exact { topic } => Some(topic),
            _ => None,
        }
    }
}

/// Offline redelivery watermark (session-level, filter → the topic offset last acknowledged).
type SharedReplayOffsets = Arc<Mutex<HashMap<String, u64>>>;

/// Session state: identity, subscription table, downlink queue, and the local rate-limit fallback bucket.
struct ConnSession {
    level: u8,
    user_id: String,
    device_id: String,
    client_id: String,
    out: mpsc::Sender<Outbound>,
    /// Whether to save the session on disconnect (clean=false / MQTT 5 session expiry > 0).
    persistent: bool,
    /// Session persistence handle (`None` = no persistence).
    session_store: Option<SessionStore>,
    /// MQTT topic filter → subscription (pubsub task + redelivery task).
    subs: HashMap<String, Subscription>,
    /// Lattice topic → session id cache (inbound publishing needs the conv_id; avoids a DB lookup per message).
    topic_conv: HashMap<String, String>,
    /// Recently processed inbound QoS1 packet ids → envelope id/payload fingerprint (retransmission dedup, see the module comment).
    inbound_qos1: HashMap<u16, InboundQos1>,
    /// Inbound QoS2 stash (before PUBREL / done and awaiting cleanup).
    inbound_qos2: HashMap<u16, InboundQos2>,
    /// Offline redelivery watermark (shared by the redelivery task and persistence).
    replay_offsets: SharedReplayOffsets,
    /// Match snapshot of normal subscriptions (exact + wildcard): the Redis downlink task uses it to pick the max matching QoS and dedup.
    plain_filters: Arc<Mutex<Vec<PlainFilter>>>,
    /// Realtime downlink dedup window (deliver once when the same message matches multiple filters).
    delivery_dedupe: Arc<Mutex<DeliveryDedupe>>,
    /// Inbound Topic Alias mapping (MQTT 5, connection-level; cleared on disconnect and not restored with a persistent session).
    topic_aliases: HashMap<u16, String>,
    /// MQTT 5 server Receive Maximum (this gateway fills it in CONNACK when the client CONNECT declares it;
    /// Some = advertised, so inbound QoS1/2 in-flight counts are validated and exceeding them → DISCONNECT 0x93).
    /// None = not advertised (the client assumes the default 65535, no extra validation, keeping only the INBOUND_QOS2_CAP defense).
    inbound_receive_max: Option<u16>,
    /// The WILL saved at CONNECT (discarded on a normal DISCONNECT).
    will: Option<WillState>,
    redis: Option<RedisLink>,
    local_bucket: LocalBucket,
}

impl ConnSession {
    async fn send_raw(&self, packet: Packet) -> bool {
        self.out.send(Outbound::Raw(packet)).await.is_ok()
    }

    /// Inbound QoS1 retransmission decision: DUP=1 with the same packet id/topic/payload → return the envelope id allocated first.
    fn retransmitted_env_id(&self, publish: &Publish) -> Option<String> {
        if !publish.dup || publish.qos != 1 {
            return None;
        }
        let packet_id = publish.packet_id?;
        let prev = self.inbound_qos1.get(&packet_id)?;
        let same_topic = prev.topic == publish.topic;
        let same_payload = prev.payload_len == publish.payload.len()
            && prev.payload_hash == payload_fingerprint(&publish.payload);
        (same_topic && same_payload).then(|| prev.env_id.clone())
    }

    /// Record the envelope id of a successfully accepted inbound QoS1 (reused by retransmission on the same connection → pipeline dedup hit).
    fn remember_inbound_qos1(
        &mut self,
        packet_id: u16,
        topic: &str,
        env_id: &str,
        payload: &[u8],
    ) {
        if self.inbound_qos1.len() >= INBOUND_QOS1_DEDUP_CAP {
            self.inbound_qos1.clear();
        }
        self.inbound_qos1.insert(
            packet_id,
            InboundQos1 {
                env_id: env_id.to_string(),
                topic: topic.to_string(),
                payload_hash: payload_fingerprint(payload),
                payload_len: payload.len(),
            },
        );
    }

    /// 10 msg/s per device; the Redis counter is preferred (consistent across connections/restart windows), falling back to this connection's local bucket on failure.
    async fn allow_ingress(&mut self, state: &AppState) -> bool {
        let key = keys::ratelimit_mqtt(&self.device_id);
        match state.redis.bump_rate(&key, 1).await {
            Ok(count) => !quota_exceeded(count, DEVICE_MSG_PER_SEC),
            Err(e) => {
                tracing::debug!(error = %e, "mqtt rate counter unavailable, fallback to local bucket");
                self.local_bucket.allow(DEVICE_MSG_PER_SEC as u64)
            }
        }
    }

    fn log_identity(&self) -> (String, String) {
        (
            crate::observe::Metrics::user_hash(&self.user_id),
            self.device_id.clone(),
        )
    }

    /// Inbound QoS2 in-flight count (PUBREC replied, waiting for PUBREL persistence; `done` entries already persisted do not count).
    ///
    /// QoS1 is processed serially inside the frame loop (PUBACK immediately after persistence succeeds), so in-flight is ≤1 and not counted separately.
    /// Used for server Receive Maximum validation: `outstanding + 1` for a new inbound PUBLISH must not exceed the advertised cap.
    fn inbound_outstanding(&self) -> usize {
        self.inbound_qos2.values().filter(|item| !item.done).count()
    }

    /// Register normal-subscription match information (exact/wildcard).
    fn add_plain_filter(&self, filter: PlainFilter) {
        if let Ok(mut filters) = self.plain_filters.lock() {
            filters.push(filter);
        }
    }

    /// Remove the match information for one original filter (UNSUBSCRIBE / restore rebuild).
    fn remove_plain_filter(&self, raw: &str) {
        if let Ok(mut filters) = self.plain_filters.lock() {
            filters.retain(|filter| filter.raw != raw);
        }
    }

    /// Build the session "reader state" persistence snapshot (subscription table + inbound QoS2 stash + redelivery watermark).
    fn session_state_snapshot(&self) -> PersistedSessionState {
        let mut subs: Vec<PersistedSub> = self
            .subs
            .iter()
            .map(|(filter, sub)| PersistedSub {
                filter: filter.clone(),
                topic: sub.exact_topic().unwrap_or_default().to_string(),
                qos: sub.qos,
                sub_id: sub.sub_id,
            })
            .collect();
        subs.sort_by(|a, b| a.filter.cmp(&b.filter));
        let mut inbound: Vec<PersistedInboundQos2> = self
            .inbound_qos2
            .iter()
            .take(SESSION_INBOUND_MAX)
            .map(|(packet_id, item)| PersistedInboundQos2 {
                packet_id: *packet_id,
                filter: item.filter.clone(),
                topic: item.topic.clone(),
                payload_b64: lattice_core::envelope::base64_encode(&item.payload),
                content_type: item.props.content_type.clone(),
                ttl_secs: item.props.ttl_secs,
                retain: item.retain,
                env_id: item.env_id.clone(),
                done: item.done,
            })
            .collect();
        inbound.sort_by_key(|item| item.packet_id);
        let replay_offsets = self
            .replay_offsets
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default();
        PersistedSessionState {
            version: 1,
            subs,
            inbound_qos2: inbound,
            replay_offsets,
        }
    }

    /// Persist the session "reader state" (subscriptions/inbound QoS2/redelivery watermark); a no-op for non-persistent sessions/no store.
    async fn persist_state(&self) {
        if !self.persistent {
            return;
        }
        let Some(store) = self.session_store.clone() else {
            return;
        };
        let snapshot = self.session_state_snapshot();
        store.save_state(&snapshot).await;
    }
}

/// Restore persisted entries into in-memory state (entries that fail to decode/exceed limits are dropped with a warn).
fn restore_inbound_qos2(restored: &[PersistedInboundQos2]) -> HashMap<u16, InboundQos2> {
    let mut map = HashMap::new();
    for item in restored.iter().take(SESSION_INBOUND_MAX) {
        let Some(payload) = lattice_core::envelope::base64_decode(&item.payload_b64) else {
            continue;
        };
        map.insert(
            item.packet_id,
            InboundQos2 {
                filter: item.filter.clone(),
                topic: item.topic.clone(),
                payload,
                props: PublishProps {
                    content_type: item.content_type.clone(),
                    ttl_secs: item.ttl_secs,
                    ..Default::default()
                },
                retain: item.retain,
                env_id: item.env_id.clone(),
                done: item.done,
            },
        );
    }
    map
}


// ---------------------------------------------------------------------------
// Authentication (⑤ §11: PSK token = refresh token; devices.token_hash stores only the hash)
// ---------------------------------------------------------------------------

async fn authenticate(state: &AppState, connect: &Connect) -> Result<Identity, AuthFailure> {
    let Some(username) = connect.username.as_deref() else {
        return Err(AuthFailure::BadCredentials);
    };
    let Some(password) = connect.password.as_deref() else {
        return Err(AuthFailure::BadCredentials);
    };
    let token = std::str::from_utf8(password).map_err(|_| AuthFailure::BadCredentials)?;
    let hash = crate::auth::password::hash_refresh(token);

    let device = crate::store::pg::device_by_token_hash(&state.db, &hash)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "mqtt auth device lookup failed");
            AuthFailure::Unavailable
        })?
        .ok_or(AuthFailure::BadCredentials)?;
    // The SQL already filters `revoked_at is null`; re-check here so a modified query cannot silently let a revoked device through.
    if device.revoked_at.is_some() {
        return Err(AuthFailure::BadCredentials);
    }

    // username may be the device id (recommended) or a username; when using a username it must belong to the same user as the token's device.
    if username != device.id {
        let named = crate::store::pg::user_by_username(&state.db, username)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "mqtt auth username lookup failed");
                AuthFailure::Unavailable
            })?;
        match named {
            Some(user) if user.id == device.user_id => {}
            _ => return Err(AuthFailure::NotAuthorized),
        }
    }

    let user = crate::store::pg::user_by_id(&state.db, &device.user_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "mqtt auth user lookup failed");
            AuthFailure::Unavailable
        })?
        .ok_or(AuthFailure::NotAuthorized)?;
    if user.status != "active" {
        tracing::warn!(user = %crate::observe::Metrics::user_hash(&user.id), status = %user.status, "mqtt connect rejected: user not active");
        return Err(AuthFailure::NotAuthorized);
    }

    Ok(Identity { user_id: user.id, device_id: device.id })
}

// ---------------------------------------------------------------------------
// TLS / mTLS + X.509 device identity (PL-11)
// ---------------------------------------------------------------------------
//
// Design notes (consistent with the task card):
// - Certificate parsing takes only the SAN URI / rfc822Name (email) / Subject CN. The repo does not pull in x509-parser
//   (no new crates in the offline vendor set), so a **minimal DER TLV parser** covers the fixed X.509 structure here;
//   Any parse failure is treated as "no usable identity" (fail-closed: never panic, never guess).
// - Identity string format: `lattice://user/<user>/device/<device>` (recommended) or `<user>@<device>`;
//   a Subject CN may also contain only `<device>` (the user is then looked up in PG `devices.user_id`). The user segment accepts
//   a user id or username; the device segment must be a device id.
// - The certificate chain itself is validated by rustls `WebPkiClientVerifier` (the client_ca trust anchor); here we only do
//   **post-handshake identity mapping + PG ownership/revocation checks + CONNECT anti-impersonation checks**.
// - Logs print only `peer` / user hash / device id, **never certificate/private key content**.

/// Maximum length of the user/device segments of a certificate identity (anything longer is illegal, keeping abnormal values out of logs/DB).
const CERT_ID_MAX_LEN: usize = 128;

/// OID `2.5.4.3` (Subject CommonName).
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// OID `2.5.29.17` (SubjectAltName).
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];

/// Candidate names available from the TLS client certificate (SAN URI / rfc822Name / Subject CN).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CertNames {
    uris: Vec<String>,
    emails: Vec<String>,
    cns: Vec<String>,
}

/// The lattice identity declared by a certificate; `user=None` = the certificate declared only a device (CN form), so the user is looked up in PG.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CertName {
    user: Option<String>,
    device: String,
}

/// TLS client certificate identity state after the handshake (settled before the MQTT CONNECT).
#[derive(Debug, Clone, PartialEq, Eq)]
enum TlsClientIdentity {
    /// The client presented no certificate (possible only with `require_client_cert=false`): fall back to PSK/JWT semantics.
    NoCert,
    /// A certificate was presented and a lattice identity was parsed from it.
    Parsed(CertName),
    /// A certificate was presented but no lattice identity could be parsed: fail-closed rejection.
    Unparsable,
}

/// Reason for TLS client certificate auth failure; `as_str()` is the metric label value (low cardinality — do not add values casually).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsAuthFailure {
    NoCert,
    BadCert,
    UnknownIdentity,
    DeviceMismatch,
}

impl TlsAuthFailure {
    fn as_str(self) -> &'static str {
        match self {
            TlsAuthFailure::NoCert => "no_cert",
            TlsAuthFailure::BadCert => "bad_cert",
            TlsAuthFailure::UnknownIdentity => "unknown_identity",
            TlsAuthFailure::DeviceMismatch => "device_mismatch",
        }
    }
}

/// Allowed character set for the user/device segments in a certificate: ids (ULID/UUID) and usernames (alphanumerics `-_.:`).
///
/// This only narrows to "looks like an id" (rejecting whitespace/control characters/NUL); authority comes from the PG lookup.
fn valid_cert_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= CERT_ID_MAX_LEN
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

/// Parse `lattice://user/<user>/device/<device>` (`rest` = the part after `lattice://`).
fn parse_uri_identity(rest: &str) -> Option<CertName> {
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let mut segments = rest.split('/');
    match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (Some("user"), Some(user), Some("device"), Some(device), None)
            if valid_cert_id(user) && valid_cert_id(device) =>
        {
            Some(CertName { user: Some(user.to_string()), device: device.to_string() })
        }
        _ => None,
    }
}

/// Parse an identity string from a certificate: `lattice://user/<user>/device/<device>` or `<user>@<device>`.
fn parse_identity_value(raw: &str) -> Option<CertName> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix("lattice://") {
        return parse_uri_identity(rest);
    }
    let (user, device) = raw.split_once('@')?;
    if valid_cert_id(user) && valid_cert_id(device) {
        Some(CertName { user: Some(user.to_string()), device: device.to_string() })
    } else {
        None
    }
}

/// Compatibility form where the CN contains only a device id (the user is looked up in PG `devices.user_id`).
fn parse_device_only(raw: &str) -> Option<CertName> {
    let raw = raw.trim();
    if valid_cert_id(raw) && !raw.contains('@') && !raw.contains("://") {
        Some(CertName { user: None, device: raw.to_string() })
    } else {
        None
    }
}

/// Pick one usable lattice identity by priority SAN URI → SAN email → Subject CN.
fn resolve_cert_name(names: &CertNames) -> Option<CertName> {
    for raw in names.uris.iter().chain(names.emails.iter()) {
        if let Some(name) = parse_identity_value(raw) {
            return Some(name);
        }
    }
    for raw in &names.cns {
        if let Some(name) = parse_identity_value(raw) {
            return Some(name);
        }
        if let Some(name) = parse_device_only(raw) {
            return Some(name);
        }
    }
    None
}

/// Read one DER TLV: `(tag, value, next_offset)`; an illegal/out-of-range length returns `None` (fail-closed).
fn der_read_tlv(buf: &[u8], pos: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *buf.get(pos)?;
    let mut idx = pos + 1;
    let first_len = *buf.get(idx)?;
    idx += 1;
    let len = if first_len & 0x80 == 0 {
        first_len as usize
    } else {
        let n = (first_len & 0x7f) as usize;
        // DER lengths are at most 4 bytes (X.509 objects are far below 4GiB); the 0x80 indefinite length is illegal in DER.
        if n == 0 || n > 4 {
            return None;
        }
        let mut value = 0usize;
        for _ in 0..n {
            value = (value << 8) | *buf.get(idx)? as usize;
            idx += 1;
        }
        value
    };
    let end = idx.checked_add(len)?;
    let value = buf.get(idx..end)?;
    Some((tag, value, end))
}

/// Collect all CNs in the Subject Name (`Name ::= SEQUENCE OF SET OF AttributeTypeAndValue`).
fn collect_subject_cns(subject: &[u8]) -> Option<Vec<String>> {
    let mut cns = Vec::new();
    let mut pos = 0usize;
    while pos < subject.len() {
        let (rdn_tag, rdn, next) = der_read_tlv(subject, pos)?;
        pos = next;
        if rdn_tag != 0x31 {
            return None; // An RDN must be a SET
        }
        let mut atv_pos = 0usize;
        while atv_pos < rdn.len() {
            let (atv_tag, atv, atv_next) = der_read_tlv(rdn, atv_pos)?;
            atv_pos = atv_next;
            if atv_tag != 0x30 {
                return None; // AttributeTypeAndValue must be a SEQUENCE
            }
            let (oid_tag, oid, oid_next) = der_read_tlv(atv, 0)?;
            if oid_tag != 0x06 || oid != OID_COMMON_NAME {
                continue;
            }
            let (value_tag, value, _) = der_read_tlv(atv, oid_next)?;
            // DirectoryString (UTF8String/PrintableString/TeletexString) or IA5String.
            if matches!(value_tag, 0x0C | 0x13 | 0x14 | 0x16) {
                if let Ok(text) = std::str::from_utf8(value) {
                    cns.push(text.to_string());
                }
            }
        }
    }
    Some(cns)
}

/// Parse SubjectAltName inside Extensions (`[3] EXPLICIT Extensions`): URI / rfc822Name.
fn collect_subject_alt_names(exts: &[u8], names: &mut CertNames) -> Option<()> {
    let mut pos = 0usize;
    while pos < exts.len() {
        let (ext_tag, ext, next) = der_read_tlv(exts, pos)?;
        pos = next;
        if ext_tag != 0x30 {
            return None; // An Extension must be a SEQUENCE
        }
        let (oid_tag, oid, mut inner) = der_read_tlv(ext, 0)?;
        if oid_tag != 0x06 {
            return None;
        }
        if oid != OID_SUBJECT_ALT_NAME {
            continue;
        }
        // Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
        let (maybe_critical, _, after_critical) = der_read_tlv(ext, inner)?;
        if maybe_critical == 0x01 {
            inner = after_critical;
        }
        let (octet_tag, san_bytes, _) = der_read_tlv(ext, inner)?;
        if octet_tag != 0x04 {
            return None;
        }
        let (san_tag, san, _) = der_read_tlv(san_bytes, 0)?;
        if san_tag != 0x30 {
            return None;
        }
        let mut sp = 0usize;
        while sp < san.len() {
            let (general_tag, value, general_next) = der_read_tlv(san, sp)?;
            sp = general_next;
            match general_tag {
                // GeneralName ::= [1] rfc822Name (IA5String, context-specific primitive)
                0x81 => {
                    if let Ok(text) = std::str::from_utf8(value) {
                        names.emails.push(text.to_string());
                    }
                }
                // GeneralName ::= [6] uniformResourceIdentifier (IA5String)
                0x86 => {
                    if let Ok(text) = std::str::from_utf8(value) {
                        names.uris.push(text.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    Some(())
}

/// Extract the SAN URI / email / Subject CN from the leaf certificate DER; returns `None` when the structure is invalid.
fn extract_cert_names(der: &[u8]) -> Option<CertNames> {
    let (cert_tag, cert_body, _) = der_read_tlv(der, 0)?;
    if cert_tag != 0x30 {
        return None;
    }
    let (tbs_tag, tbs, _) = der_read_tlv(cert_body, 0)?;
    if tbs_tag != 0x30 {
        return None;
    }
    let mut pos = 0usize;
    // version [0] EXPLICIT Version DEFAULT v1 (may be absent)
    let (tag, _, next) = der_read_tlv(tbs, pos)?;
    if tag == 0xA0 {
        pos = next;
    }
    // serialNumber INTEGER
    let (tag, _, next) = der_read_tlv(tbs, pos)?;
    pos = next;
    if tag != 0x02 {
        return None;
    }
    // signature AlgorithmIdentifier / issuer Name / validity Time are all SEQUENCE
    for _ in 0..2 {
        let (tag, _, next) = der_read_tlv(tbs, pos)?;
        pos = next;
        if tag != 0x30 {
            return None;
        }
    }
    // validity
    let (tag, _, next) = der_read_tlv(tbs, pos)?;
    pos = next;
    if tag != 0x30 {
        return None;
    }
    // subject Name (CN candidates)
    let (subject_tag, subject, next) = der_read_tlv(tbs, pos)?;
    pos = next;
    if subject_tag != 0x30 {
        return None;
    }
    let mut names = CertNames { cns: collect_subject_cns(subject)?, ..Default::default() };
    // subjectPublicKeyInfo (skip the content)
    let (spki_tag, _, next) = der_read_tlv(tbs, pos)?;
    pos = next;
    if spki_tag != 0x30 {
        return None;
    }
    // Optional fields: issuerUniqueID [1] / subjectUniqueID [2] / extensions [3]
    while pos < tbs.len() {
        let (tag, value, next) = der_read_tlv(tbs, pos)?;
        pos = next;
        if tag == 0xA3 {
            let (exts_tag, exts, _) = der_read_tlv(value, 0)?;
            if exts_tag != 0x30 {
                return None;
            }
            collect_subject_alt_names(exts, &mut names)?;
        }
    }
    Some(names)
}

/// Derive the identity state from the client leaf certificate DER (both "no usable identity" and "unparseable certificate structure" are fail-closed).
fn parse_client_identity(der: &[u8]) -> TlsClientIdentity {
    match extract_cert_names(der) {
        Some(names) => match resolve_cert_name(&names) {
            Some(name) => TlsClientIdentity::Parsed(name),
            None => TlsClientIdentity::Unparsable,
        },
        None => TlsClientIdentity::Unparsable,
    }
}

/// Read a PEM certificate chain (the first certificate is the leaf; multiple allowed). An empty file/no certificate = error (fail-closed).
fn load_pem_certificates(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("open tls cert {path}: {e}")))?;
    let mut reader = BufReader::new(file);
    let mut out = Vec::new();
    for item in rustls_pemfile::certs(&mut reader) {
        match item {
            Ok(cert) => out.push(cert),
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parse tls cert {path}: {e}"),
                ))
            }
        }
    }
    if out.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no PEM certificate in {path}"),
        ));
    }
    Ok(out)
}

/// Read a PEM private key (PKCS#8 / PKCS#1 / SEC1 all accepted). An empty file/no key = error (fail-closed).
fn load_pem_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("open tls key {path}: {e}")))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("parse tls key {path}: {e}")))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("no PEM private key in {path}"),
            )
        })
}

/// Assemble the rustls server configuration (a separate function so unit tests can build it directly from in-memory certificates).
///
/// - `require_client_cert=true`: `client_ca` is mandatory (otherwise fail-closed, refusing to start the TLS listener);
/// - `require_client_cert=false` and no `client_ca`: do not request a client certificate (plain TLS + PSK/JWT);
/// - `require_client_cert=false` with a `client_ca`: request but do not require it; a presented certificate is still validated against the trust anchor.
fn build_tls_server_config(
    server_certs: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_ca: Vec<CertificateDer<'static>>,
    require_client_cert: bool,
) -> io::Result<Arc<ServerConfig>> {
    let builder = ServerConfig::builder();
    let builder = if client_ca.is_empty() {
        if require_client_cert {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mqtt.require_client_cert=true but mqtt.client_ca is empty (fail-closed)",
            ));
        }
        builder.with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        for cert in client_ca {
            roots.add(cert).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("load mqtt.client_ca trust anchor: {e}"),
                )
            })?;
        }
        let verifier = if require_client_cert {
            WebPkiClientVerifier::builder(Arc::new(roots)).build()
        } else {
            WebPkiClientVerifier::builder(Arc::new(roots))
                .allow_unauthenticated()
                .build()
        }
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("build mqtt client cert verifier: {e}"),
            )
        })?;
        builder.with_client_cert_verifier(verifier)
    };
    let mut config = builder.with_single_cert(server_certs, server_key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("load mqtt tls server cert/key: {e}"),
        )
    })?;
    config.alpn_protocols = vec![TLS_ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// Load the TLS server configuration from `[mqtt]` config (read PEM + assemble the rustls config).
fn load_tls_server_config(cfg: &crate::config::MqttCfg) -> io::Result<Arc<ServerConfig>> {
    if cfg.tls_cert.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mqtt.tls_enabled=true but mqtt.tls_cert is empty",
        ));
    }
    if cfg.tls_key.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mqtt.tls_enabled=true but mqtt.tls_key is empty",
        ));
    }
    let server_certs = load_pem_certificates(&cfg.tls_cert)?;
    let server_key = load_pem_private_key(&cfg.tls_key)?;
    let client_ca = if cfg.client_ca.trim().is_empty() {
        Vec::new()
    } else {
        load_pem_certificates(&cfg.client_ca)?
    };
    build_tls_server_config(server_certs, server_key, client_ca, cfg.require_client_cert)
}

/// Classify a TLS handshake error into a certificate-auth metric label; IO/protocol errors unrelated to certificates return `None`
/// (only `mqtt_tls_connections_total{result=fail}` is counted, without polluting the certificate-auth counter).
fn classify_tls_handshake_error(err: &io::Error) -> Option<TlsAuthFailure> {
    let inner = err
        .get_ref()?
        .downcast_ref::<tokio_rustls::rustls::Error>()?;
    match inner {
        tokio_rustls::rustls::Error::NoCertificatesPresented => Some(TlsAuthFailure::NoCert),
        // Expired/wrong CA/bad signature/incomplete chain all appear inside InvalidCertificate(...).
        tokio_rustls::rustls::Error::InvalidCertificate(_) => Some(TlsAuthFailure::BadCert),
        _ => None,
    }
}

/// Whether the CONNECT username matches the certificate identity (anti-impersonation: a certificate must not be used to impersonate another user/device).
///
/// Accepted forms (the certificate is authoritative for the device identity; the username must not point at another device):
/// - the device id (recommended);
/// - the certificate user's user id or username (the device is uniquely determined by the certificate);
/// - `<user>@<device>` (the user segment may be a user id or username; the device segment must equal the certificate's device).
fn connect_username_matches(
    username: &str,
    user: &crate::store::pg::User,
    device: &crate::store::pg::Device,
) -> bool {
    if username == device.id || username == user.id || username == user.username {
        return true;
    }
    match username.split_once('@') {
        Some((claimed_user, claimed_device)) => {
            claimed_device == device.id
                && (claimed_user == user.id || claimed_user == user.username)
        }
        None => false,
    }
}

/// TLS client certificate auth: PG identity mapping (user/device exist, ownership, revocation, active) + CONNECT anti-impersonation.
async fn authenticate_tls(
    state: &AppState,
    connect: &Connect,
    cert_name: &CertName,
) -> Result<Identity, TlsAuthFailure> {
    let device = crate::store::pg::device_by_id(&state.db, &cert_name.device)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "mqtt tls auth device lookup failed");
            TlsAuthFailure::UnknownIdentity
        })?
        .ok_or_else(|| {
            tracing::warn!("mqtt tls auth rejected: device not found");
            TlsAuthFailure::UnknownIdentity
        })?;
    if device.revoked_at.is_some() {
        tracing::warn!(
            device = %device.id,
            "mqtt tls auth rejected: device revoked"
        );
        return Err(TlsAuthFailure::DeviceMismatch);
    }
    // The user segment accepts a user id or username; when omitted, it is looked up from device.user_id.
    let user = match cert_name.user.as_deref() {
        Some(claimed) => {
            let by_id = crate::store::pg::user_by_id(&state.db, claimed)
                .await
                .map_err(|e| {
                    tracing::warn!(error = %e, "mqtt tls auth user lookup failed");
                    TlsAuthFailure::UnknownIdentity
                })?;
            let found = match by_id {
                Some(user) => Some(user),
                None => crate::store::pg::user_by_username(&state.db, claimed)
                    .await
                    .map_err(|e| {
                        tracing::warn!(error = %e, "mqtt tls auth username lookup failed");
                        TlsAuthFailure::UnknownIdentity
                    })?,
            };
            match found {
                Some(user) if user.id == device.user_id => user,
                Some(user) => {
                    tracing::warn!(
                        user = %crate::observe::Metrics::user_hash(&user.id),
                        device = %device.id,
                        "mqtt tls auth rejected: device does not belong to certificate user"
                    );
                    return Err(TlsAuthFailure::DeviceMismatch);
                }
                None => {
                    tracing::warn!("mqtt tls auth rejected: certificate user not found");
                    return Err(TlsAuthFailure::UnknownIdentity);
                }
            }
        }
        None => crate::store::pg::user_by_id(&state.db, &device.user_id)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "mqtt tls auth user lookup failed");
                TlsAuthFailure::UnknownIdentity
            })?
            .ok_or_else(|| {
                tracing::warn!("mqtt tls auth rejected: device owner user not found");
                TlsAuthFailure::UnknownIdentity
            })?,
    };
    if user.status != "active" {
        tracing::warn!(
            user = %crate::observe::Metrics::user_hash(&user.id),
            status = %user.status,
            "mqtt tls auth rejected: user not active"
        );
        return Err(TlsAuthFailure::DeviceMismatch);
    }
    // Anti-impersonation: the certificate already determines user/device, so the CONNECT username must not point at someone else/another device.
    let username = connect.username.as_deref().unwrap_or_default();
    if !connect_username_matches(username, &user, &device) {
        tracing::warn!(
            user = %crate::observe::Metrics::user_hash(&user.id),
            device = %device.id,
            "mqtt tls auth rejected: CONNECT username/device does not match certificate identity"
        );
        return Err(TlsAuthFailure::DeviceMismatch);
    }
    Ok(Identity { user_id: user.id, device_id: device.id })
}

// ---------------------------------------------------------------------------
// Packet dispatch
// ---------------------------------------------------------------------------

async fn dispatch(
    state: &Arc<AppState>,
    session: &mut ConnSession,
    packet: Packet,
) -> Option<CloseReason> {
    match packet.kind {
        PACKET_PUBLISH => handle_publish(state, session, &packet).await,
        PACKET_PUBREL => handle_pubrel(state, session, &packet).await,
        PACKET_PUBACK => match parse_puback(&packet.body) {
            // Outbound QoS1 ACK: forwarded to the write task to clear the pending map (the write task owns pending state).
            // try_send: when the queue is full, prefer letting that item trigger one retransmission (at-least-once) over blocking the read loop.
            Some(packet_id) => {
                if session
                    .out
                    .try_send(Outbound::PubAck { packet_id })
                    .is_err()
                {
                    tracing::debug!(packet_id, "mqtt puback dropped: outbound queue full");
                }
                None
            }
            None => {
                protocol_error(session, "malformed PUBACK").await;
                Some(CloseReason::ProtocolError)
            }
        },
        PACKET_PUBREC => match parse_qos_ack(&packet.body) {
            Some((packet_id, reason)) => {
                if session
                    .out
                    .try_send(Outbound::PubRec { packet_id, reason })
                    .is_err()
                {
                    tracing::debug!(packet_id, "mqtt pubrec dropped: outbound queue full");
                }
                None
            }
            None => {
                protocol_error(session, "malformed PUBREC").await;
                Some(CloseReason::ProtocolError)
            }
        },
        PACKET_PUBCOMP => match parse_qos_ack(&packet.body) {
            Some((packet_id, _reason)) => {
                if session
                    .out
                    .try_send(Outbound::PubComp { packet_id })
                    .is_err()
                {
                    tracing::debug!(packet_id, "mqtt pubcomp dropped: outbound queue full");
                }
                None
            }
            None => {
                protocol_error(session, "malformed PUBCOMP").await;
                Some(CloseReason::ProtocolError)
            }
        },
        PACKET_SUBSCRIBE => handle_subscribe(state, session, &packet).await,
        PACKET_UNSUBSCRIBE => handle_unsubscribe(state, session, &packet).await,
        PACKET_PINGREQ => {
            if session.send_raw(pingresp()).await {
                None
            } else {
                Some(CloseReason::ConnectionLost)
            }
        }
        PACKET_DISCONNECT => handle_disconnect(session, &packet).await,
        PACKET_CONNECT => {
            protocol_error(session, "duplicate CONNECT").await;
            Some(CloseReason::ProtocolError)
        }
        other => {
            protocol_error(session, &format!("unsupported packet type {other}")).await;
            Some(CloseReason::ProtocolError)
        }
    }
}

/// MQTT 5 signals a protocol error with DISCONNECT(0x82); 3.1.1 just disconnects (no equivalent packet).
async fn protocol_error(session: &mut ConnSession, detail: &str) {
    let (user, device) = session.log_identity();
    tracing::warn!(user = %user, device = %device, detail, "mqtt protocol error, closing connection");
    if session.level == 5 {
        let _ = session.send_raw(disconnect(REASON_PROTOCOL_ERROR)).await;
    }
}

/// Handle DISCONNECT: a normal disconnect publishes no WILL; MQTT 5 `reason=0x04` requires publishing the WILL;
/// the MQTT 5 Session Expiry Interval property can override the session TTL (0 = clear the session on disconnect).
async fn handle_disconnect(session: &mut ConnSession, packet: &Packet) -> Option<CloseReason> {
    let (reason, session_expiry) = match parse_disconnect(&packet.body) {
        Ok(parsed) => parsed,
        Err(e) => {
            protocol_error(session, &format!("malformed DISCONNECT: {e}")).await;
            return Some(CloseReason::ProtocolError);
        }
    };
    if let Some(expiry) = session_expiry {
        if expiry == 0 {
            // Disconnect ends the session: do not save it, and delete the leftover Redis session during cleanup.
            session.persistent = false;
            if let Some(store) = session.session_store.clone() {
                store.clear().await;
            }
        } else if let Some(store) = &mut session.session_store {
            store.ttl_secs = expiry as u64;
            session.persistent = true;
        }
    }
    if reason == REASON_DISCONNECT_WITH_WILL {
        return Some(CloseReason::ClientDisconnectWithWill);
    }
    Some(CloseReason::ClientDisconnect)
}

/// Unified persistence path for an inbound PUBLISH: build the envelope → `pipeline::ingest` → realtime loopback when not a duplicate.
///
/// The caller handles rate limiting/ACK/failure reasons; this function only does "persist + loopback", called directly for QoS0/1,
/// at PUBREL for QoS2, and when the server publishes a WILL on the client's behalf.
#[allow(clippy::too_many_arguments)]
async fn ingest_publish_once(
    state: &Arc<AppState>,
    user_id: &str,
    device_id: &str,
    redis: Option<&RedisLink>,
    topic_conv: &mut HashMap<String, String>,
    filter: &str,
    topic: &str,
    publish: &Publish,
    env_id_override: Option<String>,
) -> LatticeResult<crate::pipeline::IngestOutcome> {
    let conv_id = ensure_publish_topic(state, topic_conv, user_id, device_id, topic).await?;
    let mut envelope = envelope_from_publish(topic, user_id, publish);
    envelope.conv_id = conv_id;
    if let Some(env_id) = env_id_override {
        envelope.id = env_id;
    }
    let echo_body = envelope.encode_body();
    // Exactly the same pipeline as WS `envelope` frames: messages/seq/message_dedup/routing all apply.
    let outcome = crate::pipeline::ingest(state, user_id, device_id, envelope).await?;
    if !outcome.duplicate {
        // Cross-node realtime downlink: online MQTT subscribers receive the same envelope bytes from the Redis channel.
        match redis {
            Some(link) => {
                if let Err(e) = link.publish(&keys::channel_mqtt(topic), &echo_body).await {
                    tracing::warn!(
                        user = %crate::observe::Metrics::user_hash(user_id),
                        device = %device_id,
                        topic = %topic,
                        error = %e,
                        "mqtt realtime publish failed"
                    );
                }
            }
            None => {
                tracing::debug!(topic = %topic, "mqtt realtime fanout skipped: redis unavailable");
            }
        }
    }
    tracing::debug!(
        user = %crate::observe::Metrics::user_hash(user_id),
        device = %device_id,
        filter = %filter,
        topic = %topic,
        id = %outcome.id,
        seq = outcome.seq,
        duplicate = outcome.duplicate,
        bytes = publish.payload.len(),
        "mqtt publish persisted"
    );
    Ok(outcome)
}

async fn handle_publish(
    state: &Arc<AppState>,
    session: &mut ConnSession,
    packet: &Packet,
) -> Option<CloseReason> {
    let mut publish = match parse_publish(packet.flags, &packet.body, session.level) {
        Ok(p) => p,
        Err(e) => {
            protocol_error(session, &format!("malformed PUBLISH: {e}")).await;
            return Some(CloseReason::ProtocolError);
        }
    };
    let (user, device) = session.log_identity();

    // QoS allowlist (QoS3 is already rejected by parse_publish; this guards against future changes).
    if !qos_supported(publish.qos) {
        protocol_error(session, &format!("unsupported publish qos {}", publish.qos)).await;
        return Some(CloseReason::ProtocolError);
    }

    // MQTT 5 server Receive Maximum (advertised in CONNACK 0x21) validation: the client's inbound QoS1/2 in-flight count must not
    // exceed the advertised cap. Only validated when this connection really advertised that property (see the negotiation in handle_stream).
    // - QoS1 is processed serially inside the frame loop (PUBACK immediately after persistence), so in-flight is ≤1; this mainly constrains QoS2;
    // - a repeated PUBLISH (a QoS2 stash with the same packet id / a QoS1 retransmission dedup hit) does not take quota twice;
    // - over the limit: reply DISCONNECT(0x93 Receive Maximum exceeded) per MQTT 5 §3.3.4, then disconnect.
    if publish.qos > 0 {
        if let Some(max) = session.inbound_receive_max {
            let duplicate = publish
                .packet_id
                .map(|id| session.inbound_qos2.contains_key(&id))
                .unwrap_or(false)
                || session.retransmitted_env_id(&publish).is_some();
            if !duplicate && session.inbound_outstanding() + 1 > max as usize {
                state
                    .metrics
                    .mqtt_receive_max_total
                    .with_label_values(&["violation"])
                    .inc();
                tracing::warn!(
                    user = %user,
                    device = %device,
                    outstanding = session.inbound_outstanding(),
                    receive_maximum = max,
                    "mqtt inbound receive maximum exceeded, closing connection"
                );
                if session.level == 5 {
                    let _ = session
                        .send_raw(disconnect(REASON_RECEIVE_MAXIMUM_EXCEEDED))
                        .await;
                }
                return Some(CloseReason::QuotaExceeded);
            }
        }
    }

    // MQTT 5 Topic Alias (§3.3.2.3.4): an empty topic + alias restores the topic from the session-level mapping;
    // a non-empty topic + alias creates/updates alias→topic once the mapping has been validated. 3.1.1 has no property block, so it is always None.
    let mut alias_to_set: Option<u16> = None;
    if session.level == 5 {
        let alias_max = state.cfg.mqtt.topic_alias_max;
        match resolve_topic_alias(
            &session.topic_aliases,
            alias_max,
            publish.props.topic_alias,
            &publish.topic,
        ) {
            AliasOutcome::None => {}
            AliasOutcome::Set => alias_to_set = publish.props.topic_alias,
            AliasOutcome::Used(mapped) => {
                state
                    .metrics
                    .mqtt_alias_total
                    .with_label_values(&["used"])
                    .inc();
                publish.topic = mapped;
            }
            AliasOutcome::Error(kind) => {
                state
                    .metrics
                    .mqtt_alias_total
                    .with_label_values(&["error"])
                    .inc();
                tracing::warn!(
                    user = %user, device = %device, reason = %kind.as_str(),
                    alias = ?publish.props.topic_alias, "mqtt topic alias invalid"
                );
                let _ = session.send_raw(disconnect(kind.reason())).await;
                return Some(CloseReason::ProtocolError);
            }
        }
    }

    // Topic mapping and device binding (⑤ §11).
    let topic = match map_topic(&publish.topic, &session.device_id) {
        Ok(topic) => topic,
        Err(e) => {
            tracing::warn!(user = %user, device = %device, topic = %publish.topic, reason = ?e, "mqtt publish topic rejected");
            if session.level == 5 {
                let _ = session.send_raw(disconnect(e.disconnect_reason())).await;
            }
            return Some(match e {
                TopicError::Invalid => CloseReason::TopicInvalid,
                TopicError::DeviceMismatch => CloseReason::TopicNotAuthorized,
            });
        }
    };

    // The alias mapping is only recorded after the topic passes validation (preventing an illegal/unauthorized topic from entering the session mapping).
    if let Some(alias) = alias_to_set {
        session.topic_aliases.insert(alias, publish.topic.clone());
        state
            .metrics
            .mqtt_alias_total
            .with_label_values(&["set"])
            .inc();
        tracing::debug!(user = %user, device = %device, alias, topic = %publish.topic, "mqtt topic alias set");
    }

    if publish.qos == 2 {
        // ---- Inbound QoS2: stash + PUBREC, persisting only at PUBREL (see the module comment) ----
        let Some(packet_id) = publish.packet_id else {
            protocol_error(session, "qos2 publish without packet id").await;
            return Some(CloseReason::ProtocolError);
        };
        if session.inbound_qos2.contains_key(&packet_id) {
            // A repeated PUBLISH with the same packet id (the sender resent because it missed PUBREC): reply only PUBREC,
            // without re-persisting or re-looping (PL-11: the core assertion of QoS2 dedup semantics).
            state
                .metrics
                .mqtt_qos2_total
                .with_label_values(&["pubrec"])
                .inc();
            let _ = session.send_raw(pubrec(session.level, packet_id, REASON_SUCCESS)).await;
            tracing::debug!(user = %user, device = %device, packet_id, "mqtt qos2 duplicate publish ignored");
            return None;
        }
        if session.inbound_qos2.len() >= INBOUND_QOS2_CAP {
            tracing::warn!(user = %user, device = %device, cap = INBOUND_QOS2_CAP, "mqtt inbound qos2 staging full");
            state
                .metrics
                .mqtt_qos2_total
                .with_label_values(&["error"])
                .inc();
            if session.level == 5 {
                let _ = session.send_raw(disconnect(REASON_QUOTA_EXCEEDED)).await;
            }
            return Some(CloseReason::QuotaExceeded);
        }
        // A repeated PUBLISH does not consume rate-limit quota; only the first acceptance counts.
        if !session.allow_ingress(state).await {
            tracing::warn!(user = %user, device = %device, "mqtt qos2 publish rate limited");
            state
                .metrics
                .mqtt_qos2_total
                .with_label_values(&["error"])
                .inc();
            if session.level == 5 {
                let _ = session
                    .send_raw(pubrec(5, packet_id, REASON_QUOTA_EXCEEDED))
                    .await;
                return None;
            }
            return Some(CloseReason::QuotaExceeded);
        }
        session.inbound_qos2.insert(
            packet_id,
            InboundQos2 {
                filter: publish.topic.clone(),
                topic,
                payload: publish.payload.clone(),
                props: publish.props.clone(),
                retain: publish.retain,
                env_id: lattice_core::ids::new_id(),
                done: false,
            },
        );
        session.persist_state().await;
        if !session.send_raw(pubrec(session.level, packet_id, REASON_SUCCESS)).await {
            return Some(CloseReason::ConnectionLost);
        }
        state
            .metrics
            .mqtt_qos2_total
            .with_label_values(&["pubrec"])
            .inc();
        return None;
    }

    // ---- Inbound QoS0/QoS1 (keeping the existing behavior) ----
    // Inbound QoS1 retransmission on the same connection (DUP=1 + same packet id + same payload): reuse the envelope id allocated first,
    // absorbed by pipeline's message_dedup; the retransmission does not consume per-device rate-limit quota (client behavior, not a new message).
    let retransmitted = session.retransmitted_env_id(&publish);

    // 10 msg/s per device; over the limit: for MQTT 5 QoS1 reply PUBACK 0x97 (connection kept), otherwise disconnect.
    if retransmitted.is_none() && !session.allow_ingress(state).await {
        tracing::warn!(user = %user, device = %device, "mqtt publish rate limited");
        if session.level == 5 && publish.qos == 1 {
            if let Some(packet_id) = publish.packet_id {
                let _ = session
                    .send_raw(puback(5, packet_id, REASON_QUOTA_EXCEEDED))
                    .await;
            }
            return None;
        }
        if session.level == 5 {
            let _ = session.send_raw(disconnect(REASON_QUOTA_EXCEEDED)).await;
        }
        return Some(CloseReason::QuotaExceeded);
    }

    match ingest_publish_once(
        state,
        &session.user_id.clone(),
        &session.device_id.clone(),
        session.redis.as_ref(),
        &mut session.topic_conv,
        &publish.topic,
        &topic,
        &publish,
        retransmitted,
    )
    .await
    {
        Ok(outcome) => {
            if let Some(packet_id) = publish.packet_id {
                session.remember_inbound_qos1(
                    packet_id,
                    &publish.topic,
                    &outcome.id,
                    &publish.payload,
                );
            }
            // retained (saved after a successful QoS0/1 persist; retain with an empty payload means delete).
            if publish.retain {
                retained_store(state, &publish.topic, &topic, &publish, &session.user_id).await;
            }
            // QoS1: PUBACK is sent **only after persistence succeeds** (the success path).
            if publish.qos == 1 {
                if let Some(packet_id) = publish.packet_id {
                    if !session
                        .send_raw(puback(session.level, packet_id, REASON_SUCCESS))
                        .await
                    {
                        return Some(CloseReason::ConnectionLost);
                    }
                }
            }
            None
        }
        Err(e) => {
            reject_ingest_failure(state, session, &publish, &user, &device, &topic, &e).await
        }
    }
}

/// PUBREL of inbound QoS2: reply PUBCOMP **only after persistence succeeds**; a repeated PUBREL that hits a done record only replies PUBCOMP.
async fn handle_pubrel(
    state: &Arc<AppState>,
    session: &mut ConnSession,
    packet: &Packet,
) -> Option<CloseReason> {
    let Some((packet_id, _reason)) = parse_qos_ack(&packet.body) else {
        protocol_error(session, "malformed PUBREL").await;
        return Some(CloseReason::ProtocolError);
    };
    let (user, device) = session.log_identity();
    let Some(entry) = session.inbound_qos2.get(&packet_id).cloned() else {
        // Unknown packet id: MQTT 5 replies PUBCOMP(0x92); 3.1.1 has no failure reason, so reply a successful PUBCOMP.
        state
            .metrics
            .mqtt_qos2_total
            .with_label_values(&["error"])
            .inc();
        let reason = if session.level == 5 {
            REASON_PACKET_ID_NOT_FOUND
        } else {
            REASON_SUCCESS
        };
        let _ = session.send_raw(pubcomp(session.level, packet_id, reason)).await;
        tracing::debug!(user = %user, device = %device, packet_id, "mqtt pubrel for unknown packet id");
        return None;
    };

    if entry.done {
        // Persisted already but the previous PUBCOMP may have been lost: just clean up and re-send PUBCOMP, never persist twice.
        session.inbound_qos2.remove(&packet_id);
        session.persist_state().await;
        let _ = session.send_raw(pubcomp(session.level, packet_id, REASON_SUCCESS)).await;
        state
            .metrics
            .mqtt_qos2_total
            .with_label_values(&["pubcomp"])
            .inc();
        return None;
    }

    let publish = Publish {
        topic: entry.filter.clone(),
        qos: 2,
        dup: false,
        retain: entry.retain,
        packet_id: Some(packet_id),
        props: entry.props.clone(),
        payload: entry.payload.clone(),
    };
    match ingest_publish_once(
        state,
        &session.user_id.clone(),
        &session.device_id.clone(),
        session.redis.as_ref(),
        &mut session.topic_conv,
        &entry.filter,
        &entry.topic,
        &publish,
        Some(entry.env_id.clone()),
    )
    .await
    {
        Ok(_outcome) => {
            if entry.retain {
                retained_store(state, &entry.filter, &entry.topic, &publish, &session.user_id).await;
            }
            session.inbound_qos2.remove(&packet_id);
            session.persist_state().await;
            state
                .metrics
                .mqtt_qos2_total
                .with_label_values(&["pubcomp"])
                .inc();
            if !session.send_raw(pubcomp(session.level, packet_id, REASON_SUCCESS)).await {
                return Some(CloseReason::ConnectionLost);
            }
            tracing::debug!(user = %user, device = %device, packet_id, "mqtt qos2 delivered on pubrel");
            None
        }
        Err(e) => {
            // **Never reply PUBCOMP without persistence**: pass the failure reason to wherever the protocol can express it (MQTT 5 DISCONNECT),
            // and keep the entry in the session (persisted when clean=false) so the client can resend PUBREL after reconnecting.
            let reason = ingest_failure_reason(&e);
            state
                .metrics
                .mqtt_ingest_failed_total
                .with_label_values(&[reason.label])
                .inc();
            state
                .metrics
                .mqtt_qos2_total
                .with_label_values(&["error"])
                .inc();
            tracing::warn!(
                user = %user, device = %device, packet_id, code = %e.code.as_str(),
                detail = %e.message, "mqtt qos2 pubrel ingest failed (will not send PUBCOMP)"
            );
            session.persist_state().await;
            if session.level == 5 {
                let _ = session.send_raw(disconnect(reason.code)).await;
            }
            Some(CloseReason::IngestFailed)
        }
    }
}

/// Ensure the Lattice topic conversation exists and the sender is a member (a precondition of `pipeline::ingest`), returning `conv_id`.
///
/// The MQTT gateway has no device-level publish ACL (the SUBSCRIBE stage validates only the device segment), so "publish implies subscribe"
/// is equivalent to SUBSCRIBE first and amplifies no permissions; the result is cached in the connection, avoiding a DB lookup per message.
async fn ensure_publish_topic(
    state: &AppState,
    topic_conv: &mut HashMap<String, String>,
    user_id: &str,
    device_id: &str,
    topic: &str,
) -> LatticeResult<String> {
    if let Some(conv) = topic_conv.get(topic) {
        return Ok(conv.clone());
    }
    let existing = crate::store::pg::topic_conv_id(&state.db, topic).await?;
    let member = match &existing {
        Some(conv) => crate::store::pg::member_role(&state.db, conv, user_id).await?.is_some(),
        None => false,
    };
    if !member {
        crate::routing::topic::subscribe(state, user_id, topic).await?;
        tracing::info!(
            user = %crate::observe::Metrics::user_hash(user_id),
            device = %device_id,
            topic = %topic,
            "mqtt publish auto-subscribed sender (publish implies subscribe)"
        );
    }
    let conv = crate::store::pg::topic_conv_id(&state.db, topic)
        .await?
        .ok_or_else(|| crate::error::internal("topic conversation missing after subscribe"))?;
    topic_conv.insert(topic.to_string(), conv.clone());
    Ok(conv)
}

/// Inbound persistence failure → MQTT 5 PUBACK reason code and metric label (0x97 / 0x87 / 0x80).
struct IngestFailureReason {
    code: u8,
    label: &'static str,
}

fn ingest_failure_reason(e: &LatticeError) -> IngestFailureReason {
    match e.code {
        ErrorCode::Rate | ErrorCode::Quota => IngestFailureReason {
            code: REASON_QUOTA_EXCEEDED,
            label: "rate",
        },
        ErrorCode::AuthFail | ErrorCode::Forbidden => IngestFailureReason {
            code: REASON_NOT_AUTHORIZED,
            label: "forbidden",
        },
        ErrorCode::Protocol | ErrorCode::Format | ErrorCode::TooLarge => IngestFailureReason {
            code: REASON_UNSPECIFIED_ERROR,
            label: "protocol",
        },
        _ => IngestFailureReason {
            code: REASON_UNSPECIFIED_ERROR,
            label: "persist",
        },
    }
}

/// Unified rejection path for persistence failure: count + log (no payload), then reply the protocol-appropriate failure reason/disconnect.
///
/// - MQTT 5 QoS1: reply PUBACK(reason) (`0x97`/`0x87`/`0x80`), keeping the connection (the client can decide to retry);
/// - MQTT 3.1.1 / QoS0: no failure-ACK semantics exist — disconnect, and the client resends after reconnecting (at-least-once;
///   the resend is absorbed by `message_dedup`, so there is no double write).
async fn reject_ingest_failure(
    state: &Arc<AppState>,
    session: &mut ConnSession,
    publish: &Publish,
    user: &str,
    device: &str,
    topic: &str,
    e: &LatticeError,
) -> Option<CloseReason> {
    let reason = ingest_failure_reason(e);
    state
        .metrics
        .mqtt_ingest_failed_total
        .with_label_values(&[reason.label])
        .inc();
    tracing::warn!(
        user = %user,
        device = %device,
        topic = %topic,
        code = %e.code.as_str(),
        detail = %e.message,
        qos = publish.qos,
        bytes = publish.payload.len(),
        "mqtt publish rejected: ingest failed (not acking success)"
    );
    if session.level == 5 {
        if publish.qos == 1 {
            if let Some(packet_id) = publish.packet_id {
                let _ = session
                    .send_raw(puback(5, packet_id, reason.code))
                    .await;
            }
            return None;
        }
        // MQTT 5 QoS0 has no ACK: use DISCONNECT to convey the failure reason, then disconnect.
        let _ = session.send_raw(disconnect(reason.code)).await;
    }
    Some(CloseReason::IngestFailed)
}

// ---------------------------------------------------------------------------
// WILL / retained (completed in PL-11)
// ---------------------------------------------------------------------------

/// Will Delay cap (seconds): values above it are clamped to the cap (preventing a client from parking state outside the connection task for a very long time).
const MAX_WILL_DELAY_SECS: u32 = 3_600;

/// Publish one message on the server identity's behalf (WILL): the same `pipeline::ingest` pipeline as inbound (including realtime loopback + retained).
async fn publish_server_message(
    state: &Arc<AppState>,
    user_id: &str,
    device_id: &str,
    redis: Option<RedisLink>,
    will: &WillState,
) {
    let publish = Publish {
        topic: will.filter.clone(),
        qos: will.qos.min(2),
        dup: false,
        retain: will.retain,
        packet_id: None,
        props: PublishProps {
            content_type: will.props.content_type.clone(),
            payload_format: will.props.payload_format,
            ttl_secs: will.props.message_expiry,
            ..Default::default()
        },
        payload: will.payload.clone(),
    };
    let mut topic_conv = HashMap::new();
    match ingest_publish_once(
        state,
        user_id,
        device_id,
        redis.as_ref(),
        &mut topic_conv,
        &will.filter,
        &will.topic,
        &publish,
        None,
    )
    .await
    {
        Ok(outcome) => {
            if will.retain {
                retained_store(state, &will.filter, &will.topic, &publish, user_id).await;
            }
            state.metrics.mqtt_will_total.inc();
            tracing::info!(
                user = %crate::observe::Metrics::user_hash(user_id),
                device = %device_id,
                topic = %will.topic,
                qos = publish.qos,
                retain = will.retain,
                id = %outcome.id,
                "mqtt will published"
            );
        }
        Err(e) => {
            tracing::warn!(
                user = %crate::observe::Metrics::user_hash(user_id),
                device = %device_id,
                topic = %will.topic,
                code = %e.code.as_str(),
                detail = %e.message,
                "mqtt will publish failed"
            );
        }
    }
}

/// Publish the WILL by disconnect reason when the connection ends (not on a normal DISCONNECT; a delayed WILL uses a Redis marker so a reconnect can cancel it).
async fn publish_will(state: &Arc<AppState>, session: &mut ConnSession, reason: CloseReason) {
    if !reason.publish_will() {
        return;
    }
    let Some(will) = session.will.take() else {
        return;
    };
    let delay = will.delay_secs.min(MAX_WILL_DELAY_SECS);
    if delay == 0 {
        publish_server_message(state, &session.user_id, &session.device_id, session.redis.clone(), &will)
            .await;
        return;
    }
    let key = will_key(&session.user_id, &session.device_id, &session.client_id);
    let nonce = lattice_core::ids::new_id();
    // The marker exists = there is an unpublished delayed WILL; a reconnect with the same client_id deletes the key → cancels publication.
    if let Err(e) = state
        .redis
        .set_json(&key, &nonce, delay as u64 + 60)
        .await
    {
        tracing::warn!(error = %e, "mqtt will delay marker failed, publishing immediately");
        publish_server_message(state, &session.user_id, &session.device_id, session.redis.clone(), &will)
            .await;
        return;
    }
    let state = state.clone();
    let redis_handle = state.redis.clone();
    let user_id = session.user_id.clone();
    let device_id = session.device_id.clone();
    let redis_link = session.redis.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(delay as u64)).await;
        let still_pending = matches!(redis_handle.get_json(&key).await, Ok(Some(current)) if current == nonce);
        if !still_pending {
            tracing::debug!(user = %crate::observe::Metrics::user_hash(&user_id), device = %device_id, "mqtt delayed will cancelled by reconnect");
            return;
        }
        let _ = redis_handle.del(&key).await;
        publish_server_message(&state, &user_id, &device_id, redis_link, &will).await;
    });
}

/// Deliver one exact-subscription retained message to the just-subscribed client (retain flag=1; QoS=min(retained, granted)).
///
/// `seen`: wire topics already delivered within this SUBSCRIBE (overlapping filters send the same topic only once).
fn spawn_retained_delivery(
    state: &Arc<AppState>,
    out: mpsc::Sender<Outbound>,
    filter: String,
    topic: String,
    granted_qos: u8,
    sub_id: Option<u32>,
    seen: Arc<Mutex<HashSet<String>>>,
) -> JoinHandle<()> {
    let state = state.clone();
    tokio::spawn(async move {
        let Some((meta, payload)) = retained_load(&state, &filter, &topic).await else {
            return;
        };
        // An exact subscription's downlink topic equals the filter (`lattice/{topic}/{device}`).
        let wire = filter.clone();
        let first = seen.lock().map(|mut set| set.insert(wire.clone())).unwrap_or(true);
        if !first {
            return;
        }
        let qos = meta.qos.min(granted_qos).min(2);
        let item = Outbound::Publish {
            topic: filter,
            payload,
            qos,
            retain: true,
            ack: None,
            sub_ids: sub_id.into_iter().collect(),
        };
        if out.send(item).await.is_ok() {
            state
                .metrics
                .mqtt_retained_total
                .with_label_values(&["delivered"])
                .inc();
        }
    })
}

/// retained delivery for wildcard subscriptions: SCAN all retained and match the normalized pattern against the Lattice topic.
///
/// - send only one message per matching topic (when multiple publishers have retained messages on the same topic, take the latest `stored_at`);
/// - deliver with retain=1, QoS=min(retained qos, granted qos), topic = `lattice/{topic}/{this connection's device}`;
/// - `seen` is shared with exact subscriptions, so overlapping filters within one SUBSCRIBE do not deliver twice.
fn spawn_retained_wildcard_delivery(
    state: &Arc<AppState>,
    out: mpsc::Sender<Outbound>,
    pattern: String,
    device: String,
    granted_qos: u8,
    sub_id: Option<u32>,
    seen: Arc<Mutex<HashSet<String>>>,
) -> JoinHandle<()> {
    let state = state.clone();
    tokio::spawn(async move {
        let keys = match state.redis.scan_prefix(RETAINED_KEY_PREFIX).await {
            Ok(keys) => keys,
            Err(e) => {
                tracing::warn!(error = %e, "mqtt wildcard retained scan failed");
                return;
            }
        };
        let mut newest: HashMap<String, (u64, u8, Vec<u8>)> = HashMap::new();
        for key in keys.into_iter().take(RETAINED_SCAN_LIMIT) {
            let Some(rest) = key.strip_prefix(RETAINED_KEY_PREFIX) else {
                continue;
            };
            // Key layout `{topic}:{device}`: device is a UUID and never contains ':', so splitting once from the right is enough.
            let Some((topic, _publisher_device)) = rest.rsplit_once(':') else {
                continue;
            };
            if !matches(&pattern, topic) {
                continue;
            }
            let raw = match state.redis.get_json(&key).await {
                Ok(Some(raw)) => raw,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(error = %e, "mqtt wildcard retained read failed");
                    continue;
                }
            };
            let Ok(meta) = serde_json::from_str::<RetainedMessage>(&raw) else {
                continue;
            };
            let Some(payload) = meta.decode_payload() else {
                continue;
            };
            if payload.is_empty() {
                continue;
            }
            let replace = newest
                .get(topic)
                .map(|(stored_at, _, _)| meta.stored_at >= *stored_at)
                .unwrap_or(true);
            if replace {
                newest.insert(topic.to_string(), (meta.stored_at, meta.qos.min(2), payload));
            }
        }
        let mut topics: Vec<String> = newest.keys().cloned().collect();
        topics.sort();
        for topic in topics {
            let Some((_, retained_qos, payload)) = newest.remove(&topic) else {
                continue;
            };
            let wire = wire_topic(&topic, &device);
            let first = seen.lock().map(|mut set| set.insert(wire.clone())).unwrap_or(true);
            if !first {
                continue;
            }
            let qos = retained_qos.min(granted_qos).min(2);
            let item = Outbound::Publish {
                topic: wire,
                payload,
                qos,
                retain: true,
                ack: None,
                sub_ids: sub_id.into_iter().collect(),
            };
            if out.send(item).await.is_err() {
                return;
            }
            state
                .metrics
                .mqtt_wildcard_total
                .with_label_values(&["match"])
                .inc();
            state
                .metrics
                .mqtt_retained_total
                .with_label_values(&["delivered"])
                .inc();
        }
    })
}


/// Abort all background tasks of one subscription; a shared subscription also leaves the in-group round robin.
fn abort_subscription(sub: Subscription) {
    if let Some(task) = sub.task {
        task.abort();
    }
    if let Some(task) = sub.replay {
        task.abort();
    }
    if let SubKind::Shared { group, pattern, member_id } = sub.kind {
        if let Some(member_id) = member_id {
            shared_unregister(&group, &pattern, member_id);
        }
    }
}

/// Activate an exact subscription: cache topic→conv, register match information, start the pubsub task; start redelivery when `start_replay`.
async fn activate_exact_subscription(
    state: &Arc<AppState>,
    session: &mut ConnSession,
    filter: &str,
    topic: &str,
    granted: u8,
    sub_id: Option<u32>,
    start_replay: bool,
) {
    if let Ok(Some(conv)) = crate::store::pg::topic_conv_id(&state.db, topic).await {
        session.topic_conv.insert(topic.to_string(), conv);
    }
    // A repeated SUBSCRIBE for the same filter: the old match information is replaced by the newly granted QoS (the old task is also aborted when subs is replaced).
    session.remove_plain_filter(filter);
    session.add_plain_filter(PlainFilter::exact(
        filter.to_string(),
        topic.to_string(),
        granted,
        sub_id,
    ));
    let task = spawn_exact_subscription(
        session.redis.as_ref(),
        topic,
        &session.device_id,
        session.plain_filters.clone(),
        session.delivery_dedupe.clone(),
        session.out.clone(),
    );
    let replay = if start_replay {
        let skip = session
            .replay_offsets
            .lock()
            .ok()
            .and_then(|m| m.get(filter).copied());
        Some(spawn_pending_replay(state, session, filter, topic, granted, sub_id, skip))
    } else {
        None
    };
    if let Some(old) = session.subs.insert(
        filter.to_string(),
        Subscription {
            kind: SubKind::Exact { topic: topic.to_string() },
            qos: granted,
            sub_id,
            task,
            replay,
        },
    ) {
        abort_subscription(old);
    }
}

/// Activate a wildcard subscription: register match information and start the Redis PSUBSCRIBE task (online realtime; no PG membership/redelivery).
fn activate_wildcard_subscription(
    state: &Arc<AppState>,
    session: &mut ConnSession,
    filter: &str,
    pattern: &str,
    granted: u8,
    sub_id: Option<u32>,
) {
    session.remove_plain_filter(filter);
    session.add_plain_filter(PlainFilter::wildcard(
        filter.to_string(),
        pattern.to_string(),
        granted,
        sub_id,
    ));
    let task = spawn_wildcard_subscription(
        session.redis.as_ref(),
        pattern,
        &session.device_id,
        session.plain_filters.clone(),
        session.delivery_dedupe.clone(),
        session.out.clone(),
        state.metrics.clone(),
    );
    if let Some(old) = session.subs.insert(
        filter.to_string(),
        Subscription {
            kind: SubKind::Wildcard { pattern: pattern.to_string() },
            qos: granted,
            sub_id,
            task,
            replay: None,
        },
    ) {
        abort_subscription(old);
    }
}

/// Normalize a shared subscription's inner filter into a "match pattern": only filters **containing wildcards** (`+`/`#`) are accepted.
///
/// Shared subscriptions on an exact topic (`$share/{group}/lattice/{topic}/{device}`) are outside this gateway's scope:
/// they carry no "spread across multiple different topics" semantics (a single topic can simply be subscribed exactly), and the existing
/// `scripts/mqtt-smoke.mjs` asserts "`$share` with an exact filter → SUBACK 0x8F" as a contract, so this stays consistent.
fn normalize_shared_pattern(inner: &str, _device_id: &str) -> Result<String, u8> {
    if !filter_has_wildcard(inner) {
        return Err(REASON_TOPIC_FILTER_INVALID);
    }
    validate_topic_filter(inner).map_err(|_| REASON_TOPIC_FILTER_INVALID)?;
    let pattern = normalize_filter(inner);
    if pattern.is_empty() || validate_topic_filter(&pattern).is_err() {
        return Err(REASON_TOPIC_FILTER_INVALID);
    }
    Ok(pattern)
}

/// Activate a shared subscription: register an in-group member (the first member in the group starts that group's Redis PSUBSCRIBE task).
fn activate_shared_subscription(
    state: &Arc<AppState>,
    session: &mut ConnSession,
    filter: &str,
    group: &str,
    pattern: &str,
    granted: u8,
    sub_id: Option<u32>,
) {
    let member_id = shared_register(
        session.redis.as_ref(),
        &state.metrics,
        group,
        pattern,
        &session.device_id,
        granted,
        sub_id,
        session.out.clone(),
    );
    if let Some(old) = session.subs.insert(
        filter.to_string(),
        Subscription {
            kind: SubKind::Shared {
                group: group.to_string(),
                pattern: pattern.to_string(),
                member_id,
            },
            qos: granted,
            sub_id,
            task: None,
            replay: None,
        },
    ) {
        abort_subscription(old);
    }
}

/// Restore subscriptions of a persistent session on reconnect (called after CONNACK):
/// - exact subscriptions: resubscribe the user-level topic + rebuild the pubsub/redelivery tasks (old behavior);
/// - wildcard/shared subscriptions: rebuild only the realtime subscription (online realtime semantics; no history redelivery, no retained resend).
async fn restore_subscriptions(state: &Arc<AppState>, session: &mut ConnSession, subs: &[PersistedSub]) {
    let user = session.user_id.clone();
    let device = session.device_id.clone();
    let user_hash = crate::observe::Metrics::user_hash(&user);
    for sub in subs {
        let granted = sub.qos.min(2);
        if sub.filter.starts_with("$share/") {
            let Some((group, inner)) = parse_shared_filter(&sub.filter) else {
                tracing::warn!(user = %user_hash, device = %device, filter = %sub.filter, "mqtt session restore: invalid shared filter, skipped");
                continue;
            };
            let pattern = match normalize_shared_pattern(&inner, &device) {
                Ok(pattern) => pattern,
                Err(reason) => {
                    tracing::warn!(user = %user_hash, device = %device, filter = %sub.filter, reason, "mqtt session restore: shared filter unmappable, skipped");
                    continue;
                }
            };
            activate_shared_subscription(state, session, &sub.filter, &group, &pattern, granted, sub.sub_id);
            tracing::info!(user = %user_hash, device = %device, filter = %sub.filter, qos = granted, sub_id = ?sub.sub_id, "mqtt session shared subscription restored");
        } else if filter_has_wildcard(&sub.filter) {
            if validate_topic_filter(&sub.filter).is_err() {
                tracing::warn!(user = %user_hash, device = %device, filter = %sub.filter, "mqtt session restore: invalid wildcard filter, skipped");
                continue;
            }
            let pattern = normalize_filter(&sub.filter);
            if pattern.is_empty() || validate_topic_filter(&pattern).is_err() {
                tracing::warn!(user = %user_hash, device = %device, filter = %sub.filter, "mqtt session restore: wildcard filter empty after normalize, skipped");
                continue;
            }
            activate_wildcard_subscription(state, session, &sub.filter, &pattern, granted, sub.sub_id);
            tracing::info!(user = %user_hash, device = %device, filter = %sub.filter, qos = granted, sub_id = ?sub.sub_id, "mqtt session wildcard subscription restored");
        } else {
            if let Err(e) = crate::routing::topic::subscribe(state, &user, &sub.topic).await {
                tracing::warn!(user = %user_hash, device = %device, topic = %sub.topic, error = %e, "mqtt session restore: re-subscribe failed");
                continue;
            }
            activate_exact_subscription(state, session, &sub.filter, &sub.topic, granted, sub.sub_id, true).await;
            tracing::info!(user = %user_hash, device = %device, filter = %sub.filter, qos = sub.qos, sub_id = ?sub.sub_id, "mqtt session subscription restored");
        }
    }
    if !subs.is_empty() {
        session.persist_state().await;
    }
}

/// Follow-up retained / offline redelivery targets after a successful subscription (both started after SUBACK).
///
/// `sub_id` is this subscription's MQTT 5 Subscription Identifier: retained/redelivered PUBLISH messages must carry it too
/// (the identifier of the matching subscription; always None on 3.1.1 and ignored when encoding).
enum SubscribeTarget {
    /// Exact subscription: one retained message (`lattice/{topic}/{device}`).
    RetainedExact { filter: String, topic: String, granted: u8, sub_id: Option<u32> },
    /// Wildcard subscription: all matching retained messages.
    RetainedWildcard { pattern: String, granted: u8, sub_id: Option<u32> },
    /// Exact subscription: offline topic pending redelivery.
    Replay { filter: String, topic: String, granted: u8, sub_id: Option<u32> },
}

async fn handle_subscribe(
    state: &Arc<AppState>,
    session: &mut ConnSession,
    packet: &Packet,
) -> Option<CloseReason> {
    let request = match parse_subscribe(&packet.body, session.level) {
        Ok(r) => r,
        Err(e) => {
            protocol_error(session, &format!("malformed SUBSCRIBE: {e}")).await;
            return Some(CloseReason::ProtocolError);
        }
    };
    let (user, device) = session.log_identity();
    // MQTT 5 Subscription Identifier: shared by all filters in this SUBSCRIBE (always None on 3.1.1).
    let subscription_id = request.subscription_id;
    let mut codes = Vec::with_capacity(request.filters.len());
    // Redelivery/retained start after SUBACK: first let the client know the subscription was granted, then send it PUBLISH for that topic.
    let mut targets: Vec<SubscribeTarget> = Vec::new();

    for (filter, requested_qos) in request.filters {
        // QoS2 is supported now: grant min(requested, 2) (no downgrade anymore, MQTT 5 §3.8.4).
        let granted = granted_qos(requested_qos);

        // ---- Shared subscription `$share/{group}/{filter}` ----
        if filter.starts_with("$share/") {
            let Some((group, inner)) = parse_shared_filter(&filter) else {
                state
                    .metrics
                    .mqtt_wildcard_total
                    .with_label_values(&["invalid"])
                    .inc();
                codes.push(suback_code(session.level, REASON_TOPIC_FILTER_INVALID));
                tracing::warn!(user = %user, device = %device, filter = %filter, "mqtt shared filter rejected: invalid syntax");
                continue;
            };
            let pattern = match normalize_shared_pattern(&inner, &session.device_id) {
                Ok(pattern) => pattern,
                Err(reason) => {
                    state
                        .metrics
                        .mqtt_wildcard_total
                        .with_label_values(&["invalid"])
                        .inc();
                    codes.push(suback_code(session.level, reason));
                    tracing::warn!(user = %user, device = %device, filter = %filter, reason, "mqtt shared filter rejected: inner filter unmappable");
                    continue;
                }
            };
            activate_shared_subscription(
                state,
                session,
                &filter,
                &group,
                &pattern,
                granted,
                subscription_id,
            );
            if subscription_id.is_some() {
                state.metrics.mqtt_sub_id_total.inc();
            }
            codes.push(suback_code(session.level, granted));
            tracing::info!(
                user = %user, device = %device, group = %group, filter = %filter, pattern = %pattern,
                qos = granted, sub_id = ?subscription_id, "mqtt shared subscribe"
            );
            continue;
        }

        // ---- Wildcard normal subscription (matched against the Lattice topic path) ----
        if filter_has_wildcard(&filter) {
            if let Err(e) = validate_topic_filter(&filter) {
                state
                    .metrics
                    .mqtt_wildcard_total
                    .with_label_values(&["invalid"])
                    .inc();
                codes.push(suback_code(session.level, REASON_TOPIC_FILTER_INVALID));
                tracing::warn!(user = %user, device = %device, filter = %filter, reason = %e, "mqtt wildcard filter rejected");
                continue;
            }
            let pattern = normalize_filter(&filter);
            if pattern.is_empty() || validate_topic_filter(&pattern).is_err() {
                state
                    .metrics
                    .mqtt_wildcard_total
                    .with_label_values(&["invalid"])
                    .inc();
                codes.push(suback_code(session.level, REASON_TOPIC_FILTER_INVALID));
                continue;
            }
            activate_wildcard_subscription(
                state,
                session,
                &filter,
                &pattern,
                granted,
                subscription_id,
            );
            if subscription_id.is_some() {
                state.metrics.mqtt_sub_id_total.inc();
            }
            codes.push(suback_code(session.level, granted));
            targets.push(SubscribeTarget::RetainedWildcard {
                pattern: pattern.clone(),
                granted,
                sub_id: subscription_id,
            });
            tracing::info!(
                user = %user, device = %device, filter = %filter, pattern = %pattern, qos = granted,
                sub_id = ?subscription_id, "mqtt wildcard subscribe"
            );
            continue;
        }

        // ---- Exact subscription (old behavior: PG membership + offline redelivery + one retained) ----
        let topic = match map_topic(&filter, &session.device_id) {
            Ok(topic) => topic,
            Err(e) => {
                codes.push(suback_code(session.level, e.suback_reason()));
                continue;
            }
        };
        match crate::routing::topic::subscribe(state, &session.user_id, &topic).await {
            Ok(_) => {
                // Build only the pubsub task first (no redelivery): SUBACK is still in the downlink queue, and redelivery must come after it.
                activate_exact_subscription(
                    state,
                    session,
                    &filter,
                    &topic,
                    granted,
                    subscription_id,
                    false,
                )
                .await;
                if subscription_id.is_some() {
                    state.metrics.mqtt_sub_id_total.inc();
                }
                codes.push(suback_code(session.level, granted));
                targets.push(SubscribeTarget::RetainedExact {
                    filter: filter.clone(),
                    topic: topic.clone(),
                    granted,
                    sub_id: subscription_id,
                });
                targets.push(SubscribeTarget::Replay {
                    filter: filter.clone(),
                    topic: topic.clone(),
                    granted,
                    sub_id: subscription_id,
                });
                tracing::info!(
                    user = %user, device = %device, topic = %topic, qos = granted,
                    sub_id = ?subscription_id, "mqtt subscribe"
                );
            }
            Err(e) => {
                tracing::warn!(user = %user, device = %device, topic = %topic, error = %e, "mqtt subscribe failed");
                let reason = if e.code == lattice_core::ErrorCode::Rate {
                    REASON_QUOTA_EXCEEDED
                } else {
                    REASON_UNSPECIFIED_ERROR
                };
                codes.push(suback_code(session.level, reason));
            }
        }
    }

    if !session.send_raw(suback(session.level, request.packet_id, &codes)).await {
        return Some(CloseReason::ConnectionLost);
    }

    // SUBACK is already queued → deliver retained first (one per filter / per topic), then start offline redelivery.
    // seen: overlapping filters within one SUBSCRIBE deliver the same retained topic only once.
    let seen: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    for target in &targets {
        match target {
            SubscribeTarget::RetainedExact { filter, topic, granted, sub_id } => {
                spawn_retained_delivery(
                    state,
                    session.out.clone(),
                    filter.clone(),
                    topic.clone(),
                    *granted,
                    *sub_id,
                    seen.clone(),
                );
            }
            SubscribeTarget::RetainedWildcard { pattern, granted, sub_id } => {
                spawn_retained_wildcard_delivery(
                    state,
                    session.out.clone(),
                    pattern.clone(),
                    session.device_id.clone(),
                    *granted,
                    *sub_id,
                    seen.clone(),
                );
            }
            SubscribeTarget::Replay { .. } => {}
        }
    }
    for target in targets {
        let SubscribeTarget::Replay { filter, topic, granted, sub_id } = target else {
            continue;
        };
        // On a repeated SUBSCRIBE for the same filter, stop the old redelivery task first (otherwise the same queue is redelivered concurrently).
        if let Some(old) = session.subs.get_mut(&filter) {
            if let Some(task) = old.replay.take() {
                task.abort();
            }
        }
        let skip = session.replay_offsets.lock().ok().and_then(|m| m.get(&filter).copied());
        let task = spawn_pending_replay(state, session, &filter, &topic, granted, sub_id, skip);
        if let Some(sub) = session.subs.get_mut(&filter) {
            sub.replay = Some(task);
        }
    }
    // Subscriptions are part of the persistent session: with clean=false they are written to Redis immediately (a crash/disconnect loses no subscription).
    session.persist_state().await;
    None
}

async fn handle_unsubscribe(
    state: &Arc<AppState>,
    session: &mut ConnSession,
    packet: &Packet,
) -> Option<CloseReason> {
    let request = match parse_unsubscribe(&packet.body, session.level) {
        Ok(r) => r,
        Err(e) => {
            protocol_error(session, &format!("malformed UNSUBSCRIBE: {e}")).await;
            return Some(CloseReason::ProtocolError);
        }
    };
    let (user, device) = session.log_identity();
    let mut codes = Vec::with_capacity(request.filters.len());

    for filter in request.filters {
        // ---- Shared subscription ----
        if filter.starts_with("$share/") {
            if parse_shared_filter(&filter).is_none() {
                codes.push(REASON_TOPIC_FILTER_INVALID);
                continue;
            }
            match session.subs.remove(&filter) {
                Some(sub) => {
                    abort_subscription(sub);
                    codes.push(REASON_SUCCESS);
                    tracing::info!(user = %user, device = %device, filter = %filter, "mqtt shared unsubscribe");
                }
                None => codes.push(REASON_NO_SUBSCRIPTION_EXISTED),
            }
            continue;
        }
        // ---- Wildcard normal subscription ----
        if filter_has_wildcard(&filter) {
            if validate_topic_filter(&filter).is_err() {
                codes.push(REASON_TOPIC_FILTER_INVALID);
                continue;
            }
            match session.subs.remove(&filter) {
                Some(sub) => {
                    let pattern = match &sub.kind {
                        SubKind::Wildcard { pattern } => pattern.clone(),
                        _ => String::new(),
                    };
                    abort_subscription(sub);
                    session.remove_plain_filter(&filter);
                    codes.push(REASON_SUCCESS);
                    tracing::info!(user = %user, device = %device, filter = %filter, pattern = %pattern, "mqtt wildcard unsubscribe");
                }
                None => codes.push(REASON_NO_SUBSCRIPTION_EXISTED),
            }
            continue;
        }
        // ---- Exact subscription (old behavior) ----
        let topic = match map_topic(&filter, &session.device_id) {
            Ok(topic) => topic,
            Err(e) => {
                codes.push(e.suback_reason());
                continue;
            }
        };
        match session.subs.remove(&filter) {
            Some(sub) => {
                abort_subscription(sub);
                session.remove_plain_filter(&filter);
                if let Ok(mut offsets) = session.replay_offsets.lock() {
                    offsets.remove(&filter);
                }
                // The in-session topic→conv cache is invalidated too: publishing that topic later re-validates membership
                // and "publishes implies subscribe" (otherwise ingest's membership check would 403, inconsistent with the first publish).
                session.topic_conv.remove(&topic);
                // Unsubscribe = user-level unsubscribe (the same persistence path as REST `POST /v1/topics/{t}/unsubscribe`).
                if let Err(e) = crate::routing::topic::unsubscribe(state, &session.user_id, &topic).await {
                    tracing::warn!(user = %user, device = %device, topic = %topic, error = %e, "mqtt unsubscribe failed");
                }
                codes.push(REASON_SUCCESS);
                tracing::info!(user = %user, device = %device, topic = %topic, "mqtt unsubscribe");
            }
            None => codes.push(REASON_NO_SUBSCRIPTION_EXISTED),
        }
    }

    if !session.send_raw(unsuback(session.level, request.packet_id, &codes)).await {
        return Some(CloseReason::ConnectionLost);
    }
    session.persist_state().await;
    None
}

// ---------------------------------------------------------------------------
// Offline pending redelivery (PL-11 11.11)
// ---------------------------------------------------------------------------

/// Start a redelivery task for a single subscription: consume `pending:{user}:topic:{t}` in ascending offset/seq order.
///
/// Semantics align with WS `drain_topics`, but the function is **not shared** (WS goes through hub frames while MQTT emits outbound PUBLISH and
/// must wait for PUBACK/PUBCOMP before dequeuing):
/// - the caller guarantees "SUBACK first, then redelivery" (avoiding PUBLISH to a client that has not subscribed locally);
/// - dequeue and advance `topic_offsets` only after PUBACK (QoS1) / PUBCOMP (QoS2); on disconnect/retransmission exhaustion the
///   task aborts, unacknowledged entries stay in the queue, and redelivery continues on the next reconnect (at-least-once, duplicating at most one);
/// - the session-level redelivery watermark is written back too (`replay_offsets`, persisted with the session when clean=false), for reconnect dedup hints;
/// - per-device rate limit `[mqtt] replay_rate_per_sec` (default 10 msg/s, the same convention as §17.13).
fn spawn_pending_replay(
    state: &Arc<AppState>,
    session: &ConnSession,
    filter: &str,
    topic: &str,
    granted_qos: u8,
    sub_id: Option<u32>,
    skip_offset: Option<u64>,
) -> JoinHandle<()> {
    let state = state.clone();
    let user = session.user_id.clone();
    let device = session.device_id.clone();
    let out = session.out.clone();
    let filter = filter.to_string();
    let topic = topic.to_string();
    let offsets = session.replay_offsets.clone();
    let store = session.session_store.clone();
    tokio::spawn(async move {
        replay_topic_pending(
            state,
            user,
            device,
            filter,
            topic,
            granted_qos,
            sub_id,
            out,
            offsets,
            store,
            skip_offset,
        )
        .await;
    })
}

#[allow(clippy::too_many_arguments)]
async fn replay_topic_pending(
    state: Arc<AppState>,
    user: String,
    device: String,
    filter: String,
    topic: String,
    granted_qos: u8,
    sub_id: Option<u32>,
    out: mpsc::Sender<Outbound>,
    offsets: SharedReplayOffsets,
    store: Option<SessionStore>,
    skip_offset: Option<u64>,
) {
    let user_hash = crate::observe::Metrics::user_hash(&user);
    let queue = keys::pending_topic(&user, &topic);
    let batch = match state.redis.pending_batch(&queue, REPLAY_BATCH).await {
        Ok(batch) => batch,
        Err(e) => {
            tracing::warn!(user = %user_hash, device = %device, topic = %topic, error = %e, "mqtt pending replay: read queue failed");
            return;
        }
    };
    if batch.is_empty() {
        return;
    }
    let rate = state.cfg.mqtt.replay_rate_per_sec.max(1) as u64;
    let budget = Duration::from_millis((1000 / rate).max(1));
    // Deliver messages at the granted QoS (QoS0/1/2 all supported)
    let qos = granted_qos.min(2);
    let mut sent = 0usize;
    tracing::info!(
        user = %user_hash, device = %device, topic = %topic, pending = batch.len(),
        "mqtt pending replay start"
    );
    for (msg_id, offset) in batch {
        if let Some(skip) = skip_offset {
            if (offset as u64) <= skip {
                // The watermark recorded in the session already confirmed this message (e.g. the PG watermark had not advanced after the last ACK):
                // dequeue directly, so a reconnect does not deliver an acknowledged message again.
                let _ = state.redis.pending_remove(&queue, &msg_id).await;
                continue;
            }
        }
        if msg_id.is_empty() {
            // Old-format entries from before v0.15 (the message was not yet persisted at enqueue time): cannot be looked up → drop them
            let _ = state.redis.pending_remove(&queue, &msg_id).await;
            continue;
        }
        let msg = match crate::store::pg::message_by_id(&state.db, &msg_id).await {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                // The message has expired/been archived: dequeue directly, avoiding zombie entries
                let _ = state.redis.pending_remove(&queue, &msg_id).await;
                continue;
            }
            Err(e) => {
                tracing::warn!(user = %user_hash, device = %device, topic = %topic, error = %e, "mqtt pending replay: message lookup failed");
                break;
            }
        };
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
        let body = env.encode_body();
        let (ack_tx, ack_rx) = if qos > 0 {
            let (tx, rx) = oneshot::channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        if out
            .send(Outbound::Publish {
                topic: filter.clone(),
                payload: body,
                qos,
                retain: false,
                ack: ack_tx,
                sub_ids: sub_id.into_iter().collect(),
            })
            .await
            .is_err()
        {
            break; // the connection is closed
        }
        if let Some(rx) = ack_rx {
            match tokio::time::timeout(REPLAY_ACK_TIMEOUT, rx).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => {
                    tracing::debug!(
                        topic = %topic, msg_id = %msg_id,
                        "mqtt pending replay: ack wait ended (connection closing), will retry on next connect"
                    );
                    break;
                }
            }
        }
        // Sent (QoS0) or PUBACK/PUBCOMP received (QoS1/2): dequeue + advance the watermark (offset is monotonic, so a reconnect can resume).
        if let Err(e) = state.redis.pending_remove(&queue, &msg_id).await {
            tracing::warn!(error = %e, "mqtt pending replay: dequeue failed");
        }
        if let Err(e) = crate::store::pg::set_topic_offset(&state.db, &user, &topic, offset).await {
            tracing::warn!(error = %e, "mqtt pending replay: advance topic offset failed");
        }
        if let Ok(mut map) = offsets.lock() {
            map.insert(filter.clone(), offset as u64);
        }
        if let Some(store) = &store {
            store.patch_replay_offset(&filter, offset as u64).await;
        }
        state.metrics.mqtt_pending_replay_total.inc();
        sent += 1;
        tokio::time::sleep(budget).await;
    }
    if sent > 0 {
        tracing::info!(
            user = %user_hash, device = %device, topic = %topic, sent,
            "mqtt pending replay done"
        );
    }
}

// ---------------------------------------------------------------------------
// Connection lifecycle
// ---------------------------------------------------------------------------

/// Result of one frame-loop step (three-way select: write task closed / packet read / keepalive timeout).
enum FrameEvent {
    /// The write task ended or requested a disconnect (e.g. QoS1 retransmission exhausted).
    WriterClosed(Option<CloseReason>),
    Read(io::Result<Option<Packet>>),
    Idle,
}

/// Sleep future for the keepalive deadline; permanently pending when there is no deadline (not participating in wakeups).
async fn sleep_until_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending::<()>().await,
    }
}

/// Full lifecycle of a plaintext connection (a thin wrapper: set nodelay, then hand over to the generic implementation; no certificate identity = the original PSK/JWT).
async fn handle_connection(
    state: Arc<AppState>,
    socket: TcpStream,
    peer: SocketAddr,
    redis: Option<RedisLink>,
) {
    if let Err(e) = socket.set_nodelay(true) {
        tracing::debug!(error = %e, "mqtt set_nodelay failed");
    }
    handle_stream(state, socket, peer, redis, None).await;
}

/// Full lifecycle of a single connection: first packet CONNECT → auth/session restore → frame loop → cleanup (persistence/WILL).
///
/// The generic `S` serves both plaintext `TcpStream` and TLS `TlsStream<TcpStream>`. `tls_peer`:
/// - `None` = plaintext connection (no certificate identity, using the original PSK/JWT semantics);
/// - `Some(NoCert)` = TLS without a client certificate (only with require_client_cert=false), also falling back to PSK/JWT;
/// - `Some(Parsed/Unparsable)` = TLS + client certificate (X.509 identity mapping + CONNECT anti-impersonation).
async fn handle_stream<S>(
    state: Arc<AppState>,
    mut stream: S,
    peer: SocketAddr,
    redis: Option<RedisLink>,
    tls_peer: Option<TlsClientIdentity>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let started = std::time::Instant::now();

    // 1) The first packet must be CONNECT (within 10s), otherwise close immediately.
    let connect = match tokio::time::timeout(CONNECT_TIMEOUT, read_packet(&mut stream)).await {
        Ok(Ok(Some(first))) if first.kind == PACKET_CONNECT => match parse_connect(&first.body) {
            Ok(connect) => connect,
            Err(ConnectError::UnsupportedProtocol(level)) => {
                tracing::warn!(peer = %peer, level, "mqtt connect rejected: unsupported protocol level");
                let reply_level = if level == 5 { 5 } else { 4 };
                let code = if level == 5 {
                    REASON_UNSUPPORTED_PROTOCOL_VERSION
                } else {
                    CONNACK_BAD_PROTOCOL
                };
                let _ = write_packet(&mut stream, &connack(reply_level, false, code)).await;
                let _ = stream.flush().await;
                return;
            }
            Err(ConnectError::Malformed(e)) => {
                tracing::warn!(peer = %peer, error = %e, "mqtt malformed CONNECT, closing");
                return;
            }
        },
        Ok(Ok(Some(_))) => {
            tracing::warn!(peer = %peer, "mqtt first packet is not CONNECT, closing");
            return;
        }
        Ok(Ok(None)) => return,
        Ok(Err(e)) => {
            tracing::debug!(peer = %peer, error = %e, "mqtt connection dropped before CONNECT");
            return;
        }
        Err(_) => {
            tracing::warn!(peer = %peer, "mqtt CONNECT timeout");
            return;
        }
    };

    // 1.1) Empty client id with non-clean: the session cannot be restored/saved by client_id, so reject per protocol.
    //      (3.1.1 §3.1.3.1: an empty id is allowed only with clean session; MQTT 5 §3.1.3.1: an empty id requires clean_start.)
    if connect.client_id.is_empty() && !connect.clean_session {
        tracing::warn!(peer = %peer, "mqtt connect rejected: empty client id with persistent session");
        let code = if connect.level == 5 {
            REASON_CLIENT_ID_INVALID
        } else {
            CONNACK_IDENTIFIER_REJECTED
        };
        let _ = write_packet(&mut stream, &connack(connect.level, false, code)).await;
        let _ = stream.flush().await;
        return;
    }

    // 1.2) MQTT 5 CONNECT `Receive Maximum(0x21)` legal range 1..=65535: 0 is a protocol error.
    //      Reply CONNACK(0x82 Protocol Error) per MQTT 5 §3.1.2.11.3, then disconnect; 3.1.1 has no such property.
    let server_receive_maximum = effective_receive_maximum(state.cfg.mqtt.receive_maximum);
    if connect.level == 5 && connect.props.receive_maximum == Some(0) {
        state
            .metrics
            .mqtt_receive_max_total
            .with_label_values(&["violation"])
            .inc();
        tracing::warn!(
            peer = %peer,
            "mqtt connect rejected: receive maximum 0 is a protocol error"
        );
        let _ = write_packet(&mut stream, &connack(5, false, REASON_PROTOCOL_ERROR)).await;
        let _ = stream.flush().await;
        return;
    }

    // 2) Auth:
    //    - TLS with a client certificate → X.509 identity (PG validation + CONNECT anti-impersonation, **not** using the password);
    //    - TLS without a client certificate (require_client_cert=false) / plaintext → the original PSK refresh token semantics.
    let identity = match tls_peer.as_ref() {
        Some(TlsClientIdentity::Parsed(cert_name)) => {
            match authenticate_tls(&state, &connect, cert_name).await {
                Ok(identity) => {
                    state
                        .metrics
                        .mqtt_tls_auth_total
                        .with_label_values(&["ok"])
                        .inc();
                    tracing::info!(
                        peer = %peer,
                        user = %crate::observe::Metrics::user_hash(&identity.user_id),
                        device = %identity.device_id,
                        "mqtt tls client certificate authenticated"
                    );
                    identity
                }
                Err(failure) => {
                    state
                        .metrics
                        .mqtt_tls_auth_total
                        .with_label_values(&[failure.as_str()])
                        .inc();
                    let code = connack_code(connect.level, AuthFailure::NotAuthorized);
                    tracing::warn!(
                        peer = %peer,
                        result = failure.as_str(),
                        "mqtt tls connect rejected: certificate identity check failed"
                    );
                    let _ = write_packet(&mut stream, &connack(connect.level, false, code)).await;
                    let _ = stream.flush().await;
                    return;
                }
            }
        }
        Some(TlsClientIdentity::Unparsable) => {
            state
                .metrics
                .mqtt_tls_auth_total
                .with_label_values(&[TlsAuthFailure::UnknownIdentity.as_str()])
                .inc();
            tracing::warn!(
                peer = %peer,
                "mqtt tls connect rejected: client certificate has no lattice identity"
            );
            let code = connack_code(connect.level, AuthFailure::NotAuthorized);
            let _ = write_packet(&mut stream, &connack(connect.level, false, code)).await;
            let _ = stream.flush().await;
            return;
        }
        // TLS without a client certificate (only require_client_cert=false) → fall back to the original PSK/JWT;
        // plaintext connections also come here (no certificate identity; semantics identical to before TLS was added).
        Some(TlsClientIdentity::NoCert) | None => match authenticate(&state, &connect).await {
            Ok(identity) => identity,
            Err(failure) => {
                let code = connack_code(connect.level, failure);
                tracing::warn!(peer = %peer, reason = ?failure, "mqtt connect rejected");
                let _ = write_packet(&mut stream, &connack(connect.level, false, code)).await;
                let _ = stream.flush().await;
                return;
            }
        },
    };

    // 2.1) WILL topic mapping/device ownership is validated at CONNECT (a will must not publish into someone else's topic).
    let will = if connect.will {
        let raw_topic = connect.will_topic.clone().unwrap_or_default();
        match map_topic(&raw_topic, &identity.device_id) {
            Ok(topic) => Some(WillState {
                filter: raw_topic,
                topic,
                payload: connect.will_payload.clone().unwrap_or_default(),
                qos: connect.will_qos.min(2),
                retain: connect.will_retain,
                props: connect.will_props.clone(),
                delay_secs: connect.will_props.delay_secs.unwrap_or(0),
            }),
            Err(e) => {
                tracing::warn!(
                    peer = %peer, user = %crate::observe::Metrics::user_hash(&identity.user_id),
                    device = %identity.device_id, topic = %raw_topic, reason = ?e,
                    "mqtt connect rejected: will topic invalid"
                );
                let code = if connect.level == 5 {
                    e.disconnect_reason()
                } else {
                    CONNACK_NOT_AUTHORIZED
                };
                let _ = write_packet(&mut stream, &connack(connect.level, false, code)).await;
                let _ = stream.flush().await;
                return;
            }
        }
    } else {
        None
    };

    // 2.2) Session parameters: 3.1.1 clean_session=false → the configured TTL; for MQTT 5 the Session Expiry Interval
    //      wins (absent 0 = the session ends on disconnect), clamped to `[mqtt] session_expiry_max_secs`.
    let max_expiry = state.cfg.mqtt.session_expiry_max_secs.max(1);
    let configured_ttl = state.cfg.mqtt.session_ttl_secs;
    let (effective_ttl, clean_start) = if connect.level == 5 {
        let expiry = connect.props.session_expiry.unwrap_or(0) as u64;
        (expiry.min(max_expiry), connect.clean_session)
    } else if connect.clean_session {
        (0, true)
    } else {
        (configured_ttl, false)
    };
    let store_enabled = configured_ttl > 0;
    let persistent = store_enabled && effective_ttl > 0;
    let session_store = store_enabled.then(|| {
        SessionStore::new(
            state.redis.clone(),
            &identity.user_id,
            &identity.device_id,
            &connect.client_id,
            if effective_ttl > 0 { effective_ttl } else { configured_ttl },
        )
    });

    // Cancelling a late WILL: a reconnect with the same client_id deletes the delayed-WILL marker (MQTT 5 §3.1.2.11.2).
    let pending_will_key = will_key(&identity.user_id, &identity.device_id, &connect.client_id);
    if let Ok(Some(_)) = state.redis.get_json(&pending_will_key).await {
        let _ = state.redis.del(&pending_will_key).await;
        tracing::debug!(client_id = %connect.client_id, "mqtt pending delayed will cancelled");
    }

    // 2.3) Session restore: clean_start clears the old session first (cleaned is counted only if something was really cleared), otherwise try to restore
    //      (if Redis is unavailable, degrade to a new session).
    let (restored_state, restored_out, restored, cleaned_existing) = match &session_store {
        Some(store) if !clean_start => {
            let (state, out, present) = store.load().await;
            (state, out, present, false)
        }
        Some(store) => {
            let existed = store.clear().await;
            (
                PersistedSessionState::default(),
                PersistedOutboundState::default(),
                false,
                existed,
            )
        }
        _ => (
            PersistedSessionState::default(),
            PersistedOutboundState::default(),
            false,
            false,
        ),
    };
    if restored {
        state
            .metrics
            .mqtt_session_total
            .with_label_values(&["restored"])
            .inc();
    } else if cleaned_existing {
        state
            .metrics
            .mqtt_session_total
            .with_label_values(&["cleaned"])
            .inc();
    }

    // 3) CONNACK success; session_present = a persistent session was restored.
    //    MQTT 5 property compatibility rules (**symmetric negotiation**):
    //    - when the client CONNECT declared `Receive Maximum(0x21)`, CONNACK fills 0x21 with the server's
    //      inbound Receive Maximum (`[mqtt] receive_maximum`, 0 = fill 65535);
    //    - when the client CONNECT declared `Topic Alias Maximum(0x22)`, CONNACK fills 0x22 with the
    //      inbound alias cap the server accepts (`[mqtt] topic_alias_max`).
    //    Clients that declare neither keep the 3-byte CONNACK (the existing smoke/E2E packet-shape assertions).
    //    3.1.1 has no property block.
    let session_present = restored && !clean_start;
    let connack_receive_max = if connect.level == 5 && connect.props.receive_maximum.is_some() {
        Some(server_receive_maximum)
    } else {
        None
    };
    let alias_max = if connect.level == 5 && connect.props.topic_alias_maximum.is_some() {
        Some(state.cfg.mqtt.topic_alias_max)
    } else {
        None
    };
    let connack_packet = connack_with_props(
        connect.level,
        session_present,
        CONNACK_ACCEPTED,
        connack_receive_max,
        alias_max,
    );
    if let Err(e) = write_packet(&mut stream, &connack_packet).await {
        tracing::warn!(peer = %peer, error = %e, "mqtt CONNACK write failed");
        return;
    }
    // The client declared its own Receive Maximum (default 65535): the write task's limit on QoS1/2
    // in flight toward that client (undeclared / already validated that 0 is invalid).
    let client_receive_max = connect
        .props
        .receive_maximum
        .map(|max| max.max(1))
        .unwrap_or(MAX_RECEIVE_MAXIMUM);
    // Outbound Topic Alias: enabled only for MQTT5 + the config switch + client Topic Alias Maximum>0.
    let outbound_alias = OutboundAlias::new(
        state.cfg.mqtt.outbound_topic_alias,
        connect.props.topic_alias_maximum.unwrap_or(0),
    );
    let (user_hash, device_id) = (
        crate::observe::Metrics::user_hash(&identity.user_id),
        identity.device_id.clone(),
    );
    tracing::info!(
        peer = %peer,
        user = %user_hash,
        device = %device_id,
        client_id = %connect.client_id,
        level = connect.level,
        keepalive_secs = connect.keepalive_secs,
        clean_start,
        persistent,
        session_present,
        session_ttl = effective_ttl,
        will = will.is_some(),
        topic_alias_max = alias_max,
        peer_topic_alias_max = ?connect.props.topic_alias_maximum,
        server_receive_maximum = connack_receive_max,
        client_receive_max,
        outbound_topic_alias = outbound_alias.enabled,
        "mqtt connected"
    );

    // 4) Split the read/write halves: the write task exclusively owns the write half and the QoS ACK pending map; the read loop multiplexes control packets/ACKs via mpsc
    //    and selects on the write task's "give up retransmission/write failure" notification (the read loop must not wait for keepalive when the client never ACKs).
    let (mut reader, writer_half) = tokio::io::split(stream);
    let (out_tx, out_rx) = mpsc::channel(OUT_QUEUE);
    let (close_tx, mut close_rx) = mpsc::channel::<CloseReason>(1);
    let mut pending = PendingPublishes::new(
        connect.level,
        Duration::from_millis(state.cfg.mqtt.retransmit_ms.max(1)),
        state.cfg.mqtt.max_retransmits,
    );
    // Outbound QoS2 restored from a persistent session: the write task resends immediately at startup with the original packet id (DUP=1 / PUBREL).
    let restored_resend = if restored {
        pending.restore(&restored_out.pending, Instant::now())
    } else {
        Vec::new()
    };
    let out_store = if persistent { session_store.clone() } else { None };
    let mut writer = tokio::spawn(writer_loop(
        writer_half,
        connect.level,
        out_rx,
        pending,
        restored_resend,
        out_store,
        client_receive_max,
        outbound_alias,
        close_tx,
        state.metrics.clone(),
    ));

    let stored_offsets: SharedReplayOffsets =
        Arc::new(Mutex::new(restored_state.replay_offsets.clone()));
    let session_store_for_cleanup = session_store.clone();
    let inbound_receive_max = connack_receive_max.map(|_| server_receive_maximum);
    let mut session = ConnSession {
        level: connect.level,
        user_id: identity.user_id.clone(),
        device_id: identity.device_id.clone(),
        client_id: connect.client_id.clone(),
        out: out_tx,
        persistent,
        session_store,
        subs: HashMap::new(),
        topic_conv: HashMap::new(),
        inbound_qos1: HashMap::new(),
        inbound_qos2: restore_inbound_qos2(&restored_state.inbound_qos2),
        replay_offsets: stored_offsets,
        plain_filters: Arc::new(Mutex::new(Vec::new())),
        delivery_dedupe: Arc::new(Mutex::new(DeliveryDedupe::new(DELIVERY_DEDUPE_WINDOW))),
        topic_aliases: HashMap::new(),
        inbound_receive_max,
        will,
        redis,
        local_bucket: LocalBucket::default(),
    };

    // 4.1) Restore the persistent session's subscriptions (resubscribe user-level topics + rebuild pubsub/redelivery tasks) as preparation before the read loop.
    if session_present && !restored_state.subs.is_empty() {
        restore_subscriptions(&state, &mut session, &restored_state.subs).await;
    }

    // 5) Frame loop: disconnect after 1.5× keepalive with no packet at all; also disconnect immediately when the write task gives up retransmission/write fails.
    let idle = keepalive_timeout(connect.keepalive_secs);
    let mut deadline = idle.map(|d| Instant::now() + d);
    let reason: CloseReason = 'frames: loop {
        let read_fut = read_packet(&mut reader);
        tokio::pin!(read_fut);
        let event = tokio::select! {
            biased;
            closed = close_rx.recv() => FrameEvent::WriterClosed(closed),
            result = &mut read_fut => FrameEvent::Read(result),
            _ = sleep_until_deadline(deadline) => FrameEvent::Idle,
        };
        let packet = match event {
            FrameEvent::WriterClosed(reason) => {
                break 'frames reason.unwrap_or(CloseReason::ConnectionLost);
            }
            FrameEvent::Idle => break 'frames CloseReason::KeepAliveTimeout,
            FrameEvent::Read(Ok(Some(packet))) => packet,
            FrameEvent::Read(Ok(None)) => break 'frames CloseReason::ConnectionLost,
            FrameEvent::Read(Err(e)) => {
                tracing::warn!(user = %user_hash, device = %device_id, error = %e, "mqtt read failed");
                break 'frames CloseReason::ConnectionLost;
            }
        };
        // Any received packet resets keepalive (the deadline rolls from "the last received packet").
        deadline = idle.map(|d| Instant::now() + d);
        if let Some(end) = dispatch(&state, &mut session, packet).await {
            break 'frames end;
        }
    };

    // 6) Cleanup: **save the session snapshot first** (subscriptions are still in the subs table), then stop the pubsub/redelivery tasks;
    //    then publish the WILL by disconnect reason, and finally close the downlink queue and flush queued packets.
    if session.persistent {
        session.persist_state().await;
    } else if let Some(store) = session_store_for_cleanup.clone() {
        store.clear().await;
    }
    for (_, sub) in session.subs.drain() {
        // The pubsub/redelivery tasks of wildcard/exact subscriptions abort with the connection; shared-subscription members leave the in-group round robin too
        // (otherwise a closed member would linger in the group; is_closed also removes it at delivery time, but it would slow down selection).
        abort_subscription(sub);
    }
    publish_will(&state, &mut session, reason).await;
    // A DISCONNECT can turn the session from "persistent" to "non-persistent" (Session Expiry=0): the state at cleanup time is authoritative.
    let session_persistent = session.persistent;
    drop(session);
    if tokio::time::timeout(WRITER_FLUSH_TIMEOUT, &mut writer).await.is_err() {
        writer.abort();
    }
    // Cleanup for "delete the session on disconnect" (clean=true / MQTT 5 DISCONNECT Session Expiry=0): the `out_store` the write task captured
    // at startup is the value from connection setup (possibly Some), so when it exits it writes unfinished outbound QoS2 back to
    // Redis and may recreate the session key that was just deleted above → clean once more here after the write task ends.
    if !session_persistent {
        if let Some(store) = session_store_for_cleanup {
            store.clear().await;
        }
    }    crate::store::pg::touch_device(&state.db, &identity.device_id).await.ok();

    tracing::info!(
        user = %user_hash,
        device = %device_id,
        client_id = %connect.client_id,
        peer = %peer,
        secs = started.elapsed().as_secs(),
        reason = reason.as_str(),
        "mqtt disconnected"
    );
}

/// Write task: exclusive write half + QoS1/QoS2 pending map (packet-id allocation, ACK state machine, timeout retransmission, session persistence).
///
/// On exit it notifies the read loop to disconnect via `close_tx`: `PublishRetryExhausted` = retransmission exhausted;
/// anything else (downlink channel closed/write failure/protocol error/Receive Maximum queue overflow) = the connection is no longer usable.
///
/// `initial`: outbound QoS2 resend packets restored from a persistent session (written out immediately at startup).
/// `out_store`: writes the unfinished outbound QoS2 snapshot back to Redis when clean=false (QoS1 keeps the "reconnect clears pending" semantics).
/// `receive_max`: the Receive Maximum declared in the client CONNECT (the QoS1/2 in-flight limit, default 65535).
/// `outbound_alias`: outbound Topic Alias state (enabled for MQTT 5 + client cap>0; connection-scoped).
#[allow(clippy::too_many_arguments)]
async fn writer_loop<W: AsyncWrite + Unpin>(
    mut writer: W,
    level: u8,
    mut rx: mpsc::Receiver<Outbound>,
    mut pending: PendingPublishes,
    initial: Vec<Packet>,
    out_store: Option<SessionStore>,
    receive_max: u16,
    mut outbound_alias: OutboundAlias,
    close_tx: mpsc::Sender<CloseReason>,
    metrics: Arc<crate::observe::Metrics>,
) {
    let mut exit_reason: Option<CloseReason> = None;
    // Outbound PUBLISH messages waiting for an ACK to free quota because the client's Receive Maximum is used up (bounded, FIFO-ordered).
    let mut receive_queue: std::collections::VecDeque<QueuedPublish> =
        std::collections::VecDeque::new();
    // Unfinished QoS2 packets restored from a persistent session: resent with the original packet id (PUBLISH DUP=1 / PUBREL).
    if !initial.is_empty() {
        for packet in initial {
            if let Err(e) = write_packet(&mut writer, &packet).await {
                tracing::debug!(error = %e, "mqtt writer failed on session restore resend");
                break;
            }
        }
        persist_outbound(&out_store, &pending).await;
    }
    'write: loop {
        let now = Instant::now();
        let wake = pending.next_due().unwrap_or(now + PENDING_IDLE_WAKE);
        let outbound = tokio::select! {
            maybe = rx.recv() => maybe,
            _ = tokio::time::sleep_until(wake) => {
                // Expiry: resend in ascending packet-id order (stable order); disconnect once the cap is reached.
                for packet_id in pending.due_ids(now) {
                    match pending.retransmit(packet_id, now) {
                        Some(Retransmit::Resend(packet)) => {
                            metrics
                                .mqtt_publish_retransmit_total
                                .with_label_values(&["retransmit"])
                                .inc();
                            tracing::debug!(
                                packet_id,
                                pending = pending.len(),
                                "mqtt publish retransmit"
                            );
                            if let Err(e) = write_packet(&mut writer, &packet).await {
                                tracing::debug!(error = %e, "mqtt writer failed on retransmit");
                                break 'write;
                            }
                        }
                        Some(Retransmit::Exhausted) => {
                            metrics
                                .mqtt_publish_retransmit_total
                                .with_label_values(&["exhausted"])
                                .inc();
                            tracing::warn!(
                                packet_id,
                                max_retransmits = pending.max_retransmits(),
                                "mqtt publish retransmit exhausted, closing connection"
                            );
                            exit_reason = Some(CloseReason::PublishRetryExhausted);
                            break 'write;
                        }
                        None => {}
                    }
                }
                continue 'write;
            }
        };
        let Some(outbound) = outbound else {
            // The read loop has ended (session dropped) → flush and exit normally, no further notification needed.
            break 'write;
        };
        match outbound {
            Outbound::Raw(packet) => {
                if let Err(e) = write_packet(&mut writer, &packet).await {
                    tracing::debug!(error = %e, "mqtt writer failed");
                    break 'write;
                }
            }
            Outbound::Publish { topic, payload, qos, retain, ack, sub_ids } => {
                // Client Receive Maximum flow control: when the QoS1/2 in-flight count (pending map size) reaches the limit,
                // enter the bounded FIFO queue and resend in order once PUBACK/PUBREC(failure)/PUBCOMP frees quota.
                // QoS0 is not subject to quota, but it also queues when the queue is non-empty (avoiding cross-QoS reordering).
                if receive_queue.len() >= OUTBOUND_RECEIVE_QUEUE {
                    metrics
                        .mqtt_receive_max_total
                        .with_label_values(&["throttled"])
                        .inc();
                    tracing::warn!(
                        queued = receive_queue.len(),
                        cap = OUTBOUND_RECEIVE_QUEUE,
                        client_receive_max = receive_max,
                        pending = pending.len(),
                        "mqtt outbound receive-maximum queue overflow, closing connection"
                    );
                    exit_reason = Some(CloseReason::QuotaExceeded);
                    break 'write;
                }
                if qos > 0 && pending.len() >= receive_max as usize {
                    metrics
                        .mqtt_receive_max_total
                        .with_label_values(&["throttled"])
                        .inc();
                    tracing::debug!(
                        qos,
                        pending = pending.len(),
                        client_receive_max = receive_max,
                        "mqtt outbound publish throttled by client receive maximum"
                    );
                }
                receive_queue.push_back(QueuedPublish::from_outbound(
                    topic, payload, qos, retain, ack, sub_ids,
                ));
            }
            Outbound::PubAck { packet_id } => {
                // A PUBACK for an unknown packet id is ignored per protocol (possibly a late ACK for an already-cleared entry).
                if !pending.ack(packet_id) {
                    tracing::debug!(packet_id, "mqtt puback for unknown packet id");
                }
            }
            Outbound::PubRec { packet_id, reason } => match pending.on_pubrec(packet_id, reason, Instant::now())
            {
                PubRecAction::SendPubRel(packet) => {
                    metrics
                        .mqtt_qos2_total
                        .with_label_values(&["pubrel"])
                        .inc();
                    if let Err(e) = write_packet(&mut writer, &packet).await {
                        tracing::debug!(error = %e, "mqtt writer failed sending pubrel");
                        break 'write;
                    }
                    persist_outbound(&out_store, &pending).await;
                }
                PubRecAction::Rejected { reason } => {
                    metrics
                        .mqtt_qos2_total
                        .with_label_values(&["error"])
                        .inc();
                    tracing::warn!(packet_id, reason, "mqtt qos2 publish rejected by client (pubrec reason)");
                    persist_outbound(&out_store, &pending).await;
                }
                PubRecAction::ProtocolError => {
                    metrics
                        .mqtt_qos2_total
                        .with_label_values(&["error"])
                        .inc();
                    tracing::warn!(packet_id, "mqtt pubrec for a publish not in wait-pubrec state, closing");
                    if level == 5 {
                        let _ = write_packet(&mut writer, &disconnect(REASON_PROTOCOL_ERROR)).await;
                    }
                    exit_reason = Some(CloseReason::ProtocolError);
                    break 'write;
                }
                PubRecAction::Unknown => {
                    metrics
                        .mqtt_qos2_total
                        .with_label_values(&["error"])
                        .inc();
                    // MQTT 5: reply PUBREL(0x92 packet id not found); 3.1.1: reply PUBREL (the peer should ignore it).
                    let reason = if level == 5 {
                        REASON_PACKET_ID_NOT_FOUND
                    } else {
                        REASON_SUCCESS
                    };
                    if let Err(e) = write_packet(&mut writer, &pubrel(level, packet_id, reason)).await {
                        tracing::debug!(error = %e, "mqtt writer failed sending pubrel(unknown)");
                        break 'write;
                    }
                }
            },
            Outbound::PubComp { packet_id } => match pending.on_pubcomp(packet_id) {
                PubCompAction::Completed => {
                    metrics
                        .mqtt_qos2_total
                        .with_label_values(&["pubcomp"])
                        .inc();
                    persist_outbound(&out_store, &pending).await;
                }
                PubCompAction::Unknown => {
                    metrics
                        .mqtt_qos2_total
                        .with_label_values(&["error"])
                        .inc();
                    tracing::debug!(packet_id, "mqtt pubcomp for unknown packet id");
                }
            },
        }
        // After handling each outbound command, try to flush the Receive Maximum queue: PUBACK / PUBCOMP / a failed PUBREC
        // all shrink the pending map (freeing quota), so the head packet can proceed (FIFO-ordered).
        if let Err(reason) = flush_outbound_queue(
            &mut writer,
            level,
            &mut pending,
            &mut receive_queue,
            &mut outbound_alias,
            receive_max,
            &out_store,
            &metrics,
        )
        .await
        {
            exit_reason = Some(reason);
            break 'write;
        }
    }
    let _ = writer.flush().await;
    // Session persistence: save unfinished outbound QoS2 (continuing after reconnect when clean=false).
    persist_outbound(&out_store, &pending).await;
    // Notify the read loop: when the write task ends (retransmission exhausted/write failure) the read loop must not keep waiting for client packets.
    let _ = close_tx.try_send(exit_reason.unwrap_or(CloseReason::ConnectionLost));
}

/// Write the outbound QoS2 pending snapshot back to the session (a no-op for non-persistent sessions/no Redis).
async fn persist_outbound(store: &Option<SessionStore>, pending: &PendingPublishes) {
    if let Some(store) = store {
        store.save_outbound(&pending.snapshot()).await;
    }
}


// ---------------------------------------------------------------------------
// Listen entry points
// ---------------------------------------------------------------------------

/// Start the MQTT gateway (called from main): the plaintext/TLS listeners are **independent**; a failure of either only warns and
/// the node keeps running (② §7.2).
pub fn spawn(state: Arc<AppState>) {
    if !state.cfg.mqtt.enabled && !state.cfg.mqtt.tls_enabled {
        tracing::info!(
            "mqtt gateway disabled by config (mqtt.enabled=false, mqtt.tls_enabled=false)"
        );
        return;
    }
    if state.cfg.mqtt.enabled {
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(state).await {
                tracing::warn!(error = %e, "mqtt gateway cannot listen; node continues without MQTT");
            }
        });
    } else {
        tracing::info!("mqtt plaintext gateway disabled by config (mqtt.enabled=false)");
    }
    if state.cfg.mqtt.tls_enabled {
        tokio::spawn(async move {
            if let Err(e) = serve_tls(state).await {
                tracing::warn!(
                    error = %e,
                    "mqtt tls gateway cannot listen; node continues without MQTT over TLS (plaintext unaffected)"
                );
            }
        });
    } else {
        tracing::info!("mqtt tls gateway disabled by config (mqtt.tls_enabled=false)");
    }
}

/// Listen on `cfg.mqtt.bind` and spawn an independent task per connection; the connection count is bounded by `cfg.mqtt.max_connections`.
pub async fn serve(state: Arc<AppState>) -> io::Result<()> {
    let bind = state.cfg.mqtt.bind.clone();
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    let listen_addr = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| bind.clone());
    let redis = RedisLink::connect(&state.cfg.redis.url).await;
    tracing::info!(
        addr = %listen_addr,
        max_connections = state.cfg.mqtt.max_connections,
        realtime_channel = redis.is_some(),
        "mqtt gateway listening"
    );

    let active = Arc::new(AtomicUsize::new(0));
    let max_connections = state.cfg.mqtt.max_connections;
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "mqtt accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if !try_acquire(&active, max_connections) {
            tracing::warn!(peer = %peer, max_connections, "mqtt connection limit reached, closing");
            drop(socket);
            continue;
        }
        let state = state.clone();
        let active_guard = active.clone();
        let redis = redis.clone();
        tokio::spawn(async move {
            let _guard = ActiveGuard { active: active_guard };
            handle_connection(state, socket, peer, redis).await;
        });
    }
}

/// Listen on `cfg.mqtt.tls_bind` (TLS/mTLS): after a successful TLS handshake, enter the same MQTT lifecycle as plaintext.
///
/// - A certificate/private key/CA load or port bind failure returns `Err` (`spawn` only WARNs; node readiness is unaffected);
/// - A handshake failure counts `lattice_mqtt_tls_connections_total{result=fail}`, and certificate-class failures (no certificate/bad chain/
///   expired/wrong CA) additionally count `lattice_mqtt_tls_auth_total{result=no_cert|bad_cert}`;
/// - A successful handshake counts `{result=ok}`; no client certificate (only require=false) counts `no_cert` and falls back to PSK/JWT;
/// - With a client certificate, the X.509 identity is parsed, and after CONNECT the PG validation + anti-impersonation checks run.
pub async fn serve_tls(state: Arc<AppState>) -> io::Result<()> {
    let tls_config = load_tls_server_config(&state.cfg.mqtt)?;
    let bind = state.cfg.mqtt.tls_bind.clone();
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    let listen_addr = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| bind.clone());
    let redis = RedisLink::connect(&state.cfg.redis.url).await;
    tracing::info!(
        addr = %listen_addr,
        max_connections = state.cfg.mqtt.max_connections,
        require_client_cert = state.cfg.mqtt.require_client_cert,
        alpn = "mqtt",
        realtime_channel = redis.is_some(),
        "mqtt tls gateway listening"
    );

    let acceptor = TlsAcceptor::from(tls_config);
    let active = Arc::new(AtomicUsize::new(0));
    let max_connections = state.cfg.mqtt.max_connections;
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "mqtt tls accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if !try_acquire(&active, max_connections) {
            tracing::warn!(peer = %peer, max_connections, "mqtt tls connection limit reached, closing");
            drop(socket);
            continue;
        }
        let state = state.clone();
        let active_guard = active.clone();
        let redis = redis.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _guard = ActiveGuard { active: active_guard };
            if let Err(e) = socket.set_nodelay(true) {
                tracing::debug!(error = %e, "mqtt tls set_nodelay failed");
            }
            let tls_stream =
                match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(socket)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(e)) => {
                        state
                            .metrics
                            .mqtt_tls_connections_total
                            .with_label_values(&["fail"])
                            .inc();
                        if let Some(failure) = classify_tls_handshake_error(&e) {
                            state
                                .metrics
                                .mqtt_tls_auth_total
                                .with_label_values(&[failure.as_str()])
                                .inc();
                        }
                        // Log only the error text (rustls certificate error descriptions contain no certificate content).
                        tracing::warn!(peer = %peer, error = %e, "mqtt tls handshake failed");
                        return;
                    }
                    Err(_) => {
                        state
                            .metrics
                            .mqtt_tls_connections_total
                            .with_label_values(&["fail"])
                            .inc();
                        tracing::warn!(peer = %peer, "mqtt tls handshake timeout");
                        return;
                    }
                };
            state
                .metrics
                .mqtt_tls_connections_total
                .with_label_values(&["ok"])
                .inc();
            let leaf = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first());
            let tls_identity = match leaf {
                Some(cert) => parse_client_identity(cert.as_ref()),
                None => {
                    // With require=true rustls already rejected at the handshake stage; here it can only be require=false.
                    state
                        .metrics
                        .mqtt_tls_auth_total
                        .with_label_values(&["no_cert"])
                        .inc();
                    if state.cfg.mqtt.require_client_cert {
                        tracing::warn!(
                            peer = %peer,
                            "mqtt tls connection rejected: require_client_cert=true but client presented no certificate"
                        );
                        return;
                    }
                    TlsClientIdentity::NoCert
                }
            };
            handle_stream(state, tls_stream, peer, redis, Some(tls_identity)).await;
        });
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn write_bytes(out: &mut Vec<u8>, raw: &[u8]) {
        out.extend_from_slice(&(raw.len() as u16).to_be_bytes());
        out.extend_from_slice(raw);
    }

    /// Build a CONNECT packet body (optionally with an MQTT 5 property block).
    fn connect_body(
        level: u8,
        client_id: &str,
        username: Option<&str>,
        password: Option<&str>,
        keepalive: u16,
    ) -> Vec<u8> {
        connect_body_with_props(level, client_id, username, password, keepalive, &[])
    }

    fn connect_body_with_props(
        level: u8,
        client_id: &str,
        username: Option<&str>,
        password: Option<&str>,
        keepalive: u16,
        props: &[u8],
    ) -> Vec<u8> {
        let mut flags = 0x02u8; // clean session
        if username.is_some() {
            flags |= 0x80;
        }
        if password.is_some() {
            flags |= 0x40;
        }
        let mut body = Vec::new();
        write_string(&mut body, "MQTT");
        body.push(level);
        body.push(flags);
        body.extend_from_slice(&keepalive.to_be_bytes());
        if level == 5 {
            write_varint(props.len(), &mut body);
            body.extend_from_slice(props);
        }
        write_string(&mut body, client_id);
        if let Some(username) = username {
            write_string(&mut body, username);
        }
        if let Some(password) = password {
            write_bytes(&mut body, password.as_bytes());
        }
        body
    }

    fn sample_publish(level: u8, qos: u8, topic: &str, payload: &[u8]) -> Packet {
        let mut body = Vec::new();
        write_string(&mut body, topic);
        if qos > 0 {
            body.extend_from_slice(&7u16.to_be_bytes());
        }
        if level == 5 {
            // content-type=text/plain + lx-user-prop=42 + a non-allowlisted user property
            let mut props = Vec::new();
            props.push(0x03);
            write_string(&mut props, "text/plain");
            props.push(0x26);
            write_string(&mut props, "lx-sensor");
            write_string(&mut props, "42");
            props.push(0x26);
            write_string(&mut props, "ignored");
            write_string(&mut props, "x");
            props.push(0x01);
            props.push(0x01);
            write_varint(props.len(), &mut body);
            body.extend_from_slice(&props);
        }
        body.extend_from_slice(payload);
        Packet::new(PACKET_PUBLISH, (qos & 0x03) << 1, body)
    }

    #[test]
    fn varint_roundtrip_and_limits() {
        for value in [0usize, 1, 127, 128, 16_383, 16_384, 2_097_151, 2_097_152, 268_435_455] {
            let mut buf = Vec::new();
            write_varint(value, &mut buf);
            let (back, used) = decode_varint(&buf).expect("decode");
            assert_eq!(back, value);
            assert_eq!(used, buf.len());
        }
        // Truncated (continuation bit only) and over-4-bytes are both invalid
        assert_eq!(decode_varint(&[0x80]), None);
        assert_eq!(decode_varint(&[0xff, 0xff, 0xff, 0xff]), None);
        assert_eq!(decode_varint(&[]), None);
    }

    #[test]
    fn connect_parse_v311() {
        let body = connect_body(4, "client-1", Some("dev-1"), Some("b64:token"), 60);
        let connect = parse_connect(&body).expect("connect");
        assert_eq!(connect.level, 4);
        assert!(connect.clean_session);
        assert_eq!(connect.keepalive_secs, 60);
        assert_eq!(connect.client_id, "client-1");
        assert_eq!(connect.username.as_deref(), Some("dev-1"));
        assert_eq!(connect.password.as_deref(), Some(b"b64:token".as_slice()));
        assert!(!connect.will);
    }

    #[test]
    fn connect_parse_v5_skips_properties() {
        // MQTT 5 CONNECT properties: Session Expiry Interval = 0 (0x11 + u32)
        let props = [0x11u8, 0, 0, 0, 0];
        let body = connect_body_with_props(5, "client-5", Some("user"), Some("pw"), 30, &props);
        let connect = parse_connect(&body).expect("connect");
        assert_eq!(connect.level, 5);
        assert_eq!(connect.keepalive_secs, 30);
        assert_eq!(connect.username.as_deref(), Some("user"));
    }

    #[test]
    fn connect_rejects_bad_protocol_and_flags() {
        // The old protocol (MQTT 3.1) should be returned as UnsupportedProtocol so CONNACK 0x01 can be replied
        let mut old = Vec::new();
        write_string(&mut old, "MQIsdp");
        old.push(3);
        old.push(0x02);
        old.extend_from_slice(&60u16.to_be_bytes());
        write_string(&mut old, "client");
        assert_eq!(parse_connect(&old), Err(ConnectError::UnsupportedProtocol(3)));

        // The password flag is 1 but username is 0 → invalid
        let mut body = connect_body(4, "c", None, None, 10);
        body[7] = 0x42; // flags: clean + password
        // After removing the username the password bytes are still missing; parsing must fail at some stage
        assert!(parse_connect(&body).is_err());
    }

    #[test]
    fn publish_roundtrip_qos0_v311() {
        let packet = sample_publish(4, 0, "lattice/release/dev-1", b"hello");
        let publish = parse_publish(packet.flags, &packet.body, 4).expect("publish");
        assert_eq!(publish.topic, "lattice/release/dev-1");
        assert_eq!(publish.qos, 0);
        assert_eq!(publish.packet_id, None);
        assert_eq!(publish.payload, b"hello");
        assert_eq!(publish.props, PublishProps::default());

        let encoded = encode_publish(4, "lattice/release/dev-1", b"hello", 0, 0);
        assert_eq!(encoded.flags, 0);
        let back = parse_publish(encoded.flags, &encoded.body, 4).expect("decode outbound");
        assert_eq!(back.payload, b"hello");
        assert_eq!(back.topic, "lattice/release/dev-1");
    }

    #[test]
    fn publish_roundtrip_qos1_v5_properties() {
        let packet = sample_publish(5, 1, "lattice/release/dev-1", b"\x00\x01binary");
        let publish = parse_publish(packet.flags, &packet.body, 5).expect("publish");
        assert_eq!(publish.qos, 1);
        assert_eq!(publish.packet_id, Some(7));
        assert_eq!(publish.payload, b"\x00\x01binary");
        assert_eq!(publish.props.content_type.as_deref(), Some("text/plain"));
        assert_eq!(publish.props.payload_format, Some(1));
        assert_eq!(publish.props.user_properties.len(), 2);

        let encoded = encode_publish(5, "a/b", &[1, 2, 3], 1, 9);
        let back = parse_publish(encoded.flags, &encoded.body, 5).expect("decode outbound");
        assert_eq!(back.topic, "a/b");
        assert_eq!(back.qos, 1);
        assert_eq!(back.packet_id, Some(9));
        assert_eq!(back.payload, vec![1, 2, 3]);
        assert_eq!(back.props, PublishProps::default(), "outbound PUBLISH property length is 0");
    }

    #[test]
    fn publish_rejects_invalid_flags_and_properties() {
        assert!(parse_publish(0x06, &[], 4).is_err(), "QoS3 is invalid");
        // An unknown property id (0x7f) must be rejected as a protocol error
        assert!(parse_publish_properties(&[0x7f, 0x00]).is_err());
        // An empty property block is legal
        assert_eq!(parse_publish_properties(&[]).unwrap(), PublishProps::default());
    }

    #[test]
    fn qos_matrix() {
        assert!(qos_supported(0));
        assert!(qos_supported(1));
        assert!(qos_supported(2), "PL-11: QoS2 is supported now");
        assert!(!qos_supported(3), "QoS3 is an illegal protocol value");
        assert_eq!(granted_qos(0), 0);
        assert_eq!(granted_qos(1), 1);
        assert_eq!(granted_qos(2), 2);
        // A 3.1.1 SUBACK allows 0x00/0x01/0x02/0x80
        assert_eq!(suback_code(4, REASON_NOT_AUTHORIZED), 0x80);
        assert_eq!(suback_code(4, 1), 1);
        assert_eq!(suback_code(4, 2), 2, "3.1.1 can grant QoS2");
        assert_eq!(suback_code(5, REASON_NOT_AUTHORIZED), REASON_NOT_AUTHORIZED);
        assert_eq!(suback_code(5, 2), 2);
    }

    // ---------------- QoS2 / persistent session / WILL / retained (completed in PL-11) ----------------

    #[test]
    fn qos_ack_encoding_and_parsing() {
        // 3.1.1: every QoS ACK has only the packet id (2 bytes)
        for packet in [
            puback(4, 7, REASON_SUCCESS),
            pubrec(4, 7, REASON_SUCCESS),
            pubrel(4, 7, REASON_SUCCESS),
            pubcomp(4, 7, REASON_SUCCESS),
        ] {
            assert_eq!(packet.body, vec![0, 7]);
        }
        assert_eq!(pubrel(4, 7, 0).flags, 0x02, "PUBREL fixed-header flags must be 0b0010");
        assert_eq!(pubrec(5, 9, REASON_SUCCESS).body, vec![0, 9], "MQTT5 success may omit the reason");
        assert_eq!(
            pubrec(5, 9, REASON_QUOTA_EXCEEDED).body,
            vec![0, 9, REASON_QUOTA_EXCEEDED]
        );
        assert_eq!(parse_qos_ack(&[0x00, 0x09]), Some((9, REASON_SUCCESS)));
        assert_eq!(
            parse_qos_ack(&[0x00, 0x09, REASON_PACKET_ID_NOT_FOUND]),
            Some((9, REASON_PACKET_ID_NOT_FOUND))
        );
        assert_eq!(parse_qos_ack(&[0x00, 0x00]), None, "packet id 0 is invalid");
        assert_eq!(parse_qos_ack(&[0x00]), None);
    }

    #[test]
    fn publish_retain_and_dup_flags_roundtrip() {
        let ranged = encode_publish_ex(5, "lattice/t/dev", b"r", 1, 3, false, true);
        assert_eq!(ranged.flags & 0x01, 1, "retain flag");
        assert_eq!(ranged.flags & 0x08, 0);
        let parsed = parse_publish(ranged.flags, &ranged.body, 5).unwrap();
        assert!(parsed.retain);
        assert!(!parsed.dup);
        let dup = encode_publish_ex(4, "lattice/t/dev", b"d", 1, 4, true, false);
        assert_eq!(dup.flags & 0x08, 0x08, "DUP flag");
        assert_eq!(dup.flags & 0x01, 0);
    }

    #[test]
    fn pending_publishes_qos2_state_machine() {
        let now = Instant::now();
        let timeout = Duration::from_millis(100);
        let mut pending = PendingPublishes::new(5, timeout, 3);
        let packet = encode_publish(5, "lattice/t/dev", b"q2", 2, 7);
        // Register a QoS1 packet first to verify that PUBREC on QoS1 is a protocol error.
        let ack_packet = encode_publish(5, "lattice/t/dev", b"q1", 1, 8);
        pending.register(8, ack_packet, 1, "lattice/t/dev".into(), b"q1".to_vec(), Vec::new(), None, now);
        pending.register(7, packet.clone(), 2, "lattice/t/dev".into(), b"q2".to_vec(), Vec::new(), None, now);
        assert_eq!(pending.len(), 2);

        // PUBREC → write PUBREL and enter AwaitPubcomp; retransmission starts resending PUBREL (not PUBLISH)
        match pending.on_pubrec(7, REASON_SUCCESS, now) {
            PubRecAction::SendPubRel(rel) => {
                assert_eq!(rel.kind, PACKET_PUBREL);
                assert_eq!(rel.flags, 0x02);
                assert_eq!(parse_qos_ack(&rel.body), Some((7, REASON_SUCCESS)));
            }
            other => panic!("expected SendPubRel, got {other:?}"),
        }
        match pending.retransmit(7, now + timeout) {
            Some(Retransmit::Resend(resend)) => {
                assert_eq!(resend.kind, PACKET_PUBREL, "a PUBREL-stage timeout must resend PUBREL");
                assert_eq!(parse_qos_ack(&resend.body).unwrap().0, 7);
            }
            other => panic!("expected a PUBREL resend, got {other:?}"),
        }
        // A repeated PUBREC is an illegal state machine transition
        assert_eq!(pending.on_pubrec(7, REASON_SUCCESS, now), PubRecAction::ProtocolError);
        // A QoS1 packet receiving PUBREC → protocol error
        assert_eq!(pending.on_pubrec(8, REASON_SUCCESS, now), PubRecAction::ProtocolError);
        // Unknown packet id → Unknown (the write task replies PUBREL 0x92)
        assert_eq!(pending.on_pubrec(999, REASON_SUCCESS, now), PubRecAction::Unknown);

        // PUBCOMP clears and triggers the redelivery notification
        let (ack_tx, mut ack_rx) = oneshot::channel();
        pending.register(11, encode_publish(5, "f", b"x", 2, 11), 2, "f".into(), b"x".to_vec(), Vec::new(), Some(ack_tx), now);
        pending.on_pubrec(11, REASON_SUCCESS, now);
        assert_eq!(pending.on_pubcomp(11), PubCompAction::Completed);
        assert!(ack_rx.try_recv().is_ok(), "PUBCOMP should trigger the redelivery confirmation");
        assert_eq!(pending.on_pubcomp(11), PubCompAction::Unknown, "a repeated PUBCOMP does not match");
        // A QoS1 entry receiving PUBCOMP does not match
        assert_eq!(pending.on_pubcomp(8), PubCompAction::Unknown);

        // MQTT5 PUBREC failure reason → drop it and do not trigger a redelivery success
        let (fail_tx, mut fail_rx) = oneshot::channel();
        pending.register(12, encode_publish(5, "f", b"y", 2, 12), 2, "f".into(), b"y".to_vec(), Vec::new(), Some(fail_tx), now);
        assert_eq!(
            pending.on_pubrec(12, REASON_QUOTA_EXCEEDED, now),
            PubRecAction::Rejected { reason: REASON_QUOTA_EXCEEDED }
        );
        assert!(fail_rx.try_recv().is_err(), "a rejected packet must not notify a redelivery success");
        assert!(pending.snapshot().iter().all(|e| e.qos == 2), "the snapshot contains only QoS2");
    }

    #[test]
    fn pending_publishes_qos2_snapshot_restore_resends_with_same_packet_id() {
        let now = Instant::now();
        let mut pending = PendingPublishes::new(5, Duration::from_secs(10), 3);
        pending.register(21, encode_publish(5, "lattice/t/dev", b"a", 2, 21), 2, "lattice/t/dev".into(), b"a".to_vec(), Vec::new(), None, now);
        pending.on_pubrec(21, REASON_SUCCESS, now); // enter AwaitPubcomp
        pending.register(22, encode_publish(5, "lattice/t/dev", b"b", 2, 22), 2, "lattice/t/dev".into(), b"b".to_vec(), vec![4, 9], None, now);
        let snapshot = pending.snapshot();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(
            snapshot.iter().find(|e| e.packet_id == 22).map(|e| e.sub_ids.clone()),
            Some(vec![4, 9]),
            "Subscription Identifier is persisted with the session"
        );

        // Reconnect restore: AwaitPubcomp → resend PUBREL immediately; AwaitPubrec → resend PUBLISH(DUP=1) with the same id
        let mut restored = PendingPublishes::new(5, Duration::from_secs(10), 3);
        let resend = restored.restore(&snapshot, now);
        assert_eq!(resend.len(), 2);
        let rel = resend.iter().find(|p| p.kind == PACKET_PUBREL).expect("PUBREL resend");
        assert_eq!(parse_qos_ack(&rel.body).unwrap().0, 21);
        let publish = resend.iter().find(|p| p.kind == PACKET_PUBLISH).expect("PUBLISH resend");
        assert_ne!(publish.flags & 0x08, 0, "a PUBLISH resend must have DUP=1");
        // The restore resend keeps the Subscription Identifier property (the property block follows topic + packet id).
        let topic_len = u16::from_be_bytes([publish.body[0], publish.body[1]]) as usize;
        let prop_offset = 2 + topic_len + 2;
        let (prop_len, used) = decode_varint(&publish.body[prop_offset..]).expect("props len");
        assert_eq!(
            &publish.body[prop_offset + used..prop_offset + used + prop_len],
            &[0x0b, 4, 0x0b, 9],
            "a resent PUBLISH should carry the persisted Subscription Identifier (ascending)"
        );
        assert_eq!(parse_publish(publish.flags, &publish.body, 5).unwrap().packet_id, Some(22));
        assert_eq!(restored.len(), 2);
        // Continue through the state machine after restore
        assert!(matches!(
            restored.on_pubrec(22, REASON_SUCCESS, now),
            PubRecAction::SendPubRel(_)
        ));
        assert_eq!(restored.on_pubcomp(22), PubCompAction::Completed);
    }

    #[test]
    fn session_and_retained_key_layout() {
        assert_eq!(
            session_state_key("u1", "d1", "c1"),
            "lattice:mqtt:sess:u1:d1:c1:state"
        );
        assert_eq!(
            session_outbound_key("u1", "d1", "c1"),
            "lattice:mqtt:sess:u1:d1:c1:out"
        );
        assert_eq!(retained_key("release", "d1"), "lattice:mqtt:retained:release:d1");
        assert_eq!(will_key("u1", "d1", "c1"), "lattice:mqtt:will:u1:d1:c1");
        assert_eq!(device_of_filter("lattice/release/d1"), "d1");
        // retained message encode/decode: binary-safe payload + qos/content-type preserved
        let publish = sample_publish(5, 1, "lattice/release/dev-1", b"\x00\x01raw");
        let parsed = parse_publish(publish.flags, &publish.body, 5).unwrap();
        let retained = RetainedMessage::from_publish(&parsed, "user-1");
        assert_eq!(retained.qos, 1);
        assert_eq!(retained.decode_payload().unwrap(), b"\x00\x01raw");
        let json = serde_json::to_string(&retained).unwrap();
        let back: RetainedMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.decode_payload().unwrap(), b"\x00\x01raw");
    }

    #[test]
    fn connect_parses_will_and_session_expiry() {
        // MQTT 5: Session Expiry=3600 + WILL(delay=5, content-type, qos1/retain) parsed together
        let mut flags = 0x02u8 | 0x04 | (1 << 3) | 0x20; // clean_start + will + will qos1 + will retain
        flags |= 0x80 | 0x40; // username + password
        let mut body = Vec::new();
        write_string(&mut body, "MQTT");
        body.push(5);
        body.push(flags);
        body.extend_from_slice(&30u16.to_be_bytes());
        // CONNECT properties: Session Expiry Interval = 3600
        let mut props = Vec::new();
        props.push(0x11);
        props.extend_from_slice(&3600u32.to_be_bytes());
        write_varint(props.len(), &mut body);
        body.extend_from_slice(&props);
        write_string(&mut body, "client-will");
        // WILL properties: delay=5 + content-type=text/plain
        let mut wprops = Vec::new();
        wprops.push(0x18);
        wprops.extend_from_slice(&5u32.to_be_bytes());
        wprops.push(0x03);
        write_string(&mut wprops, "text/plain");
        write_varint(wprops.len(), &mut body);
        body.extend_from_slice(&wprops);
        write_string(&mut body, "lattice/release/dev-1");
        write_bytes(&mut body, b"offline");
        write_string(&mut body, "dev-1");
        write_bytes(&mut body, b"token");
        let connect = parse_connect(&body).expect("connect with will");
        assert_eq!(connect.props.session_expiry, Some(3600));
        assert!(connect.will);
        assert_eq!(connect.will_qos, 1);
        assert!(connect.will_retain);
        assert_eq!(connect.will_topic.as_deref(), Some("lattice/release/dev-1"));
        assert_eq!(connect.will_payload.as_deref(), Some(b"offline".as_slice()));
        assert_eq!(connect.will_props.delay_secs, Some(5));
        assert_eq!(connect.will_props.content_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn disconnect_reason_and_will_decision() {
        assert_eq!(parse_disconnect(&[]).unwrap(), (REASON_SUCCESS, None));
        assert_eq!(
            parse_disconnect(&[REASON_DISCONNECT_WITH_WILL]).unwrap(),
            (REASON_DISCONNECT_WITH_WILL, None)
        );
        // MQTT5 DISCONNECT + Session Expiry Interval=0 (property length 5)
        let mut body = vec![REASON_SUCCESS, 0x05, 0x11, 0, 0, 0, 0];
        assert_eq!(parse_disconnect(&body).unwrap(), (REASON_SUCCESS, Some(0)));
        body[0] = 0x04;
        assert_eq!(
            parse_disconnect(&body).unwrap(),
            (REASON_DISCONNECT_WITH_WILL, Some(0))
        );
        // A normal DISCONNECT publishes no WILL; an abnormal disconnect/explicit 0x04 does
        assert!(!CloseReason::ClientDisconnect.publish_will());
        assert!(!CloseReason::ClientDisconnect.abnormal());
        assert!(CloseReason::ClientDisconnectWithWill.publish_will());
        for reason in [
            CloseReason::KeepAliveTimeout,
            CloseReason::ConnectionLost,
            CloseReason::ProtocolError,
            CloseReason::TopicInvalid,
            CloseReason::TopicNotAuthorized,
            CloseReason::QuotaExceeded,
            CloseReason::PublishRetryExhausted,
            CloseReason::IngestFailed,
        ] {
            assert!(reason.publish_will(), "{reason:?} is an abnormal disconnect and should publish the WILL");
        }
    }

    #[test]
    fn subscribe_grants_qos2_and_parses_v5_options() {
        let mut body = Vec::new();
        body.extend_from_slice(&5u16.to_be_bytes());
        write_string(&mut body, "lattice/t/dev-1");
        body.push(2); // request QoS2
        let request = parse_subscribe(&body, 4).expect("subscribe qos2");
        assert_eq!(request.filters[0].1, 2);
        assert_eq!(granted_qos(request.filters[0].1), 2);
        assert_eq!(suback_code(4, 2), 2);
        // MQTT5 reserved bit (bit5) non-zero is rejected; NL/RAP/RH are legal
        let mut v5 = Vec::new();
        v5.extend_from_slice(&6u16.to_be_bytes());
        write_varint(0, &mut v5);
        write_string(&mut v5, "lattice/a/dev-1");
        v5.push(0x0c); // QoS0 + NL(bit2) + RAP(bit3)
        assert!(parse_subscribe(&v5, 5).is_ok());
        v5.pop();
        v5.push(0x20); // QoS0 + reserved bit5
        assert!(parse_subscribe(&v5, 5).is_err());
    }

    #[test]
    fn topic_mapping_and_validation() {
        assert_eq!(
            parse_topic("lattice/release/dev-1"),
            Some(("release".into(), "dev-1".into()))
        );
        // Hierarchical topic path (completed with wildcards): the last segment is still the device segment; the middle may contain '/'
        assert_eq!(
            parse_topic("lattice/site/a/temp/dev-1"),
            Some(("site/a/temp".into(), "dev-1".into()))
        );
        assert_eq!(parse_topic("lattice/release"), None);
        assert_eq!(parse_topic("other/x/y"), None);
        assert_eq!(parse_topic("lattice//dev"), None);
        assert_eq!(parse_topic("lattice/topic/"), None);
        assert_eq!(parse_topic("lattice/site//dev"), None);
        assert_eq!(parse_topic("lattice/to+pic/dev"), None, "wildcards are rejected");
        assert_eq!(parse_topic("lattice/topic/#"), None, "wildcards are rejected");
        assert_eq!(parse_topic("lattice/topic/dev#"), None, "wildcards are rejected");
        assert_eq!(parse_topic("$share/group/lattice/topic/dev"), None);

        assert_eq!(map_topic("lattice/release/dev-1", "dev-1"), Ok("release".into()));
        assert_eq!(
            map_topic("lattice/site/a/temp/dev-1", "dev-1"),
            Ok("site/a/temp".into()),
            "hierarchical topic mapping"
        );
        assert_eq!(
            map_topic("lattice/release/dev-1", "dev-2"),
            Err(TopicError::DeviceMismatch)
        );
        assert_eq!(map_topic("lattice/release", "dev-1"), Err(TopicError::Invalid));
        assert_eq!(map_topic("$share/g/lattice/t/dev-1", "dev-1"), Err(TopicError::Invalid));
        assert_eq!(
            map_topic("lattice/release/dev-1", "dev-2").unwrap_err().suback_reason(),
            REASON_NOT_AUTHORIZED
        );
        assert_eq!(
            map_topic("bad", "dev-1").unwrap_err().suback_reason(),
            REASON_TOPIC_FILTER_INVALID
        );
        assert_eq!(wire_topic("site/a/temp", "dev-1"), "lattice/site/a/temp/dev-1");
    }

    // ---------------- Wildcards / shared subscriptions / Topic Alias (PL-11 continued) ----------------

    #[test]
    fn mqtt_filter_validation_rules() {
        // Legal: exact, single level, multi-level, parent level, empty level, $SYS
        for filter in ["a/b/c", "a/+/c", "a/#", "#", "+", "+/+", "a//b", "$SYS/#", "lattice/a/#"] {
            assert!(validate_topic_filter(filter).is_ok(), "filter should be legal: {filter}");
        }
        // Illegal: empty, # not alone/not last, + not alone, NUL
        for filter in ["", "a/#/b", "a#", "#/a", "a+", "a/+/b+", "+a/b"] {
            assert!(validate_topic_filter(filter).is_err(), "filter should be illegal: {filter}");
        }
        assert!(validate_topic_filter("a/\0/b").is_err());
        assert!(validate_topic_filter(&"a".repeat(65_536)).is_err());
        // Wildcard detection
        assert!(filter_has_wildcard("a/+/c"));
        assert!(filter_has_wildcard("#"));
        assert!(!filter_has_wildcard("lattice/a/dev-1"));
    }

    #[test]
    fn wildcard_matches_semantics() {
        // Single-level +: exactly one level
        assert!(matches("a/+/c", "a/b/c"));
        assert!(!matches("a/+/c", "a/b/d"));
        assert!(!matches("a/+/c", "a/b/c/d"));
        assert!(!matches("a/+/c", "a/c"));
        assert!(matches("a/+/c", "a//c"), "MQTT allows empty levels");
        // Multi-level #: all remaining levels, and it matches the parent level
        assert!(matches("a/#", "a"));
        assert!(matches("a/#", "a/b"));
        assert!(matches("a/#", "a/b/c"));
        assert!(!matches("a/#", "b/a"));
        assert!(matches("#", "a"));
        assert!(matches("#", "a/b/c"));
        // Other boundaries
        assert!(matches("+/+", "a/b"));
        assert!(!matches("+/+", "a/b/c"));
        assert!(matches("sport/+", "sport/"));
        assert!(!matches("a/b", "a/b/c"));
        assert!(!matches("a/b/c", "a/b"));
        assert!(!matches("", "a"));
        assert!(!matches("a", ""));
        // MQTT 4.7.2: a topic starting with $ is not matched by filters starting with # / +
        assert!(!matches("#", "$SYS/broker/load"));
        assert!(!matches("+/broker/load", "$SYS/broker/load"));
        assert!(!matches("+/#", "$SYS/x"));
        // An explicit $ prefix filter can match
        assert!(matches("$SYS/#", "$SYS/broker/load"));
        assert!(matches("$SYS/+", "$SYS/broker"));
        assert!(matches("$SYS/broker/load", "$SYS/broker/load"));
    }

    #[test]
    fn shared_filter_parsing() {
        assert_eq!(
            parse_shared_filter("$share/g1/a/#"),
            Some(("g1".into(), "a/#".into()))
        );
        assert_eq!(
            parse_shared_filter("$share/g1/lattice/a/#"),
            Some(("g1".into(), "lattice/a/#".into()))
        );
        assert_eq!(parse_shared_filter("$share//a/#"), None, "the group name cannot be empty");
        assert_eq!(parse_shared_filter("$share/g1"), None, "missing filter");
        assert_eq!(parse_shared_filter("$share/g1/"), None, "empty filter");
        assert_eq!(parse_shared_filter("$share/g+1/a/#"), None, "wildcards are not allowed in the group name");
        assert_eq!(parse_shared_filter("$share/g1/a/#/b"), None, "invalid inner filter");
        assert_eq!(
            parse_shared_filter("$share/g1/$share/g2/a"),
            None,
            "nested shared subscriptions are not allowed"
        );
        assert_eq!(parse_shared_filter("share/g1/a"), None);
        // Normalize the shared inner filter: only wildcard filters are accepted; shared subscriptions on exact filters are unimplemented (0x8F)
        assert_eq!(normalize_shared_pattern("a/#", "dev-1"), Ok("a/#".into()));
        assert_eq!(normalize_shared_pattern("lattice/site/+/temp", "dev-1"), Ok("site/+/temp".into()));
        assert_eq!(
            normalize_shared_pattern("lattice/site/temp/dev-1", "dev-1"),
            Err(REASON_TOPIC_FILTER_INVALID),
            "shared subscriptions on exact filters are unimplemented (preserving the smoke contract)"
        );
        assert_eq!(normalize_shared_pattern("bad", "dev-1"), Err(REASON_TOPIC_FILTER_INVALID));
    }

    #[test]
    fn filter_normalization_and_redis_pattern() {
        assert_eq!(normalize_filter("lattice/site/#"), "site/#");
        assert_eq!(normalize_filter("site/+/temp"), "site/+/temp");
        assert_eq!(normalize_filter("#"), "#");
        assert_eq!(redis_channel_pattern("#"), "lattice:mqtt:*");
        assert_eq!(redis_channel_pattern("site/#"), "lattice:mqtt:site*");
        assert_eq!(redis_channel_pattern("site/a/#"), "lattice:mqtt:site/a*");
        assert_eq!(redis_channel_pattern("site/+/temp"), "lattice:mqtt:site*");
        assert_eq!(redis_channel_pattern("a/b/+/c"), "lattice:mqtt:a/b*");
        // Redis glob metacharacter escaping: a * inside the path must not widen the candidate set
        assert_eq!(redis_channel_pattern("a*/b"), "lattice:mqtt:a\\*/b*");
        // Consistent with the keys::channel_mqtt prefix (preventing drift between two places)
        assert!(keys::channel_mqtt("x").starts_with(MQTT_CHANNEL_PREFIX));
    }

    #[test]
    fn topic_alias_resolution_matrix() {
        let mut aliases: HashMap<u16, String> = HashMap::new();
        let max = 4u16;
        // No alias: a non-empty topic is normal; an empty topic is a protocol error (MQTT 5 §3.3.2.1)
        assert_eq!(resolve_topic_alias(&aliases, max, None, "lattice/a/dev"), AliasOutcome::None);
        assert_eq!(
            resolve_topic_alias(&aliases, max, None, ""),
            AliasOutcome::Error(AliasError::EmptyTopicWithoutAlias)
        );
        // alias=0 / over the cap / server cap 0 (aliases not accepted)
        assert_eq!(
            resolve_topic_alias(&aliases, max, Some(0), "t"),
            AliasOutcome::Error(AliasError::Zero)
        );
        assert_eq!(
            resolve_topic_alias(&aliases, max, Some(5), "t"),
            AliasOutcome::Error(AliasError::AboveMax)
        );
        assert_eq!(
            resolve_topic_alias(&aliases, 0, Some(1), "t"),
            AliasOutcome::Error(AliasError::AboveMax)
        );
        // Create the mapping → use the mapping (empty topic)
        assert_eq!(
            resolve_topic_alias(&aliases, max, Some(1), "lattice/a/dev"),
            AliasOutcome::Set
        );
        aliases.insert(1, "lattice/a/dev".into());
        assert_eq!(
            resolve_topic_alias(&aliases, max, Some(1), ""),
            AliasOutcome::Used("lattice/a/dev".into())
        );
        // An unknown alias cannot be used with an empty topic
        assert_eq!(
            resolve_topic_alias(&aliases, max, Some(2), ""),
            AliasOutcome::Error(AliasError::Unknown)
        );
        // The same alias pointing at a different topic → conflict (strict handling, E2E asserts 0x94)
        assert_eq!(
            resolve_topic_alias(&aliases, max, Some(1), "lattice/b/dev"),
            AliasOutcome::Error(AliasError::Conflict)
        );
        // Setting the same topic repeatedly is idempotent
        assert_eq!(
            resolve_topic_alias(&aliases, max, Some(1), "lattice/a/dev"),
            AliasOutcome::Set
        );
        // Error-code mapping: everything except an empty topic is MQTT5 0x94 Topic Alias invalid
        assert_eq!(AliasError::Zero.reason(), REASON_TOPIC_ALIAS_INVALID);
        assert_eq!(AliasError::AboveMax.reason(), REASON_TOPIC_ALIAS_INVALID);
        assert_eq!(AliasError::Unknown.reason(), REASON_TOPIC_ALIAS_INVALID);
        assert_eq!(AliasError::Conflict.reason(), REASON_TOPIC_ALIAS_INVALID);
        assert_eq!(AliasError::EmptyTopicWithoutAlias.reason(), REASON_PROTOCOL_ERROR);
    }

    #[test]
    fn connack_advertises_alias_maximum() {
        let v5 = connack_with_alias_max(5, false, CONNACK_ACCEPTED, 16);
        assert_eq!(v5.body[0], 0);
        assert_eq!(v5.body[1], CONNACK_ACCEPTED);
        assert_eq!(v5.body[2], 3, "property length 3");
        assert_eq!(v5.body[3], 0x22, "Topic Alias Maximum property id");
        assert_eq!(u16::from_be_bytes([v5.body[4], v5.body[5]]), 16);
        // 3.1.1 has no property block (consistent with the old behavior)
        let v4 = connack_with_alias_max(4, false, CONNACK_ACCEPTED, 16);
        assert_eq!(v4.body, vec![0, CONNACK_ACCEPTED]);
        assert_eq!(connack(4, false, CONNACK_ACCEPTED).body, v4.body);
        // 0 = aliases not accepted (explicitly declaring 0 is legal)
        let zero = connack_with_alias_max(5, true, CONNACK_ACCEPTED, 0);
        assert_eq!(&zero.body[..], &[1, CONNACK_ACCEPTED, 3, 0x22, 0, 0]);
    }

    #[test]
    fn connack_advertises_receive_maximum_and_alias() {
        // The client declared both Receive Maximum and Topic Alias Maximum: CONNACK fills 0x21 + 0x22 together.
        let both = connack_with_props(5, false, CONNACK_ACCEPTED, Some(32), Some(16));
        assert_eq!(both.body[0], 0);
        assert_eq!(both.body[1], CONNACK_ACCEPTED);
        assert_eq!(both.body[2], 6, "the two properties total 6 bytes");
        assert_eq!(both.body[3], 0x21, "Receive Maximum property id");
        assert_eq!(u16::from_be_bytes([both.body[4], both.body[5]]), 32);
        assert_eq!(both.body[6], 0x22, "Topic Alias Maximum property id");
        assert_eq!(u16::from_be_bytes([both.body[7], both.body[8]]), 16);
        // Only Receive Maximum declared: CONNACK has only 0x21 (0x22 is not advertised when alias is undeclared,
        // preserving the existing wildcard E2E shape contract "CONNACK only returns 0x22").
        let rm = connack_with_props(5, false, CONNACK_ACCEPTED, Some(65535), None);
        assert_eq!(&rm.body[..], &[0, CONNACK_ACCEPTED, 3, 0x21, 0xff, 0xff]);
        // Neither declared: the 3-byte CONNACK (the existing smoke contract)
        assert_eq!(
            connack_with_props(5, false, CONNACK_ACCEPTED, None, None).body,
            vec![0, CONNACK_ACCEPTED, 0]
        );
        // 3.1.1 has no property block
        assert_eq!(
            connack_with_props(4, false, CONNACK_ACCEPTED, Some(32), Some(16)).body,
            vec![0, CONNACK_ACCEPTED]
        );
        // Config 0 = fill the MQTT 5 default 65535
        assert_eq!(effective_receive_maximum(0), MAX_RECEIVE_MAXIMUM);
        assert_eq!(effective_receive_maximum(1), 1);
        assert_eq!(effective_receive_maximum(32), 32);
        assert_eq!(DEFAULT_RECEIVE_MAXIMUM, 32);
        assert_eq!(MAX_RECEIVE_MAXIMUM, 65535);
    }

    #[test]
    fn outbound_topic_alias_assigns_stable_aliases_per_connection() {
        // Config off / client cap 0 → always disabled
        let mut off = OutboundAlias::new(false, 16);
        assert_eq!(off.assign("lattice/a/dev"), OutAliasDecision::Disabled);
        let mut zero = OutboundAlias::new(true, 0);
        assert_eq!(zero.assign("lattice/a/dev"), OutAliasDecision::Disabled);
        // Cap 2: the first is New(1) with the full topic; the same topic then Reuse(1); the second topic New(2);
        // once the space is full, new topics are no longer compressed (Disabled), while existing mappings can still Reuse.
        let mut alias = OutboundAlias::new(true, 2);
        assert_eq!(alias.assign("lattice/a/dev"), OutAliasDecision::New { alias: 1 });
        assert_eq!(alias.assign("lattice/a/dev"), OutAliasDecision::Reuse { alias: 1 });
        assert_eq!(alias.assign("lattice/b/dev"), OutAliasDecision::New { alias: 2 });
        assert_eq!(alias.assign("lattice/b/dev"), OutAliasDecision::Reuse { alias: 2 });
        assert_eq!(alias.assign("lattice/c/dev"), OutAliasDecision::Disabled);
        assert_eq!(alias.assign("lattice/a/dev"), OutAliasDecision::Reuse { alias: 1 });
    }

    #[test]
    fn publish_props_parse_topic_alias() {
        // PUBLISH property 0x23 + u16
        let props = parse_publish_properties(&[0x23, 0x00, 0x07]).expect("alias prop");
        assert_eq!(props.topic_alias, Some(7));
        // An outbound PUBLISH without properties → None (the server conservatively does not compress downlinks with aliases)
        let encoded = encode_publish(5, "lattice/a/dev", b"x", 1, 9);
        let back = parse_publish(encoded.flags, &encoded.body, 5).unwrap();
        assert_eq!(back.props.topic_alias, None);
        // The CONNECT client Topic Alias Maximum (0x22) is parsed and saved (negotiation record)
        let connect_props = parse_connect_properties(&[0x22, 0x00, 0x05]).expect("connect alias max");
        assert_eq!(connect_props.topic_alias_maximum, Some(5));
        // The CONNECT client Receive Maximum (0x21) is parsed and saved
        let rm_props = parse_connect_properties(&[0x21, 0x00, 0x02]).expect("connect receive max");
        assert_eq!(rm_props.receive_maximum, Some(2));
    }

    #[test]
    fn outbound_publish_props_encode_sub_ids_and_topic_alias() {
        // MQTT 5: Subscription Identifiers ascending and deduped + Topic Alias encoded together, so the client can parse them back.
        let props = OutPublishProps { sub_ids: vec![1, 2, 2, 3], topic_alias: Some(7) };
        let packet = encode_publish_with_props(5, "lattice/a/dev", b"x", 1, 9, false, false, &props);
        let back = parse_publish(packet.flags, &packet.body, 5).expect("parse outbound publish");
        assert_eq!(back.topic, "lattice/a/dev");
        assert_eq!(back.packet_id, Some(9));
        assert_eq!(back.props.topic_alias, Some(7));
        let mut body = packet.body.as_slice();
        // The property block follows topic + packet id: parse the number and values of 0x0B (ascending, 3 deduped)
        let topic_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        body = &body[2 + topic_len + 2..];
        let (prop_len, used) = decode_varint(body).expect("props len");
        let raw = &body[used..used + prop_len];
        assert_eq!(
            parse_publish_properties(raw).expect("props").topic_alias,
            Some(7)
        );
        let mut ids = Vec::new();
        let mut r = Reader::new(raw);
        while r.remaining() > 0 {
            match r.varint().unwrap() {
                0x0b => ids.push(r.varint().unwrap() as u32),
                0x23 => {
                    let _ = r.u16().unwrap();
                }
                other => panic!("unexpected property 0x{other:02x}"),
            }
        }
        assert_eq!(ids, vec![1, 2, 3], "identifiers are deduped and ascending");
        // No properties: with an empty topic + alias (using the mapping) the topic length in body is 0
        let reuse = encode_publish_with_props(
            5,
            "",
            b"y",
            1,
            10,
            false,
            false,
            &OutPublishProps { sub_ids: vec![5], topic_alias: Some(1) },
        );
        let reuse_pub = parse_publish(reuse.flags, &reuse.body, 5).unwrap();
        assert_eq!(reuse_pub.topic, "");
        assert_eq!(reuse_pub.props.topic_alias, Some(1));
        // 3.1.1: properties are ignored entirely (body is byte-identical to the old encoding)
        let v4 = encode_publish_with_props(
            4,
            "lattice/a/dev",
            b"z",
            0,
            0,
            false,
            false,
            &OutPublishProps { sub_ids: vec![1], topic_alias: Some(1) },
        );
        assert_eq!(v4.body, encode_publish_ex(4, "lattice/a/dev", b"z", 0, 0, false, false).body);
    }

    #[test]
    fn delivery_dedupe_window_claims_once() {
        let mut dedupe = DeliveryDedupe::new(Duration::from_secs(3));
        assert!(dedupe.claim("a\u{0}id-1".into()));
        assert!(!dedupe.claim("a\u{0}id-1".into()), "a duplicate within the window should be deduped");
        assert!(dedupe.claim("a\u{0}id-2".into()));
        assert!(dedupe.claim("b\u{0}id-1".into()), "the same id on a different topic is not deduped");
        // The envelope id comes from the Redis downlink envelope bytes; same id on a different topic → a different key
        let envelope = Envelope {
            id: "01JTESTID".into(),
            conv_id: "topic:a".into(),
            payload: b"x".to_vec(),
            ..Default::default()
        };
        let body = envelope.encode_body();
        assert_eq!(delivery_dedupe_key("a", &body), "a\u{0}01JTESTID");
        assert_eq!(delivery_dedupe_key("b", &body), "b\u{0}01JTESTID");
    }

    #[test]
    fn plain_filter_matching_and_max_qos_with_sub_ids() {
        let filters: Arc<Mutex<Vec<PlainFilter>>> = Arc::new(Mutex::new(vec![
            PlainFilter::exact("lattice/a/dev".into(), "a".into(), 1, Some(3)),
            PlainFilter::wildcard("a/#".into(), "a/#".into(), 2, Some(1)),
            PlainFilter::wildcard("a/+".into(), "a/+".into(), 0, Some(3)),
            PlainFilter::wildcard("b/+".into(), "b/+".into(), 0, None),
        ]));
        // Overlapping filters (exact + wildcard) take the max QoS (MQTT 3.1.1 §3.8.4 convention)
        assert_eq!(matching_delivery(&filters, "a"), Some((2, vec![1, 3])));
        assert_eq!(matching_delivery(&filters, "a/b"), Some((2, vec![1, 3])));
        assert_eq!(
            matching_delivery(&filters, "b/x"),
            Some((0, vec![])),
            "matched a QoS0 filter without an identifier"
        );
        assert_eq!(matching_delivery(&filters, "c"), None);
        // Subscription Identifier dedup + ascending: ids of multiple matching subscriptions in the same filter table are merged and stable
        assert_eq!(matching_delivery(&filters, "a/b").unwrap().1, vec![1, 3]);
    }

    #[test]
    fn shared_candidate_order_round_robin() {
        assert_eq!(shared_candidate_order(0, 3), vec![0, 1, 2]);
        assert_eq!(shared_candidate_order(1, 3), vec![1, 2, 0]);
        assert_eq!(shared_candidate_order(2, 3), vec![2, 0, 1]);
        assert_eq!(shared_candidate_order(7, 3), vec![1, 2, 0], "the cursor is handled modulo");
        assert!(shared_candidate_order(0, 0).is_empty());
        // Simulate in-group round robin: 7 messages across 3 members → 3/2/2 (order 0,1,2,0,1,2,0)
        let mut cursor = 0usize;
        let mut hits = [0usize; 3];
        for _ in 0..7 {
            let order = shared_candidate_order(cursor, 3);
            let chosen = order[0];
            hits[chosen] += 1;
            cursor = (chosen + 1) % 3;
        }
        assert_eq!(hits, [3, 2, 2]);
    }

    #[test]
    fn rate_limit_and_keepalive_decisions() {
        assert!(!quota_exceeded(0, DEVICE_MSG_PER_SEC));
        assert!(!quota_exceeded(10, DEVICE_MSG_PER_SEC));
        assert!(quota_exceeded(11, DEVICE_MSG_PER_SEC));
        assert_eq!(DEVICE_MSG_PER_SEC, 10, "design §17.13: MQTT 10 msg/s per device");
        assert_eq!(keepalive_timeout(0), None);
        assert_eq!(keepalive_timeout(60), Some(Duration::from_secs(90)));
        assert_eq!(keepalive_timeout(1), Some(Duration::from_millis(1500)));
    }

    // ---------------- QoS1 reliability (PL-11): packet id / retransmission / failure semantics ----------------

    #[test]
    fn pending_publishes_packet_id_wraps_and_skips_zero() {
        let mut pending = PendingPublishes::new(5, Duration::from_millis(10), 3);
        let mut seen = Vec::with_capacity(u16::MAX as usize);
        for _ in 0..u16::MAX {
            let id = pending.alloc_packet_id();
            assert_ne!(id, 0, "packet id 0 is invalid");
            seen.push(id);
        }
        // 1..=65535 all used, each exactly once
        assert_eq!(seen.len(), 65535);
        assert_eq!(seen[0], 1);
        assert_eq!(*seen.last().unwrap(), u16::MAX);
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 65535, "there should be no duplicates within a cycle");
        // Wraparound: the next one returns to 1 (skipping 0)
        assert_eq!(pending.alloc_packet_id(), 1);
        assert_eq!(pending.alloc_packet_id(), 2);
    }

    #[test]
    fn pending_publishes_ack_clears_and_notifies_replay() {
        let now = Instant::now();
        let mut pending = PendingPublishes::new(5, Duration::from_secs(10), 3);
        let packet = encode_publish(5, "lattice/t/dev", b"p", 1, 9);
        let (ack_tx, mut ack_rx) = oneshot::channel();
        pending.register(
            9,
            packet,
            1,
            "lattice/t/dev".into(),
            b"p".to_vec(),
            Vec::new(),
            Some(ack_tx),
            now,
        );
        assert_eq!(pending.len(), 1);
        assert!(pending.next_due().is_some());

        assert!(pending.ack(9), "PUBACK should match pending");
        assert_eq!(pending.len(), 0, "PUBACK should clear the entry");
        assert!(ack_rx.try_recv().is_ok(), "the redelivery task should receive the confirmation");
        assert!(!pending.ack(9), "a repeated PUBACK should not match");
    }

    #[test]
    fn pending_publishes_retransmit_dup_then_exhaust() {
        let now = Instant::now();
        let timeout = Duration::from_millis(100);
        let mut pending = PendingPublishes::new(4, timeout, 2);
        let packet = encode_publish(4, "lattice/t/dev", b"payload", 1, 42);
        pending.register(
            42,
            packet.clone(),
            1,
            "lattice/t/dev".into(),
            b"payload".to_vec(),
            Vec::new(),
            None,
            now,
        );
        assert!(pending.due_ids(now).is_empty(), "a just-registered packet should not be due");
        assert_eq!(pending.due_ids(now + timeout * 2), vec![42], "due entries are returned by id");

        // First/second retransmission: same packet id + DUP=1 + unchanged body
        for _ in 0..2 {
            match pending.retransmit(42, now + timeout * 2) {
                Some(Retransmit::Resend(dup)) => {
                    assert_eq!(dup.kind, PACKET_PUBLISH);
                    assert_ne!(dup.flags & 0x08, 0, "retransmission must set DUP=1");
                    assert_eq!(dup.body, packet.body, "the retransmitted body should match the first send");
                    assert_eq!(dup.flags & 0x06, packet.flags & 0x06, "the QoS bits are unchanged");
                }
                other => panic!("expected a DUP resend, got {other:?}"),
            }
        }
        // The third expiry → above max=2 → Exhausted (no more packets)
        assert_eq!(
            pending.retransmit(42, now + timeout * 3),
            Some(Retransmit::Exhausted)
        );
        assert_eq!(pending.len(), 1, "an over-limit entry is kept until the connection closes (the caller disconnects)");
        assert_eq!(pending.retransmit(999, now), None, "an unknown packet id returns None");
    }

    #[test]
    fn parse_puback_accepts_v311_and_v5_bodies() {
        assert_eq!(parse_puback(&[0x00, 0x0b]), Some(11));
        // MQTT5 failure PUBACK: packet id + reason + property length
        assert_eq!(parse_puback(&[0x00, 0x0b, REASON_QUOTA_EXCEEDED]), Some(11));
        assert_eq!(parse_puback(&[0x00, 0x0b, 0x00, 0x00]), Some(11));
        assert_eq!(parse_puback(&[]), None);
        assert_eq!(parse_puback(&[0x00]), None);
        assert_eq!(parse_puback(&[0x00, 0x00]), None, "packet id 0 is invalid");
    }

    #[test]
    fn ingest_failure_reason_codes() {
        let rate = ingest_failure_reason(&LatticeError::rate("rate limit exceeded"));
        assert_eq!((rate.code, rate.label), (REASON_QUOTA_EXCEEDED, "rate"));
        let forbidden = ingest_failure_reason(&LatticeError::forbidden("not a member"));
        assert_eq!(
            (forbidden.code, forbidden.label),
            (REASON_NOT_AUTHORIZED, "forbidden")
        );
        let protocol = ingest_failure_reason(&LatticeError::protocol("bad envelope"));
        assert_eq!(
            (protocol.code, protocol.label),
            (REASON_UNSPECIFIED_ERROR, "protocol")
        );
        let persist = ingest_failure_reason(&LatticeError::internal("pg down"));
        assert_eq!(
            (persist.code, persist.label),
            (REASON_UNSPECIFIED_ERROR, "persist")
        );
    }

    #[test]
    fn inbound_dedup_fingerprint_requires_same_payload_and_topic() {
        assert_eq!(payload_fingerprint(b"abc"), payload_fingerprint(b"abc"));
        assert_ne!(payload_fingerprint(b"abc"), payload_fingerprint(b"abd"));
        assert_ne!(payload_fingerprint(b""), payload_fingerprint(b"\0"));

        // Retransmission decision: DUP=1 with the same packet id/topic/payload → reuse the envelope id; otherwise it is a new message.
        let mut session = ConnSession {
            level: 5,
            user_id: "u".into(),
            device_id: "d".into(),
            client_id: "c".into(),
            out: mpsc::channel(1).0,
            persistent: false,
            session_store: None,
            subs: HashMap::new(),
            topic_conv: HashMap::new(),
            inbound_qos1: HashMap::new(),
            inbound_qos2: HashMap::new(),
            replay_offsets: Arc::new(Mutex::new(HashMap::new())),
            plain_filters: Arc::new(Mutex::new(Vec::new())),
            delivery_dedupe: Arc::new(Mutex::new(DeliveryDedupe::new(DELIVERY_DEDUPE_WINDOW))),
            topic_aliases: HashMap::new(),
            inbound_receive_max: None,
            will: None,
            redis: None,
            local_bucket: LocalBucket::default(),
        };
        let first = sample_publish(5, 1, "lattice/t/dev", b"same");
        let publish = parse_publish(first.flags, &first.body, 5).unwrap();
        session.remember_inbound_qos1(7, "lattice/t/dev", "01JTEST", &publish.payload);

        let mut dup_flags = publish.clone();
        dup_flags.dup = true;
        assert_eq!(
            session.retransmitted_env_id(&dup_flags).as_deref(),
            Some("01JTEST")
        );
        let mut other_payload = dup_flags.clone();
        other_payload.payload = b"different".to_vec();
        assert_eq!(session.retransmitted_env_id(&other_payload), None);
        let mut other_packet_id = dup_flags.clone();
        other_packet_id.packet_id = Some(8);
        assert_eq!(session.retransmitted_env_id(&other_packet_id), None);
        let mut not_dup = publish.clone();
        not_dup.dup = false;
        assert_eq!(session.retransmitted_env_id(&not_dup), None, "a non-DUP packet is not a retransmission");
    }

    #[test]
    fn qos1_reliability_defaults_and_config_env() {
        // Defaults: 10s / 3 times / 10 msg/s (task card and §17.13 convention)
        assert_eq!(DEFAULT_RETRANSMIT_MS, 10_000);
        assert_eq!(DEFAULT_MAX_RETRANSMITS, 3);
        assert_eq!(DEFAULT_REPLAY_RATE_PER_SEC, 10);
        // Defaults for QoS2/persistent session/retained (completed in PL-11)
        assert_eq!(DEFAULT_SESSION_TTL_SECS, 3_600);
        assert_eq!(DEFAULT_SESSION_EXPIRY_MAX_SECS, 86_400);
        assert_eq!(DEFAULT_RETAINED_TTL_SECS, 30 * 24 * 3_600);
        let cfg = crate::config::Config::default();
        assert_eq!(cfg.mqtt.retransmit_ms, DEFAULT_RETRANSMIT_MS);
        assert_eq!(cfg.mqtt.max_retransmits, DEFAULT_MAX_RETRANSMITS);
        assert_eq!(cfg.mqtt.replay_rate_per_sec, DEFAULT_REPLAY_RATE_PER_SEC);
        assert_eq!(cfg.mqtt.session_ttl_secs, DEFAULT_SESSION_TTL_SECS);
        assert_eq!(cfg.mqtt.session_expiry_max_secs, DEFAULT_SESSION_EXPIRY_MAX_SECS);
        assert_eq!(cfg.mqtt.retained_ttl_secs, DEFAULT_RETAINED_TTL_SECS);
        // env overrides (E2E uses short TTLs to speed things up)
        std::env::set_var("LATTICE__MQTT__SESSION_TTL_SECS", "120");
        std::env::set_var("LATTICE__MQTT__RETAINED_TTL_SECS", "60");
        let mut env_cfg = crate::config::Config::default();
        env_cfg.apply_env();
        std::env::remove_var("LATTICE__MQTT__SESSION_TTL_SECS");
        std::env::remove_var("LATTICE__MQTT__RETAINED_TTL_SECS");
        assert_eq!(env_cfg.mqtt.session_ttl_secs, 120);
        assert_eq!(env_cfg.mqtt.retained_ttl_secs, 60);
        // After allocating 65535 ids cyclically, the first and last written ids do not collide (smoke-style assertion)
        let mut pending = PendingPublishes::new(4, Duration::from_millis(10), 1);
        let packet = encode_publish(4, "lattice/t/dev", b"p", 1, 1);
        pending.register(1, packet, 1, "lattice/t/dev".into(), b"p".to_vec(), Vec::new(), None, Instant::now());
        assert_ne!(pending.alloc_free_packet_id(), Some(1), "an occupied id should not be allocated again");
    }

    #[tokio::test]
    async fn writer_retransmits_dup_until_puback() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (tx, rx) = mpsc::channel(8);
        let (close_tx, mut close_rx) = mpsc::channel(1);
        let metrics = crate::observe::Metrics::new();
        let pending = PendingPublishes::new(5, Duration::from_millis(40), 3);
        let writer = tokio::spawn(writer_loop(
            server,
            5,
            rx,
            pending,
            Vec::new(),
            None,
            MAX_RECEIVE_MAXIMUM,
            OutboundAlias::new(false, 0),
            close_tx,
            metrics,
        ));

        tx.send(Outbound::publish("lattice/t/dev-1", b"echo".to_vec(), 1))
            .await
            .unwrap();
        let first = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(first.kind, PACKET_PUBLISH);
        assert_eq!(first.flags & 0x08, 0, "the first send has DUP=0");
        let first_publish = parse_publish(first.flags, &first.body, 5).unwrap();
        let packet_id = first_publish.packet_id.expect("QoS1 packet id");
        assert_eq!(first_publish.payload, b"echo");

        // After the timeout a resend with the same packet id and DUP=1 should arrive
        let dup = tokio::time::timeout(Duration::from_millis(1000), read_packet(&mut client))
            .await
            .expect("should receive a DUP resend within the timeout")
            .unwrap()
            .unwrap();
        assert_eq!(dup.kind, PACKET_PUBLISH);
        assert_ne!(dup.flags & 0x08, 0, "a resend must have DUP=1");
        let dup_publish = parse_publish(dup.flags, &dup.body, 5).unwrap();
        assert_eq!(dup_publish.packet_id, Some(packet_id));

        // No further resend should occur after replying PUBACK
        tx.send(Outbound::PubAck { packet_id }).await.unwrap();
        let after_ack =
            tokio::time::timeout(Duration::from_millis(200), read_packet(&mut client)).await;
        assert!(after_ack.is_err(), "no further resend should occur after PUBACK");
        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(1), writer).await;
        // The read loop should have received the "write task ended" notification by now (or receives it when the connection closes normally)
        let _ = close_rx.try_recv();
    }

    #[tokio::test]
    async fn writer_exhausts_retransmit_and_asks_to_close() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (tx, rx) = mpsc::channel(8);
        let (close_tx, mut close_rx) = mpsc::channel(1);
        let metrics = crate::observe::Metrics::new();
        // max=1: over the limit right after the first send + 1 DUP
        let pending = PendingPublishes::new(4, Duration::from_millis(30), 1);
        let writer = tokio::spawn(writer_loop(
            server,
            4,
            rx,
            pending,
            Vec::new(),
            None,
            MAX_RECEIVE_MAXIMUM,
            OutboundAlias::new(false, 0),
            close_tx,
            metrics,
        ));
        tx.send(Outbound::publish("lattice/t/dev-1", b"x".to_vec(), 1))
            .await
            .unwrap();
        let first = read_packet(&mut client).await.unwrap().unwrap();
        assert_eq!(first.kind, PACKET_PUBLISH);
        let dup = tokio::time::timeout(Duration::from_millis(1000), read_packet(&mut client))
            .await
            .expect("should receive one DUP resend")
            .unwrap()
            .unwrap();
        assert_ne!(dup.flags & 0x08, 0);
        // After exceeding the limit the write task should notify the read loop: PublishRetryExhausted
        let reason = tokio::time::timeout(Duration::from_millis(1000), close_rx.recv())
            .await
            .expect("the write task should signal a disconnect")
            .expect("the close channel should not be closed");
        assert_eq!(reason, CloseReason::PublishRetryExhausted);
        let _ = tokio::time::timeout(Duration::from_secs(1), writer).await;
        drop(tx);
    }

    #[test]
    fn connack_suback_and_puback_encoding() {
        assert_eq!(connack(4, false, CONNACK_ACCEPTED).body, vec![0, 0]);
        assert_eq!(connack(5, false, CONNACK_ACCEPTED).body, vec![0, 0, 0]);
        assert_eq!(connack(4, false, CONNACK_BAD_CREDENTIALS).body, vec![0, 0x04]);
        assert_eq!(connack(5, false, REASON_BAD_CREDENTIALS).body, vec![0, 0x86, 0]);

        let pub_v5 = puback(5, 7, REASON_SUCCESS);
        assert_eq!(pub_v5.body, vec![0, 7]);
        let pub_v5_quota = puback(5, 7, REASON_QUOTA_EXCEEDED);
        assert_eq!(pub_v5_quota.body, vec![0, 7, REASON_QUOTA_EXCEEDED]);
        assert_eq!(puback(4, 7, REASON_SUCCESS).body, vec![0, 7]);

        let sub_v5 = suback(5, 3, &[1, REASON_NOT_AUTHORIZED]);
        assert_eq!(sub_v5.body, vec![0, 3, 0, 1, REASON_NOT_AUTHORIZED]);
        let sub_v4 = suback(4, 3, &[suback_code(4, REASON_NOT_AUTHORIZED)]);
        assert_eq!(sub_v4.body, vec![0, 3, 0x80]);

        assert_eq!(unsuback(4, 4, &[REASON_SUCCESS]).body, vec![0, 4]);
        assert_eq!(unsuback(5, 4, &[REASON_SUCCESS]).body, vec![0, 4, 0, 0]);
        assert_eq!(disconnect(REASON_QOS_NOT_SUPPORTED).body[0], REASON_QOS_NOT_SUPPORTED);
    }

    #[test]
    fn subscribe_parsing_validates_options() {
        let mut body = Vec::new();
        body.extend_from_slice(&5u16.to_be_bytes());
        write_string(&mut body, "lattice/t/dev-1");
        body.push(1); // qos1
        let request = parse_subscribe(&body, 4).expect("subscribe");
        assert_eq!(request.packet_id, 5);
        assert_eq!(
            request.filters,
            vec![("lattice/t/dev-1".to_string(), 1u8)]
        );

        // MQTT 5: property block + multiple filters
        let mut body5 = Vec::new();
        body5.extend_from_slice(&6u16.to_be_bytes());
        write_varint(0, &mut body5);
        write_string(&mut body5, "lattice/a/dev-1");
        body5.push(0);
        write_string(&mut body5, "lattice/b/dev-1");
        body5.push(1);
        let request5 = parse_subscribe(&body5, 5).expect("subscribe v5");
        assert_eq!(request5.filters.len(), 2);
        assert_eq!(request5.subscription_id, None, "no identifier when the property block is empty");

        // MQTT 5 Subscription Identifier(0x0B): 1..=268435455 is legal; 0/repeated → protocol error
        let mut with_id = Vec::new();
        with_id.extend_from_slice(&7u16.to_be_bytes());
        let mut id_props = Vec::new();
        id_props.push(0x0b);
        write_varint(268_435_455, &mut id_props);
        write_varint(id_props.len(), &mut with_id);
        with_id.extend_from_slice(&id_props);
        write_string(&mut with_id, "lattice/a/dev-1");
        with_id.push(1);
        let id_request = parse_subscribe(&with_id, 5).expect("subscribe with id");
        assert_eq!(id_request.subscription_id, Some(268_435_455));
        // 0 is invalid
        let mut zero_id = Vec::new();
        zero_id.extend_from_slice(&8u16.to_be_bytes());
        write_varint(2, &mut zero_id);
        zero_id.extend_from_slice(&[0x0b, 0x00]);
        write_string(&mut zero_id, "lattice/a/dev-1");
        zero_id.push(1);
        assert!(parse_subscribe(&zero_id, 5).is_err(), "identifier=0 is a protocol error");
        // A repeated identifier within one SUBSCRIBE is invalid
        let mut dup_id = Vec::new();
        dup_id.extend_from_slice(&9u16.to_be_bytes());
        write_varint(4, &mut dup_id);
        dup_id.extend_from_slice(&[0x0b, 0x01, 0x0b, 0x02]);
        write_string(&mut dup_id, "lattice/a/dev-1");
        dup_id.push(1);
        assert!(parse_subscribe(&dup_id, 5).is_err(), "a repeated identifier is a protocol error");
        // 3.1.1: no property block, always None (0x0B semantics ignored)
        assert_eq!(request.subscription_id, None);

        // An empty filter / QoS3 / a non-zero reserved bit should all error
        let mut empty = Vec::new();
        empty.extend_from_slice(&1u16.to_be_bytes());
        assert!(parse_subscribe(&empty, 4).is_err());
        let mut bad_qos = body.clone();
        bad_qos.pop();
        bad_qos.push(3);
        assert!(parse_subscribe(&bad_qos, 4).is_err());
        let mut bad_bits = body;
        bad_bits.pop();
        bad_bits.push(0x40);
        assert!(parse_subscribe(&bad_bits, 4).is_err());
    }

    #[test]
    fn envelope_build_maps_type_and_metadata() {
        // Default: custom:iot / raw; the topic session key and sender come from the authenticated identity
        let packet = sample_publish(4, 0, "lattice/release/dev-1", b"raw-bytes");
        let publish = parse_publish(packet.flags, &packet.body, 4).unwrap();
        let env = envelope_from_publish("release", "user-1", &publish);
        assert_eq!(env.r#type, DEFAULT_ENVELOPE_TYPE);
        assert_eq!(env.r#type, "custom:iot");
        assert_eq!(env.encoding, "raw");
        assert_eq!(env.conv_id, "topic:release");
        assert_eq!(env.sender, "user-1");
        assert_eq!(env.payload, b"raw-bytes");
        assert_eq!(env.route().to_topic, "release");
        assert!(env.metadata.is_empty());

        // Content-Type property present → MIME mapping; only lx- prefixed User-Property values are passed through
        let packet5 = sample_publish(5, 0, "lattice/json/dev-1", b"{}");
        let publish5 = parse_publish(packet5.flags, &packet5.body, 5).unwrap();
        let env5 = envelope_from_publish("json", "user-1", &publish5);
        assert_eq!((env5.r#type.as_str(), env5.encoding.as_str()), ("text", "utf8"));
        assert_eq!(env5.content_type, "text/plain");
        assert_eq!(env5.metadata.get("lx-sensor").map(String::as_str), Some("42"));
        assert!(!env5.metadata.contains_key("ignored"), "a User-Property without the lx- prefix is dropped");

        assert_eq!(mime_envelope_type("application/json; charset=utf-8"), ("json", "utf8"));
        assert_eq!(mime_envelope_type("image/png"), ("image", "raw"));
        assert_eq!(mime_envelope_type("video/mp4"), ("media", "raw"));
        assert_eq!(mime_envelope_type("application/x-protobuf"), ("proto", "raw"));
        assert_eq!(mime_envelope_type("application/octet-stream"), ("binary", "raw"));
        assert_eq!(mime_envelope_type(""), (DEFAULT_ENVELOPE_TYPE, DEFAULT_ENCODING));
    }

    #[test]
    fn auth_failure_codes_follow_contract() {
        assert_eq!(AuthFailure::BadCredentials.codes(), (CONNACK_BAD_CREDENTIALS, REASON_BAD_CREDENTIALS));
        assert_eq!(AuthFailure::NotAuthorized.codes(), (CONNACK_NOT_AUTHORIZED, REASON_NOT_AUTHORIZED));
        assert_eq!(connack_code(4, AuthFailure::BadCredentials), 0x04);
        assert_eq!(connack_code(5, AuthFailure::BadCredentials), 0x86);
        assert_eq!(connack_code(4, AuthFailure::NotAuthorized), 0x05);
        assert_eq!(connack_code(5, AuthFailure::NotAuthorized), 0x87);
        assert_eq!(connack_code(5, AuthFailure::Unavailable), REASON_SERVER_UNAVAILABLE);
    }

    #[test]
    fn connection_limit_cas() {
        let active = AtomicUsize::new(0);
        assert!(try_acquire(&active, 2));
        assert!(try_acquire(&active, 2));
        assert!(!try_acquire(&active, 2), "exceeding max_connections should be rejected");
        assert_eq!(active.load(Ordering::Relaxed), 2);
        // 0 = unlimited
        assert!(try_acquire(&active, 0));
        assert_eq!(active.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn packet_stream_roundtrip_and_eof() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let connect = Packet::new(PACKET_CONNECT, 0, connect_body(5, "c", Some("u"), Some("p"), 15));
        write_packet(&mut client, &connect).await.unwrap();
        let ping = Packet::new(PACKET_PINGREQ, 0, Vec::new());
        write_packet(&mut client, &ping).await.unwrap();
        drop(client);

        assert_eq!(read_packet(&mut server).await.unwrap(), Some(connect));
        assert_eq!(read_packet(&mut server).await.unwrap(), Some(ping));
        assert_eq!(read_packet(&mut server).await.unwrap(), None, "peer closed → None");
    }

    // -----------------------------------------------------------------------
    // End-to-end integration test (ignored by default; run manually when a local dev PG/Redis is ready)
    //
    //   cargo test -p lattice-node -- --ignored mqtt::tests::e2e_gateway_roundtrip
    // -----------------------------------------------------------------------

    use crate::transport::mqtt as gateway;

    fn mqtt_connect_packet(
        level: u8,
        client_id: &str,
        username: &str,
        password: &str,
        keepalive: u16,
    ) -> Packet {
        let body = connect_body(level, client_id, Some(username), Some(password), keepalive);
        Packet::new(PACKET_CONNECT, 0, body)
    }

    fn mqtt_subscribe_packet(level: u8, packet_id: u16, filter: &str, qos: u8) -> Packet {
        let mut body = Vec::new();
        body.extend_from_slice(&packet_id.to_be_bytes());
        if level == 5 {
            body.push(0);
        }
        write_string(&mut body, filter);
        body.push(qos);
        Packet::new(PACKET_SUBSCRIBE, 0x02, body)
    }

    fn mqtt_unsubscribe_packet(level: u8, packet_id: u16, filter: &str) -> Packet {
        let mut body = Vec::new();
        body.extend_from_slice(&packet_id.to_be_bytes());
        if level == 5 {
            body.push(0);
        }
        write_string(&mut body, filter);
        Packet::new(PACKET_UNSUBSCRIBE, 0x02, body)
    }

    fn mqtt_publish_packet(level: u8, qos: u8, topic: &str, payload: &[u8], packet_id: u16) -> Packet {
        let mut body = Vec::new();
        write_string(&mut body, topic);
        if qos > 0 {
            body.extend_from_slice(&packet_id.to_be_bytes());
        }
        if level == 5 {
            body.push(0);
        }
        body.extend_from_slice(payload);
        Packet::new(PACKET_PUBLISH, (qos & 0x03) << 1, body)
    }

    async fn read_next(stream: &mut TcpStream) -> Option<Packet> {
        read_packet(stream).await.expect("read_packet")
    }

    /// Peer EOF or a reset connection both count as closed (on Windows a reset before reading everything is legal).
    #[allow(dead_code)]
    async fn read_until_closed(stream: &mut TcpStream) -> bool {
        for _ in 0..20 {
            match read_packet(stream).await {
                Ok(Some(_)) => continue,
                _ => return true,
            }
        }
        false
    }

    #[tokio::test]
    #[ignore = "needs local dev PG/Redis (.dev/local.toml); run manually with --ignored"]
    async fn e2e_gateway_roundtrip() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let cfg_path = repo_root.join(".dev/local.toml");
        if !cfg_path.exists() {
            eprintln!("skip e2e: {} not found", cfg_path.display());
            return;
        }
        let mut cfg = match crate::config::Config::load(Some(cfg_path.as_path())) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("skip e2e: load config failed: {e}");
                return;
            }
        };
        // The test process cwd is the crate directory, so the key_dir relative path must be resolved against the repo root.
        if std::path::Path::new(&cfg.auth.key_dir).is_relative() {
            cfg.auth.key_dir = repo_root.join(&cfg.auth.key_dir).display().to_string();
        }
        let port_probe = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(e) => {
                eprintln!("skip e2e: cannot reserve port: {e}");
                return;
            }
        };
        let port = port_probe.local_addr().expect("probe addr").port();
        drop(port_probe);
        cfg.mqtt.enabled = true;
        cfg.mqtt.bind = format!("127.0.0.1:{port}");

        let state = match crate::node::build(cfg).await {
            Ok(state) => state,
            Err(e) => {
                eprintln!("skip e2e: node::build failed ({e}); start dev PG/Redis first");
                return;
            }
        };

        // Create a one-off test user + device (the refresh token is the MQTT password)
        let username = format!("mqtt-e2e-{}", lattice_core::ids::new_id().to_lowercase());
        let password_hash = crate::auth::password::hash_password("e2e-login-pw").expect("hash");
        let user = match crate::store::pg::create_user(
            &state.db,
            &username,
            &password_hash,
            Some("mqtt e2e"),
            "user",
        )
        .await
        {
            Ok(user) => user,
            Err(e) => {
                eprintln!("skip e2e: create test user failed: {e}");
                return;
            }
        };
        let (refresh_token, token_hash) = crate::auth::password::new_refresh_token();
        let device = crate::store::pg::upsert_device(
            &state.db,
            &user.id,
            &format!("fp-{}", lattice_core::ids::new_id()),
            Some("mqtt-e2e"),
            Some("linux"),
            Some(&token_hash),
        )
        .await
        .expect("upsert device");
        let topic = format!("e2e-{}", lattice_core::ids::new_id().to_lowercase());
        let filter = format!("lattice/{topic}/{}", device.id);

        let gateway_task = tokio::spawn(gateway::serve(state.clone()));
        let mut ready = false;
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(ready, "mqtt gateway did not start listening");

        // --- A wrong password must be rejected (MQTT5 0x86) ---
        {
            let mut probe = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
            gateway::write_packet(
                &mut probe,
                &mqtt_connect_packet(5, "bad-cred", &device.id, "bogus-token", 30),
            )
            .await
            .unwrap();
            let connack = read_next(&mut probe).await.expect("connack");
            assert_eq!(connack.kind, PACKET_CONNACK);
            assert_eq!(connack.body, vec![0, REASON_BAD_CREDENTIALS, 0]);
        }

        // --- MQTT5 happy path: CONNECT / SUBSCRIBE / PUBLISH(QoS1) loopback / device mismatch / rate limiting / QoS2 ---
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
        gateway::write_packet(&mut client, &mqtt_connect_packet(5, "e2e-v5", &device.id, &refresh_token, 60))
            .await
            .unwrap();
        let connack = read_next(&mut client).await.expect("connack v5");
        assert_eq!(connack.body, vec![0, 0, 0], "CONNACK success");

        gateway::write_packet(&mut client, &mqtt_subscribe_packet(5, 1, &filter, 1))
            .await
            .unwrap();
        let suback = read_next(&mut client).await.expect("suback");
        assert_eq!(suback.kind, PACKET_SUBACK);
        assert_eq!(suback.body, vec![0, 1, 0, 1], "SUBACK grants QoS1");

        // Wait for the pubsub task to really SUBSCRIBE to the Redis channel
        tokio::time::sleep(Duration::from_millis(300)).await;

        let payload = b"mqtt-e2e-hello";
        gateway::write_packet(&mut client, &mqtt_publish_packet(5, 1, &filter, payload, 11))
            .await
            .unwrap();
        let mut puback_seen = None;
        let mut echoed = None;
        for _ in 0..10 {
            let packet = read_next(&mut client).await.expect("ack/echo");
            match packet.kind {
                PACKET_PUBACK => puback_seen = Some(packet),
                PACKET_PUBLISH => echoed = Some(packet),
                other => panic!("unexpected packet {other}"),
            }
            if puback_seen.is_some() && echoed.is_some() {
                break;
            }
        }
        let puback_packet = puback_seen.expect("PUBACK");
        assert_eq!(puback_packet.body, vec![0, 11], "PUBACK success (MQTT 5 remaining length 2)");
        let echo = echoed.expect("outbound PUBLISH");
        assert_eq!(echo.flags & 0x06, 0x02, "the outbound PUBLISH uses the subscription-granted QoS1");
        let echoed_publish = parse_publish(echo.flags, &echo.body, 5).expect("outbound publish");
        assert_eq!(echoed_publish.topic, filter);
        let echoed_env = Envelope::decode_body(&echoed_publish.payload).expect("envelope decode");
        assert_eq!(echoed_env.r#type, DEFAULT_ENVELOPE_TYPE);
        assert_eq!(echoed_env.encoding, DEFAULT_ENCODING);
        assert_eq!(echoed_env.payload, payload);

        // Device segment mismatch → SUBACK 0x87
        gateway::write_packet(&mut client, &mqtt_subscribe_packet(5, 2, "lattice/release/another-device", 1))
            .await
            .unwrap();
        let denied = read_next(&mut client).await.expect("suback denied");
        assert_eq!(denied.body, vec![0, 2, 0, REASON_NOT_AUTHORIZED]);

        // Unsubscribe → UNSUBACK success, then subscribe again for the later loopback
        gateway::write_packet(&mut client, &mqtt_unsubscribe_packet(5, 3, &filter))
            .await
            .unwrap();
        let unsuback_packet = read_next(&mut client).await.expect("unsuback");
        assert_eq!(unsuback_packet.body, vec![0, 3, 0, REASON_SUCCESS]);
        gateway::write_packet(&mut client, &mqtt_subscribe_packet(5, 4, &filter, 1))
            .await
            .unwrap();
        read_next(&mut client).await.expect("resuback");
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 10 msg/s per device: wait for a clean window, then send 12 at once (avoiding the read-ACK RTT dragging the window past 1s),
        // the first 10 should succeed and the last 2 should get PUBACK 0x97.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        for i in 0..12u16 {
            gateway::write_packet(
                &mut client,
                &mqtt_publish_packet(5, 1, &filter, b"rate", 100 + i),
            )
            .await
            .unwrap();
        }
        let mut accepted = 0usize;
        let mut quota_rejected = 0usize;
        let mut acks = 0usize;
        for _ in 0..80 {
            if acks == 12 {
                break;
            }
            let packet = match read_next(&mut client).await {
                Some(packet) => packet,
                None => break,
            };
            if packet.kind != PACKET_PUBACK {
                continue; // the loopback PUBLISH of an accepted message
            }
            acks += 1;
            if packet.body.len() == 2 {
                accepted += 1;
            } else if packet.body.len() == 3 && packet.body[2] == REASON_QUOTA_EXCEEDED {
                quota_rejected += 1;
            } else {
                panic!("unexpected PUBACK body {:?}", packet.body);
            }
        }
        assert_eq!(acks, 12, "all 12 PUBLISH messages should receive a PUBACK");
        assert_eq!(accepted, DEVICE_MSG_PER_SEC as usize, "all should be accepted within 10 msg/s");
        assert_eq!(quota_rejected, 2, "the 2 above 10 msg/s should get 0x97");

        // Inbound QoS2 (MQTT 5): PUBLISH → PUBREC → PUBREL → PUBCOMP (completed in PL-11; no more disconnects)
        gateway::write_packet(&mut client, &mqtt_publish_packet(5, 2, &filter, b"qos2", 500))
            .await
            .unwrap();
        // Wait for the handshake to finish (reply PUBREL after PUBREC, then wait for PUBCOMP; loopback PUBLISH messages from the rate-limit window may interleave).
        let mut got_pubrec = false;
        let mut got_pubcomp = false;
        for _ in 0..20 {
            let packet = match read_packet(&mut client).await {
                Ok(Some(packet)) => packet,
                _ => break,
            };
            match packet.kind {
                PACKET_PUBREC => {
                    assert_eq!(parse_qos_ack(&packet.body).unwrap().0, 500);
                    got_pubrec = true;
                    gateway::write_packet(&mut client, &pubrel(5, 500, REASON_SUCCESS))
                        .await
                        .unwrap();
                }
                PACKET_PUBCOMP => {
                    assert_eq!(parse_qos_ack(&packet.body).unwrap().0, 500);
                    got_pubcomp = true;
                }
                _ => {}
            }
            if got_pubrec && got_pubcomp {
                break;
            }
        }
        assert!(got_pubrec && got_pubcomp, "MQTT5 inbound QoS2 should complete the PUBREC/PUBCOMP handshake");
        drop(client);

        // --- MQTT 3.1.1 happy path: CONNECT / PING / PUBLISH / QoS2 handshake ---
        let mut v311 = TcpStream::connect(("127.0.0.1", port)).await.expect("connect v311");
        gateway::write_packet(&mut v311, &mqtt_connect_packet(4, "e2e-v311", &username, &refresh_token, 30))
            .await
            .unwrap();
        let connack4 = read_next(&mut v311).await.expect("connack v311");
        assert_eq!(connack4.body, vec![0, 0], "3.1.1 CONNACK success");
        gateway::write_packet(&mut v311, &Packet::new(PACKET_PINGREQ, 0, Vec::new()))
            .await
            .unwrap();
        let pong = read_next(&mut v311).await.expect("pingresp");
        assert_eq!(pong.kind, PACKET_PINGRESP);
        gateway::write_packet(&mut v311, &mqtt_subscribe_packet(4, 7, &filter, 0))
            .await
            .unwrap();
        let suback4 = read_next(&mut v311).await.expect("suback v311");
        assert_eq!(suback4.body, vec![0, 7, 0]);
        // The rate-limit key is **per device** and shared across connections: wait for the previous v5 connection's rate-limit window to expire, then send 3.1.1 messages.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        gateway::write_packet(&mut v311, &mqtt_publish_packet(4, 1, &filter, b"v311", 8))
            .await
            .unwrap();
        let mut saw_ack = false;
        let mut saw_echo = false;
        for _ in 0..10 {
            match read_next(&mut v311).await {
                Some(packet) if packet.kind == PACKET_PUBACK => saw_ack = true,
                Some(packet) if packet.kind == PACKET_PUBLISH => saw_echo = true,
                Some(_) => {}
                None => break,
            }
            if saw_ack && saw_echo {
                break;
            }
        }
        assert!(saw_ack && saw_echo, "3.1.1 QoS1 inbound ACK and outbound loopback");
        gateway::write_packet(&mut v311, &mqtt_publish_packet(4, 2, &filter, b"qos2", 9))
            .await
            .unwrap();
        let mut got_pubrec = false;
        let mut got_pubcomp = false;
        for _ in 0..20 {
            let packet = match read_packet(&mut v311).await {
                Ok(Some(packet)) => packet,
                _ => break,
            };
            match packet.kind {
                PACKET_PUBREC => {
                    got_pubrec = true;
                    gateway::write_packet(&mut v311, &pubrel(4, 9, REASON_SUCCESS))
                        .await
                        .unwrap();
                }
                PACKET_PUBCOMP => got_pubcomp = true,
                _ => {}
            }
            if got_pubrec && got_pubcomp {
                break;
            }
        }
        assert!(got_pubrec && got_pubcomp, "3.1.1 inbound QoS2 should complete the PUBREC/PUBCOMP handshake");
        drop(v311);

        // --- cleanup ---
        gateway_task.abort();
        crate::routing::topic::unsubscribe(&state, &user.id, &topic).await.ok();
        crate::store::pg::set_user_status(&state.db, &user.id, "deleted").await.ok();
        crate::store::pg::revoke_device(&state.db, &device.id).await.ok();
        let _ = state.redis.del(&lattice_core::keys::ratelimit_mqtt(&device.id)).await;
        let _ = state.redis.del(&lattice_core::keys::pending_topic(&user.id, &topic)).await;
    }

    // ---------------- TLS / mTLS (PL-11) ----------------

    #[test]
    fn cert_identity_string_parsing() {
        // Recommended form: SAN URI `lattice://user/<user>/device/<device>`
        assert_eq!(
            parse_identity_value("lattice://user/user-1/device/device-1"),
            Some(CertName {
                user: Some("user-1".into()),
                device: "device-1".into()
            })
        );
        // A trailing slash is tolerated
        assert_eq!(
            parse_identity_value("lattice://user/u1/device/d1/"),
            Some(CertName { user: Some("u1".into()), device: "d1".into() })
        );
        // The `<user>@<device>` form in an email/CN
        assert_eq!(
            parse_identity_value("u1@d1"),
            Some(CertName { user: Some("u1".into()), device: "d1".into() })
        );
        // Wrong structure/charset → None (fail-closed, never guess)
        for bad in [
            "",
            "lattice://",
            "lattice://user/u1/device/",
            "lattice://user//device/d1",
            "lattice://user/u1/device/d1/extra",
            "lattice://device/d1/user/u1",
            "a@b@c",
            "u1",
            "lattice://user/u1/device/d 1",
            "lattice://user/u1/device/d1\0x",
        ] {
            assert_eq!(parse_identity_value(bad), None, "should reject {bad:?}");
        }
        // Compatibility form where the CN contains only the device id (the user is looked up in PG)
        assert_eq!(
            parse_device_only("device-1"),
            Some(CertName { user: None, device: "device-1".into() })
        );
        assert_eq!(parse_device_only("lattice://user/u1/device/d1"), None);
        assert_eq!(parse_device_only("a@b"), None);
        assert_eq!(parse_device_only("  "), None);
    }

    #[test]
    fn cert_identity_priority_uri_then_email_then_cn() {
        let names = CertNames {
            uris: vec![
                "https://example.com/not-a-lattice-identity".into(),
                "lattice://user/u1/device/d1".into(),
            ],
            emails: vec!["u2@d2".into()],
            cns: vec!["u3@d3".into()],
        };
        assert_eq!(
            resolve_cert_name(&names),
            Some(CertName { user: Some("u1".into()), device: "d1".into() })
        );
        // Fall back to email when no URI is parseable
        let names = CertNames {
            uris: vec![],
            emails: vec!["u2@d2".into()],
            cns: vec!["d3".into()],
        };
        assert_eq!(
            resolve_cert_name(&names),
            Some(CertName { user: Some("u2".into()), device: "d2".into() })
        );
        // Fall back to a device-only CN when neither is parseable
        let names = CertNames { uris: vec![], emails: vec![], cns: vec!["d3".into()] };
        assert_eq!(
            resolve_cert_name(&names),
            Some(CertName { user: None, device: "d3".into() })
        );
        assert_eq!(resolve_cert_name(&CertNames::default()), None);
    }

    #[test]
    fn der_parser_rejects_malformed_input_without_panic() {
        assert!(extract_cert_names(&[]).is_none());
        assert!(extract_cert_names(&[0x30]).is_none());
        assert!(extract_cert_names(&[0x30, 0x03, 0x02, 0x01, 0x00]).is_none());
        // The declared length exceeds the actual bytes
        assert!(extract_cert_names(&[0x30, 0x7f, 0x01, 0x02]).is_none());
        // DER OID constants for 2.5.4.3 / 2.5.29.17 (guarding against typos silently breaking SAN/CN parsing)
        assert_eq!(OID_COMMON_NAME, &[0x55, 0x04, 0x03]);
        assert_eq!(OID_SUBJECT_ALT_NAME, &[0x55, 0x1D, 0x11]);
    }

    #[test]
    fn connect_username_must_match_certificate_identity() {
        let now = chrono::Utc::now();
        let user = crate::store::pg::User {
            id: "user-1".into(),
            username: "alice".into(),
            password_hash: String::new(),
            display_name: None,
            avatar: None,
            status: "active".into(),
            role: "user".into(),
            capabilities: serde_json::json!({}),
            quota: serde_json::json!({}),
            created_at: now,
            updated_at: now,
        };
        let device = crate::store::pg::Device {
            id: "device-1".into(),
            user_id: "user-1".into(),
            name: None,
            platform: None,
            token_hash: None,
            fingerprint: None,
            last_seen: None,
            revoked_at: None,
        };
        for ok in ["device-1", "user-1", "alice", "alice@device-1", "user-1@device-1"] {
            assert!(connect_username_matches(ok, &user, &device), "should accept {ok}");
        }
        for bad in [
            "",
            "device-2",
            "bob",
            "bob@device-1",
            "alice@device-2",
            "device-1@alice",
        ] {
            assert!(
                !connect_username_matches(bad, &user, &device),
                "should reject {bad:?}"
            );
        }
    }

    // ---- rcgen generates CA/server/client certificates in memory for a real TLS handshake (no external openssl) ----

    struct TestTls {
        ca: rcgen::Certificate,
        ca_key: rcgen::KeyPair,
    }

    impl TestTls {
        fn new() -> Self {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "lattice mqtt test ca");
            let ca_key = rcgen::KeyPair::generate().unwrap();
            let ca = params.self_signed(&ca_key).unwrap();
            Self { ca, ca_key }
        }

        fn ca_der(&self) -> CertificateDer<'static> {
            self.ca.der().clone()
        }

        /// Issue one certificate: the SAN is supplied by the caller (URI/email/device-only CN etc.).
        fn issue(
            &self,
            sans: Vec<rcgen::SanType>,
            cn: &str,
            eku: rcgen::ExtendedKeyUsagePurpose,
            validity: Option<((i32, u8, u8), (i32, u8, u8))>,
        ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.subject_alt_names = sans;
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, cn);
            params.extended_key_usages.push(eku);
            if let Some((not_before, not_after)) = validity {
                params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
                params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
            }
            let cert = params.signed_by(&key, &self.ca, &self.ca_key).unwrap();
            let key_der = PrivateKeyDer::Pkcs8(
                tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
            );
            (cert.der().clone(), key_der)
        }

        /// Server certificate (SAN=localhost + 127.0.0.1; EKU=serverAuth).
        fn server_identity(&self) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
            let keys = rcgen::KeyPair::generate().unwrap();
            let mut params =
                rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                    .unwrap();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "localhost");
            params
                .extended_key_usages
                .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
            let cert = params.signed_by(&keys, &self.ca, &self.ca_key).unwrap();
            let key_der = PrivateKeyDer::Pkcs8(
                tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(keys.serialize_der()),
            );
            (cert.der().clone(), key_der)
        }

        fn uri(value: &str) -> rcgen::SanType {
            rcgen::SanType::URI(value.try_into().unwrap())
        }

        fn email(value: &str) -> rcgen::SanType {
            rcgen::SanType::Rfc822Name(value.try_into().unwrap())
        }
    }

    fn test_client_config(
        pki: &TestTls,
        identity: Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>,
    ) -> Arc<tokio_rustls::rustls::ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(pki.ca_der()).unwrap();
        let builder = tokio_rustls::rustls::ClientConfig::builder().with_root_certificates(roots);
        let mut cfg = match identity {
            Some((cert, key)) => builder.with_client_auth_cert(vec![cert], key).unwrap(),
            None => builder.with_no_client_auth(),
        };
        cfg.alpn_protocols = vec![TLS_ALPN.to_vec()];
        Arc::new(cfg)
    }

    /// Run one real TLS handshake over an in-memory duplex; returns the server-side result (the client result is ignored).
    async fn tls_handshake(
        server_cfg: Arc<ServerConfig>,
        client_cfg: Arc<tokio_rustls::rustls::ClientConfig>,
    ) -> io::Result<tokio_rustls::server::TlsStream<tokio::io::DuplexStream>> {
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let acceptor = TlsAcceptor::from(server_cfg);
        let connector = tokio_rustls::TlsConnector::from(client_cfg);
        let server_name =
            tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let (server_res, _client_res) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect(server_name, client_io)
        );
        server_res
    }

    #[test]
    fn tls_server_config_is_fail_closed_and_sets_alpn() {
        let pki = TestTls::new();
        let (cert, key) = pki.server_identity();
        // require=true without client_ca → fail-closed rejection (never "configure mTLS but skip validation")
        let err = build_tls_server_config(vec![cert.clone()], key, vec![], true).unwrap_err();
        assert!(err.to_string().contains("client_ca"), "{err}");
        // require=false without client_ca → plain TLS (no client certificate requested)
        let (cert2, key2) = pki.server_identity();
        let cfg = build_tls_server_config(vec![cert2], key2, vec![], false).unwrap();
        assert_eq!(cfg.alpn_protocols, vec![TLS_ALPN.to_vec()], "ALPN must be fixed to mqtt");
        // require=true + a trust anchor → builds successfully
        let (cert3, key3) = pki.server_identity();
        let cfg = build_tls_server_config(vec![cert3], key3, vec![pki.ca_der()], true).unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"mqtt".to_vec()]);
    }

    #[test]
    fn load_tls_server_config_rejects_empty_or_missing_files() {
        // Empty cert/key: returns an error (WARN only, no listener), never panics
        let cfg = crate::config::MqttCfg { tls_enabled: true, ..Default::default() };
        let err = load_tls_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("mqtt.tls_cert is empty"), "{err}");
        // Path does not exist: the error message carries only the path, no certificate/private key content
        let cfg = crate::config::MqttCfg {
            tls_enabled: true,
            tls_cert: "definitely-missing-cert.pem".into(),
            tls_key: "definitely-missing-key.pem".into(),
            ..Default::default()
        };
        let err = load_tls_server_config(&cfg).unwrap_err();
        assert!(err.to_string().contains("tls cert"), "{err}");
        assert!(!err.to_string().contains("BEGIN"), "the error message must not contain PEM content");
    }

    #[tokio::test]
    async fn tls_mtls_handshake_maps_certificate_identity() {
        let pki = TestTls::new();
        let (cert, key) = pki.server_identity();
        let server_cfg = build_tls_server_config(vec![cert], key, vec![pki.ca_der()], true).unwrap();
        let identity = pki.issue(
            vec![TestTls::uri("lattice://user/user-1/device/device-1")],
            "device-1",
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            None,
        );
        let client_cfg = test_client_config(&pki, Some(identity));
        let stream = tls_handshake(server_cfg, client_cfg)
            .await
            .expect("a valid certificate should complete the mTLS handshake");
        assert_eq!(
            stream.get_ref().1.alpn_protocol(),
            Some(TLS_ALPN),
            "after the handshake ALPN should be mqtt"
        );
        let leaf = stream
            .get_ref()
            .1
            .peer_certificates()
            .expect("client certificate")
            .first()
            .expect("leaf certificate")
            .clone();
        assert_eq!(
            parse_client_identity(leaf.as_ref()),
            TlsClientIdentity::Parsed(CertName {
                user: Some("user-1".into()),
                device: "device-1".into()
            }),
            "the SAN URI should map to user/device"
        );
    }

    #[tokio::test]
    async fn tls_client_certificate_rejections_are_classified() {
        let pki = TestTls::new();
        // 1) require=true + the client presents no certificate → NoCertificatesPresented → no_cert
        {
            let (cert, key) = pki.server_identity();
            let server_cfg =
                build_tls_server_config(vec![cert], key, vec![pki.ca_der()], true).unwrap();
            let err = tls_handshake(server_cfg, test_client_config(&pki, None))
                .await
                .expect_err("with require=true a missing client certificate must be rejected");
            assert_eq!(
                classify_tls_handshake_error(&err),
                Some(TlsAuthFailure::NoCert),
                "a missing certificate should be classified no_cert (err={err})"
            );
        }
        // 2) A client certificate signed by the wrong CA → InvalidCertificate(UnknownIssuer) → bad_cert
        {
            let (cert, key) = pki.server_identity();
            let server_cfg =
                build_tls_server_config(vec![cert], key, vec![pki.ca_der()], true).unwrap();
            let other_ca = TestTls::new();
            let identity = other_ca.issue(
                vec![TestTls::uri("lattice://user/u/device/d")],
                "d",
                rcgen::ExtendedKeyUsagePurpose::ClientAuth,
                None,
            );
            let client_cfg = test_client_config(&pki, Some(identity));
            let err = tls_handshake(server_cfg, client_cfg)
                .await
                .expect_err("a client certificate from the wrong CA must be rejected");
            assert_eq!(
                classify_tls_handshake_error(&err),
                Some(TlsAuthFailure::BadCert),
                "the wrong CA should be classified bad_cert (err={err})"
            );
        }
        // 3) An expired client certificate (same CA) → InvalidCertificate(CertificateExpired) → bad_cert
        {
            let (cert, key) = pki.server_identity();
            let server_cfg =
                build_tls_server_config(vec![cert], key, vec![pki.ca_der()], true).unwrap();
            let identity = pki.issue(
                vec![TestTls::uri("lattice://user/u/device/d")],
                "d",
                rcgen::ExtendedKeyUsagePurpose::ClientAuth,
                Some(((2020, 1, 1), (2021, 1, 1))),
            );
            let client_cfg = test_client_config(&pki, Some(identity));
            let err = tls_handshake(server_cfg, client_cfg)
                .await
                .expect_err("an expired client certificate must be rejected");
            assert_eq!(
                classify_tls_handshake_error(&err),
                Some(TlsAuthFailure::BadCert),
                "expiry should be classified bad_cert (err={err})"
            );
        }
        // 4) require=false + the client presents no certificate → handshake succeeds (falling back to PSK/JWT semantics)
        {
            let (cert, key) = pki.server_identity();
            let server_cfg =
                build_tls_server_config(vec![cert], key, vec![pki.ca_der()], false).unwrap();
            let stream = tls_handshake(server_cfg, test_client_config(&pki, None))
                .await
                .expect("with require=false a missing certificate should be allowed to handshake");
            assert!(
                stream.get_ref().1.peer_certificates().is_none(),
                "peer_certificates should be None when there is no client certificate"
            );
        }
        // 5) require=false but a wrong-CA certificate is presented → still rejected (allow_unauthenticated must not be abused to downgrade)
        {
            let (cert, key) = pki.server_identity();
            let server_cfg =
                build_tls_server_config(vec![cert], key, vec![pki.ca_der()], false).unwrap();
            let other_ca = TestTls::new();
            let identity = other_ca.issue(
                vec![TestTls::uri("lattice://user/u/device/d")],
                "d",
                rcgen::ExtendedKeyUsagePurpose::ClientAuth,
                None,
            );
            let client_cfg = test_client_config(&pki, Some(identity));
            let err = tls_handshake(server_cfg, client_cfg)
                .await
                .expect_err("with require=false a presented bad certificate must still be rejected");
            assert_eq!(
                classify_tls_handshake_error(&err),
                Some(TlsAuthFailure::BadCert)
            );
        }
    }

    #[tokio::test]
    async fn tls_email_and_cn_identity_fallbacks() {
        let pki = TestTls::new();
        // email SAN `<user>@<device>` (the user segment is a username; PG allows a username or an id)
        {
            let (cert, key) = pki.server_identity();
            let server_cfg =
                build_tls_server_config(vec![cert], key, vec![pki.ca_der()], true).unwrap();
            let identity = pki.issue(
                vec![TestTls::email("alice@device-9")],
                "alice",
                rcgen::ExtendedKeyUsagePurpose::ClientAuth,
                None,
            );
            let stream = tls_handshake(server_cfg, test_client_config(&pki, Some(identity)))
                .await
                .expect("an email SAN should complete the handshake");
            let leaf = stream
                .get_ref()
                .1
                .peer_certificates()
                .unwrap()
                .first()
                .unwrap()
                .clone();
            assert_eq!(
                parse_client_identity(leaf.as_ref()),
                TlsClientIdentity::Parsed(CertName {
                    user: Some("alice".into()),
                    device: "device-9".into()
                })
            );
        }
        // No SAN, CN contains only the device id → device-only (the user is looked up in PG)
        {
            let (cert, key) = pki.server_identity();
            let server_cfg =
                build_tls_server_config(vec![cert], key, vec![pki.ca_der()], true).unwrap();
            let identity = pki.issue(
                vec![],
                "device-7",
                rcgen::ExtendedKeyUsagePurpose::ClientAuth,
                None,
            );
            let stream = tls_handshake(server_cfg, test_client_config(&pki, Some(identity)))
                .await
                .expect("a device-only CN should complete the handshake");
            let leaf = stream
                .get_ref()
                .1
                .peer_certificates()
                .unwrap()
                .first()
                .unwrap()
                .clone();
            assert_eq!(
                parse_client_identity(leaf.as_ref()),
                TlsClientIdentity::Parsed(CertName { user: None, device: "device-7".into() })
            );
        }
        // SAN present but not a lattice identity, and the CN is not an id either → Unparsable (fail-closed)
        {
            let (cert, key) = pki.server_identity();
            let server_cfg =
                build_tls_server_config(vec![cert], key, vec![pki.ca_der()], true).unwrap();
            let identity = pki.issue(
                vec![TestTls::uri("spiffe://example.com/workload")],
                "some workload name",
                rcgen::ExtendedKeyUsagePurpose::ClientAuth,
                None,
            );
            let stream = tls_handshake(server_cfg, test_client_config(&pki, Some(identity)))
                .await
                .expect("a valid certificate chain is enough to handshake");
            let leaf = stream
                .get_ref()
                .1
                .peer_certificates()
                .unwrap()
                .first()
                .unwrap()
                .clone();
            assert_eq!(
                parse_client_identity(leaf.as_ref()),
                TlsClientIdentity::Unparsable
            );
        }
    }
}
