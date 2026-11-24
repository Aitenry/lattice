# MinIO high availability (four nodes, sixteen drives, erasure coding 12+4)

> **Status: template only.** No four-node cluster has been brought up; erasure coding, healing, and capacity
> figures are unmeasured. `docker-compose.yml` is a single-host topology reference; production uses four hosts.

## Files

[`docker-compose.yml`](docker-compose.yml) starts four nodes with four drives each and pins
`MINIO_ERASURE_SET_DRIVE_COUNT=16`; [`bucket-setup.sh`](bucket-setup.sh) creates buckets, versioning, object lock, IAM, and replication notes.

## Deployment

1. Four hosts, four independent data drives each (XFS or ext4), mounted at `/data1` through `/data4`. MinIO is
   the redundancy layer, so do not place RAID 5/6 underneath: it doubles redundancy overhead and amplifies writes.
2. Bring up all four nodes, then create the buckets **before lattice-node starts**:
   ```sh
   export MINIO_ENDPOINT=http://minio.lattice.internal:9000
   export MINIO_ROOT_USER=... MINIO_ROOT_PASSWORD=...
   export MINIO_APP_ACCESS_KEY=lattice_app MINIO_APP_SECRET_KEY=...
   ./bucket-setup.sh
   ```
3. Keep the S3 API (9000) and console (9001) internal; terminate TLS at the LB and set
   `[s3] public_endpoint=https://s3.example.com`. The LB must preserve the Host header because the presigned
   URL signature covers it.
4. Verify `mc admin info <alias>` shows four nodes with four drives each and erasure coding 12+4, then run
   `mc admin heal -r <alias>`.
5. Capacity is 16 drives x per-drive capacity x 75%, plus 10-20% headroom; a full cluster fails uploads and recordings while messaging continues.

## Node configuration mapping

Configuration keys come from [`config.rs`](../../../crates/lattice-node/src/config.rs); endpoint handling is in [`store/s3.rs`](../../../crates/lattice-node/src/store/s3.rs).

| Node configuration | Production value | Notes |
|---|---|---|
| `[s3] endpoint` | `http://minio-lattice.lattice.internal:9000` | Must be `http://`; the direct-write path rejects `https`, TLS terminates at the LB |
| `[s3] public_endpoint` | `https://s3.example.com` | Scheme and Host of presigned URLs; clients must reach it |
| `[s3] region` | `us-east-1` | MinIO default; used in the signature scope |
| `[s3] access_key` / `secret_key` | `lattice_app` / Secret | Dedicated IAM user created by `bucket-setup.sh`; never root |
| `[s3] bucket_large` / `bucket_media` | `lattice-large` / `lattice-media` | Chunked large files (`{yyyy}/{mm}/{dd}/{msg_id}/cN.bin`) and media recordings |
| `[s3] bucket_cold` / `bucket_plugins` | `lattice-cold` / `lattice-plugins` | Cold data, backups, and the WAL archive under `wal/pg/lattice-pg/`; plugin packages |
| `[s3] presign_ttl` | `900` | Presigned link lifetime in seconds; tune to the client download window |

Bucket order matters: `ensure_buckets()` only does HEAD then PUT on plain buckets (no versioning, no lock), and
lock is creation-time only, so run `bucket-setup.sh` first; the node then skips existing buckets.

## Bucket policy

| Capability | Behavior | Notes |
|---|---|---|
| Versioning | All four buckets | Protects against accidental overwrite and deletion; node deletes leave delete markers |
| Object lock | `lattice-cold` only, at creation | No default retention, because a forced lock would also block cleanup. For compliance set `mc retention set --default GOVERNANCE 30d` and validate the delete and cold-archive paths |
| Lifecycle | `lattice-large/uploads/` expires after 7 days | Business data is deleted through the node purge API, never by ILM |
| Cross-site replication | `mc replicate add` or `mc admin replicate add` (see `bucket-setup.sh`) | Asynchronous, so cross-site RPO equals replication lag; locks are not replicated automatically |

MinIO holds the only copy of objects referenced from PostgreSQL (`payload_ref`, `object_key`). After a MinIO
recovery, recover PostgreSQL first, then reconcile, then Redis, then NATS; before restoring traffic, sample
referenced keys and confirm they resolve with `mc stat <alias>/<bucket>/<key>`.

## Failure behavior

| Event | Expected behavior | Verified |
|---|---|---|
| One drive or one node offline | Reads and writes continue at the fault-tolerance boundary; `mc admin heal` repairs, and load rises on the remaining nodes | No |
| Two nodes offline | Eight missing drives exceeds parity; some reads fail and need off-site copies | No |
| Disk full | Uploads and recordings fail while the messaging path continues | No |
| Rolling upgrade | Update one node at a time and wait for healing before moving to the next | No |

## Recovery and rollback

```sh
mc admin heal -r lattice-s3
mc admin info lattice-s3            # four nodes online, four drives each, erasure coding 12+4
mc stat lattice-s3/lattice-large/<key>
```

| Scenario | Action |
|---|---|
| Wrong bucket or policy | Create the correct bucket, `mc mirror` the data, update `[s3] bucket_*`, restart the nodes, and keep the old bucket until verified |
| Retention locked objects | Clear GOVERNANCE with `mc retention clear --bypass` as root; COMPLIANCE cannot be cleared |
| Failed upgrade | Roll back the image tag following the release compatibility notes; never downgrade across major versions |
| Node or drive recovery | The node rejoins and heals automatically; confirm four nodes with four drives via `mc admin info` |

## Unvalidated boundaries

- No distributed cluster has run: erasure coding 12+4, healing, cross-node networking, write amplification, and
  capacity are unmeasured.
- TLS termination at the LB and Host-header preservation for presigned URLs are untested.
- Cross-site replication has never run between two real sites; object lock plus the node delete path are not
  integration-tested, and no object-level retention is applied by default to avoid locking cleanup.
- Large objects, millions of objects, and `mc admin heal` duration are untested.
