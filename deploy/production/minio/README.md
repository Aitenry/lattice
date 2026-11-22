# MinIO production HA (4 nodes × 4 drives, EC 12+4)

> **Template**, a distributed cluster has never been brought up on this machine. Design basis: the design document (outside this repository) §17.13
> (4 nodes × 4 drives = 16 drives, EC 12+4, tolerates any 4 drive failures ≈ 1 entire node).
> Offline check: `python scripts/ha-manifest-check.py`.

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | 4 nodes × 4 drives startup template; `MINIO_ERASURE_SET_DRIVE_COUNT=16` pins EC 12+4 |
| `bucket-setup.sh` | Create the 4 buckets + versioning + object lock (cold) + lifecycle example + dedicated IAM user + replication notes |
| `README.md` | This file: capacity/fault tolerance, mapping to the node `[s3]` section, failure/recovery, boundaries |

## 1. Deployment notes

1. 4 hosts, each with 4 **independent data drives** (XFS/ext4 both fine; MinIO provides redundancy itself, so
   **do not add RAID5/6 on top** — erasure coding plus RAID wastes capacity on double redundancy and amplifies
   write amplification). Mount points such as `/data1..4`.
2. Once all 4 hosts are up, create the buckets (**before lattice-node first starts**):
   ```sh
   export MINIO_ENDPOINT=http://minio.lattice.internal:9000
   export MINIO_ROOT_USER=... MINIO_ROOT_PASSWORD=...
   export MINIO_APP_ACCESS_KEY=lattice_app MINIO_APP_SECRET_KEY=...
   ./bucket-setup.sh
   ```
3. LB/entry: S3 API 9000 / Console 9001 are internal only; TLS is terminated by the LB externally
   (`[s3] public_endpoint=https://s3.example.com` for browsers/clients; signing covers Host only).
4. Verify the EC layout: `mc admin info <alias>` should show 4 nodes with 4 drives each; check self-healing
   with `mc admin heal -r <alias>`.
5. Capacity planning: 16 drives × per-drive capacity × **75%** = usable capacity (12/16 for EC 12+4); then keep
   10–20% headroom against filling up (a full cluster fails node uploads/recording, but the messaging path does
   not depend on S3 — only large files/plugins/recording are affected).

## 2. Mapping to node configuration (`crates/lattice-node/src/config.rs`)

| Node config | Production value | Notes |
|---|---|---|
| `[s3] endpoint` | `http://minio-lattice.lattice.internal:9000` | **Must be http://**: the bucket-create/direct-write path in `store/s3.rs` supports http only (TLS is terminated at the LB; `https` fails explicitly) |
| `[s3] public_endpoint` | `https://s3.example.com` | scheme+Host of presigned URLs; must be reachable by clients, otherwise 302 downloads/uploads fail |
| `[s3] region` | `us-east-1` | MinIO default region; used in the signature scope |
| `[s3] access_key` / `secret_key` | `lattice_app` / Secret | The **dedicated IAM user** created by bucket-setup.sh, never root |
| `[s3] bucket_large` | `lattice-large` | Chunked large files (`{yyyy}/{mm}/{dd}/{msg_id}/cN.bin`) |
| `[s3] bucket_media` | `lattice-media` | Media recording/upload |
| `[s3] bucket_cold` | `lattice-cold` | Cold data/backups/WAL archive for `wal-gateway.sh` (`wal/pg/lattice-pg/wal/`) |
| `[s3] bucket_plugins` | `lattice-plugins` | Plugin install packages/source packages |
| `[s3] presign_ttl` | 900 | Design §17.13 |

> **Bucket creation order matters**: the node's `ensure_buckets()` only does HEAD→PUT on plain buckets
> (no versioning/no lock). Versioning and object lock can only be enabled at bucket creation → production
> must run `bucket-setup.sh` first, then start the nodes; the node skips buckets that answer HEAD.
> (Nodes creating their own buckets in the dev compose is single-host convenience, not suitable for production.)

## 3. Bucket policy: versioning / object lock / lifecycle / replication

| Capability | What this skeleton does | Notes |
|---|---|---|
| Versioning | Enabled on all 4 buckets (`mc version enable`) | Protects against accidental deletion/overwrite; the node's `delete_object` produces delete markers, as expected |
| Object lock | **Only `lattice-cold`, at bucket creation** (`mc mb --with-lock`) | Cannot be enabled afterwards; this skeleton **does not apply** a default retention policy (node writes carry no object-lock header, and a forced default retention would lock the cleanup path). For compliance scenarios enable `mc retention set --default GOVERNANCE 30d` and validate the node delete/cold-archive paths |
| Lifecycle | Example: `lattice-large/uploads/` expires after 7 days | Business data deletion goes through the node purge API, never ILM (to avoid accidental deletion); cold-data tiering is defined separately per design D7 |
| Cross-site replication | Both methods documented at the end of `bucket-setup.sh` (`mc replicate add` / `mc admin replicate add`) | **Unvalidated**; asynchronous replication → site RPO = replication lag; locks/retention are not replicated automatically |

### Role of replication/disaster recovery
- MinIO objects are the **only source** for PG references (`payload_ref`/`object_key`); losing objects means messages/plugins are unavailable;
- Minimum production requirement: EC 12+4 self-healing (≥99.9999% durability design target) + **off-site replication or snapshot backups** (optional per design §11);
- Recovery order (② §7.5): **PG first → reconciliation → Redis → NATS → MinIO**; after MinIO recovers, run the
  object-existence check in `scripts/reconcile.py` ([C] hub object existence) before restoring traffic.

## 4. Failure behavior

| Event | Expected behavior | Verification status |
|---|---|---|
| 1 drive fails | Reads and writes continue (EC 12+4 tolerates 4 drives); `mc admin heal` rebuilds automatically | Unvalidated |
| 1 entire node offline (4 drives) | Reads and writes still work (worst case 4 drives missing = exactly at the fault-tolerance boundary); load/network rises on the online nodes | Unvalidated |
| 2 nodes offline (8 drives > 4) | Some object reads fail → recover from off-site replicas/backups | Unvalidated |
| Disk full | Uploads/recording fail (5xx or degraded on the node side); the messaging path is unaffected | Unvalidated |
| Rolling upgrade | `mc admin update`/image swap node by node; wait for each node to return and finish healing before the next | Unvalidated |

Recovery command reference (the single-host dev drill covered only the "data directory is recoverable" step):
```sh
# Trigger healing after a node/drive recovers and watch it
mc admin heal -r lattice-s3
mc admin info lattice-s3        # 4 nodes online, 4 drives each, EC 12+4
# Verify object existence (item [C] of the reconciliation script)
python scripts/reconcile.py --help   # or follow restore-runbook.md §4
```

## 5. Rollback / failback

| Scenario | Action |
|---|---|
| Wrong bucket/policy | Bucket names cannot be changed, but data can be migrated: create the correct bucket → `mc mirror` → update `[s3] bucket_*` → restart the nodes; keep the old bucket for observation, then delete |
| Object lock/retention locked objects by mistake | GOVERNANCE mode can be cleared with `mc retention clear --bypass` (requires root); COMPLIANCE cannot be cleared → wait for retention to expire (which is why this skeleton does not apply object-level locks by default) |
| Abnormal MinIO version upgrade | Roll back the image tag (storage format backward compatibility per official release notes); **do not** downgrade the binary across major versions directly — check the compatibility matrix first |
| Recovery after node/drive failure | A recovered node rejoins the distributed cluster and triggers healing automatically (**failback**: no manual switch action needed); afterwards confirm 4 nodes online with 4 drives each via `mc admin info`; if a drive was replaced, monitor the reduced replica count during healing |
| Remove this skeleton | Delete `deploy/production/minio/` (not part of runtime); roll back an already-deployed cluster per the two rows above |

## 6. Unvalidated boundaries

- **No distributed EC cluster has ever been brought up**: 4 nodes/16 drives/EC 12+4, healing, cross-node networking,
  capacity and write amplification are all unmeasured; the only existing drill covers single-host single-drive
  data-directory recovery (`perf/reports/recovery-minio-20261121.txt`, 28 assertions, 3.12s);
- **TLS not enabled**: nodes support http endpoints only, and the LB-TLS-termination path has not been integration-tested;
  whether the presigned Host is preserved by the LB when `public_endpoint` is https (the Host header must be preserved) is unvalidated;
- **Cross-site replication unvalidated**: `mc replicate add`/`mc admin replicate add` have never run against two real sites;
- **Object lock and the node delete path have not been integration-tested**: no object-level retention is applied by default,
  to avoid locking the cleanup path;
- **Large objects/large object counts** (GB-scale, millions of objects) and `mc admin heal` duration are unvalidated.
