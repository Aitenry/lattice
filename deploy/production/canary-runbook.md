# Canary release runbook — template, not validated on a real cluster

> **Status: an executable template + offline chart render assertions, not a rehearsed production process.**
> For the chart-side implementation see `deploy/helm/lattice/README.md` §10; the templates live in
> `deploy/helm/lattice/templates/canary.yaml`. This machine has **no K8s/ingress-nginx**, so "weights
> really split traffic proportionally", "header matching", and "/v1 prefix precedence" only have render
> assertions (`python scripts/helm-canary-validate.py`) — **no packet capture/counting on a real
> controller**. Record data per the §9 acceptance checklist the first time you run a canary in staging,
> and do not claim to production that canary capability is accepted until it has passed end to end.

## 1. Prerequisites (all required)

| Condition | Check command/notes |
|---|---|
| The cluster has ingress-nginx with canary annotation support | class = nginx in `kubectl -n <ns> get ingress`; the controller version supports `canary-weight`/`canary-by-header` (any ingress-nginx ≥ 0.22 does) |
| The chart is installed with `ingress.enabled=true` | Otherwise the chart deploys only the canary workload with no weighted entry point (weights would need external LB/mesh configuration) |
| The canary image is pushed to a registry reachable from the cluster | `--set canary.image.tag=<new tag>`; leave `repository` empty = same repository as stable |
| Staging has been rehearsed at least once | Recorded under `perf/reports/`; focus on validating the weight ratio and rollback duration |
| Observability is ready | stable/canary error rate, P99, WS disconnects, and `lattice_backpressure_dropped_total` are comparable; see §6 |
| The rollback path has been rehearsed | Run `canary.weight=0` / `canary.enabled=false` once each (in staging) and record the duration |
| Traffic to nodes from the external LB is out of scope for this runbook | In the production topology, traffic from Nginx/Envoy directly to nodes does not pass through the chart Ingress (`deploy/production/README.md` §1); configure its canary weights with the LB's own mechanism |

## 2. Canary target and traffic path (in one sentence)

- The chart's canary = two Deployments for the **node backend**: `<release>-node` (stable) +
  `<release>-node-canary` (same PodSpec, different image/tag); the stable Service/selector stay unchanged,
  and canary gets its own Service;
- With `ingress.enabled=true` an additional pair of Ingresses is rendered: `<release>-node-api` (`/v1` →
  stable) and `<release>-node-api-canary` (same host/path with `canary: "true"` + `canary-weight`);
- Weights apply only to **`/v1` HTTP/WS/SSE passing through ingress-nginx**; console static assets still go
  through web, and MQTT (1883/8883), QUIC (UDP 4433), and gRPC (9090 internal) are **not** part of this
  canary channel;
- For the detailed tradeoffs and resource list see `deploy/helm/lattice/README.md` §10.1.

## 3. Pre-release checklist

1. `helm diff upgrade` (or `helm template` + `kubectl diff -f -`) to confirm that **only** canary resources
   are added and stable's Deployment/Service/HPA/PDB/ConfigMap have no unexpected changes;
2. Confirm the change type of this canary: **image/code** changes can be canaried; **database migrations**
   must be two-phase expand/contract (migrations only move forward, see chart README §8), otherwise
   rolling back the image fails due to missing/extra columns;
3. Confirm no ConfigMap is changed at the same time (configuration is a release-level input shared by
   stable and canary; a configuration change rolls both sides);
4. Confirm the canary image's `/v1/health`, `/v1/ready`, and protocol compatibility (clients tolerate
   unknown error codes, design §17.10).

## 4. Phased traffic ramp-up

**Observe for at least 10 minutes** between steps; any degradation at any step → roll back per §7
immediately, without the "let's push one more step and see" mindset.

```bash
# Step 0: deploy canary at 0% traffic (pre-check); stable stays at 100%
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values \
  --set canary.enabled=true --set canary.weight=0 --set canary.image.tag=<new tag>
kubectl -n lattice rollout status deploy/<release>-node-canary
kubectl -n lattice get pods -l lattice.io/track=canary -o wide
kubectl -n lattice logs deploy/<release>-node-canary --tail=200

# Step 1: 5%
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values --set canary.weight=5
# Step 2: 25%
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values --set canary.weight=25
# Step 3: 100% (keep the canary resources for now; observe 30–60min)
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values --set canary.weight=100
```

**Must-check per step** (look at stable and canary separately, never only at aggregates):

| Metric | Criterion | Collection |
|---|---|---|
| HTTP 5xx rate | canary should not exceed the stable baseline (suggest < 0.1%) | Node metrics/Prometheus (`/metrics`) or ingress-nginx access log counted per upstream |
| P99 latency | canary ≤ stable × 1.2 | Same as above; for WS/SSE also look at connection lifetime |
| WS disconnects/reconnects | No abnormal increase (client reconnects are a normal fallback, but should not increase during canary) | Node `lattice_ws_*` metrics / client reports |
| Backpressure drops | `lattice_backpressure_dropped_total` does not grow | `/metrics` |
| ready/health | canary Pod `readinessProbe` does not flap | `kubectl get pods`, `/v1/ready` |
| Logs | No new panic/ERROR patterns | `kubectl logs` |

Confirm the traffic ratio: count per upstream in the ingress-nginx access log (or controller metrics); the
5%/25% steps should roughly match `canary.weight` (jitter at low traffic is normal — use a 10min window).

## 5. Internal-account pre-validation (independent of weights)

```bash
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values \
  --set canary.byHeader=x-lattice-canary --set canary.byHeaderValue=always
curl -s -H 'x-lattice-canary: always' https://<ingress-host>/v1/health
kubectl -n lattice describe ingress <release>-node-api-canary   # confirm the canary-by-header annotation
```

> Requests with an exact header match **always** go to canary (regardless of weight), which is useful for
> walking critical paths (login, WS send/receive, SSE, plugin package upload) with a test account/device
> first. Remember to clear byHeader or switch back to weight-only afterwards.

## 6. Observation commands

```bash
# Canary-specific metrics (requires metrics.serviceMonitor.enabled; use port-forward without a ServiceMonitor)
kubectl -n lattice port-forward svc/<release>-node-canary 9101:9100
curl -s localhost:9101/metrics | grep -E 'lattice_(http|ws|backpressure|mqtt)'

# Confirm which version is serving: Pod image tag + track label
kubectl -n lattice get pods -l lattice.io/track=canary \
  -o custom-columns=NAME:.metadata.name,IMAGE:.spec.containers[0].image,READY:.status.containerStatuses[0].ready
# Canary Ingress annotations (are weight/header the expected values)
kubectl -n lattice get ingress <release>-node-api-canary -o jsonpath='{.metadata.annotations}'
```

## 7. Rollback (decision matrix)

First determine whether the degradation comes from the **canary version** or from **release-level
configuration/infrastructure**:

| Symptom | Action | Command |
|---|---|---|
| canary 5xx/latency/crash, but stable is normal | Zero the weight (keep the replicas for troubleshooting) | `--set canary.weight=0` |
| Problems persist after zeroing the weight (possibly configuration/migration/dependency) | Remove canary and roll back the entire release | `--set canary.enabled=false` + `helm rollback <release> <revision>` |
| A database migration has run and is incompatible with the old version | Cannot be solved by rolling back the image; fix forward with expand/contract | See `deploy/production/patroni/failover-runbook.md` / chart README §8 |
| Simply no longer want to continue the canary | Disable canary, stable at 100% | `--set canary.enabled=false` |

```bash
# a) Fastest mitigation: 0% traffic, keep the canary replicas
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values --set canary.weight=0

# b) Remove the canary resources (back to pure stable; /v1 is served again by the web nginx reverse proxy)
helm upgrade <release> deploy/helm/lattice -n lattice --reuse-values --set canary.enabled=false

# c) Roll the entire release back to the previous revision (including the stable image tag/configuration)
helm history <release> -n lattice
helm rollback <release> <previous revision> -n lattice
```

After rollback you **must**: confirm all `<release>-node` Pods are ready, `/v1/ready` returns 200,
WebSocket send/receive works, `python scripts/reconcile.py` reports no FAIL (messaging pending state
reconciled against PG), and record the timeline in the §9 log.

## 8. Canary passed → full rollout

1. Observe `weight=100` for 30–60min with no anomalies;
2. Promote the new version to stable: `--set image.tag=<new tag>` + `--set canary.enabled=false` (in the
   same `helm upgrade`); stable rolls through `RollingUpdate maxUnavailable=0`;
3. After confirming stable is fully rolled out, delete the canary's historical revision/resources (keeping
   the record in `helm history` is enough);
4. If the new version needs to be reverted: `helm rollback` to the revision before stable changed its tag
   (database migrations are still governed by §7).

## 9. Canary acceptance record template (mandatory the first time in staging)

```
Time: <start> → <end> (total duration)
Target version: node <old tag> → <new tag>; web updated too: <yes/no>
Steps and durations: 0% 5min / 5% 10min / 25% 10min / 100% 30min
Measured traffic ratio: ingress-nginx upstream count ≈ <x>% (method: <access log/metrics>)
Metrics: 5xx stable=<..> canary=<..>; P99 stable=<..> canary=<..>; backpressure drops=<..>
Rollback drill: weight=0 took <..>s; enabled=false took <..>s; helm rollback took <..>s
Anomalies and handling: <none / details>
Unvalidated: real controller packet capture, external LB weights, MQTT/QUIC device canary, gRPC traffic split (see chart README §10.5)
```

## 10. Explicitly unvalidated boundaries (must not be skipped)

1. The commands in this runbook **have never been executed on a real K8s/ingress-nginx** (only render assertions exist on this machine);
2. Weighted traffic ratios, `canary-by-header` semantics, and the precedence of `/v1` versus the existing `/` prefix: template assertions only,
   no controller measurements;
3. In the production topology, traffic from Nginx/Envoy directly to nodes is not on the chart Ingress, so its
   weights must be configured separately (not covered by this runbook);
4. MQTT/QUIC device canary, proportional gRPC (9090) traffic splitting, and per-version cross-node routing: **not implemented**
   (the chart does not do this; device canary should use device-dimension configuration/dedicated access pools);
5. HPA/PDB/anti-affinity do not cover canary (fixed replicas and being interruptible at any time is a deliberate tradeoff);
6. The hot-update behavior of `helm upgrade --reuse-values` on Ingress annotations in a real cluster is unvalidated.
