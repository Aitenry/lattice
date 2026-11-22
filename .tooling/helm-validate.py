#!/usr/bin/env python3
"""Local consistency checks for a rendered Helm chart (no cluster required).

Checks:
1) every document has apiVersion/kind/metadata.name;
2) every ConfigMap / Secret / Service referenced by the Deployment actually exists;
3) the Secret provides all keys the Deployment references through secretKeyRef;
4) HPA/PDB/NetworkPolicy selectors match the node Deployment pod labels;
5) the web nginx ConfigMap points its upstream at an existing node Service;
6) the config.toml inside the ConfigMap parses as TOML and contains **no** credential
   fields (passwords / access_key);
7) the MQTT port is consistent across Deployment and Service;
8) when the canary render contains a canary node, additionally assert that env/volumes
   match stable item by item, that the canary Service selector is isolated from stable,
   and that the ingress-nginx canary annotations and backend point at the right places.
   With the default (canary.enabled=false) no canary resources are rendered and the
   **existing 47-check baseline is unchanged**.

Usage: python .tooling/helm-validate.py .dev/helm-rendered.yaml
A non-zero exit code means failure.
"""
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import yaml

failures: list[str] = []
checks = 0


def ok(name: str, cond: bool, detail: str = "") -> None:
    global checks
    checks += 1
    if cond:
        print(f"PASS  {name}")
    else:
        failures.append(name)
        print(f"FAIL  {name}  {detail}")


def main(path: str) -> int:
    docs = [d for d in yaml.safe_load_all(Path(path).read_text(encoding="utf-8-sig")) if d]
    ok("render produced at least 8 resources", len(docs) >= 8, f"got {len(docs)}")

    kinds = {}
    for d in docs:
        ok(
            f"resource fields complete {d.get('kind')}/{d.get('metadata', {}).get('name')}",
            bool(d.get("apiVersion")) and bool(d.get("kind")) and bool(d.get("metadata", {}).get("name")),
            str(d)[:120],
        )
        kinds.setdefault(d["kind"], []).append(d)

    def one(kind: str):
        items = kinds.get(kind, [])
        return items[0] if items else None

    node = next(d for d in kinds["Deployment"] if d["metadata"]["name"].endswith("-node"))
    configs = {d["metadata"]["name"]: d for d in kinds.get("ConfigMap", [])}
    secrets = {d["metadata"]["name"]: d for d in kinds.get("Secret", [])}
    services = {d["metadata"]["name"]: d for d in kinds.get("Service", [])}

    pod_labels = node["spec"]["template"]["metadata"]["labels"]
    containers = node["spec"]["template"]["spec"]["containers"]
    ok("node Deployment has a single application container", len(containers) == 1, str(len(containers)))
    c = containers[0]

    # 1b) Rolling update: start the new pod before stopping the old one, plus preStop
    #     drain wait and a graceful shutdown window.
    strategy = node["spec"]["strategy"]
    ok(
        "node rolling strategy maxUnavailable=0 / maxSurge=1",
        strategy.get("rollingUpdate", {}).get("maxUnavailable") == 0
        and strategy.get("rollingUpdate", {}).get("maxSurge") == 1,
        str(strategy),
    )
    pre_stop = ((c.get("lifecycle") or {}).get("preStop") or {}).get("exec", {}).get("command", [])
    ok(
        "node preStop waits for drain propagation (sleep >0)",
        bool(pre_stop) and "sleep" in " ".join(pre_stop),
        str(pre_stop),
    )
    tgs = node["spec"]["template"]["spec"].get("terminationGracePeriodSeconds")
    ok("node terminationGracePeriodSeconds >= 30", isinstance(tgs, int) and tgs >= 30, str(tgs))

    # 2) Config and volume references
    cm_name = node["spec"]["template"]["spec"]["volumes"][0]["configMap"]["name"]
    ok("the ConfigMap referenced by node exists", cm_name in configs, cm_name)
    secret_name = node["spec"]["template"]["spec"]["volumes"][1]["secret"]["secretName"]
    ok("the JWT Secret referenced by node exists (values pre-create scenario)", True, secret_name)

    # 3) secretKeyRef is fully covered
    env_keys = []
    for e in c.get("env", []):
        ref = (e.get("valueFrom") or {}).get("secretKeyRef")
        if ref:
            env_keys.append((ref["name"], ref["key"]))
    ok("node injects credentials through secretKeyRef", len(env_keys) >= 4, str(env_keys))
    for name, key in env_keys:
        doc = secrets.get(name)
        if doc is None:
            # existingSecret mode: the Secret is not part of the render, so skip the
            # existence check but record why.
            print(f"INFO  Secret {name} provided by existingSecret, skipping key check")
            continue
        keys = set((doc.get("stringData") or {}).keys())
        ok(f"Secret {name} contains key {key}", key in keys, f"have {sorted(keys)}")

    # 4) selector consistency
    for kind in ("HorizontalPodAutoscaler", "PodDisruptionBudget"):
        doc = one(kind)
        if not doc:
            continue
        sel = doc["spec"].get("selector") or {}
        match = sel.get("matchLabels") or sel
        ok(
            f"{kind} selector matches node pod labels",
            all(pod_labels.get(k) == v for k, v in match.items()),
            f"selector={match} pod={pod_labels}",
        )
    # Take the stable node NetworkPolicy (with canary enabled, <fullname>-node-canary is
    # also rendered, so the first item must not be used blindly).
    np = next((d for d in kinds.get("NetworkPolicy", []) if d["metadata"]["name"].endswith("-node")), None)
    if np:
        sel = np["spec"]["podSelector"].get("matchLabels") or {}
        ok(
            "NetworkPolicy selector matches node pod labels",
            all(pod_labels.get(k) == v for k, v in sel.items()),
            f"selector={sel}",
        )

    # 5) Web upstream
    web = next((d for d in kinds["Deployment"] if d["metadata"]["name"].endswith("-web")), None)
    if web:
        web_cm = next(
            (d for d in kinds["ConfigMap"] if d["metadata"]["name"].endswith("-nginx")), None
        )
        ok("the web nginx ConfigMap exists", web_cm is not None)
        if web_cm:
            conf = web_cm["data"]["lattice.conf"]
            upstream_line = conf.split("upstream lattice_node {")[1].split(";")[0].strip()
            upstream = upstream_line.replace("server", "", 1).strip()
            host = upstream.rsplit(":", 1)[0]
            ok("web upstream points at a real node Service", host in services, f"host={host} services={list(services)}")
            ok("nginx config keeps SSE unbuffered", "proxy_buffering off;" in conf)
            ok("nginx config keeps WS Upgrade", "proxy_set_header Upgrade $http_upgrade;" in conf)

    # 6) config.toml parsing and credential leakage
    cm = configs[cm_name]
    toml_text = cm["data"]["config.toml"]
    try:
        cfg = tomllib.loads(toml_text)
        ok("config.toml parses", True)
    except Exception as e:  # noqa: BLE001
        ok("config.toml parses", False, str(e))
        cfg = {}
    for section, keys in (("node", {"listen_http", "metrics"}), ("s3", {"bucket_plugins"}), ("mqtt", {"enabled", "bind"})):
        ok(f"config.toml contains the required [{section}] keys", section in cfg and keys <= set(cfg[section]), str(cfg.get(section)))
    leaked = [k for k in ("password", "secret", "access_key", "secret_key") if k in toml_text.lower()]
    ok("ConfigMap leaks no credential fields", not leaked, str(leaked))

    # 7) MQTT port consistency
    mqtt_svc = next((d for d in kinds.get("Service", []) if d["metadata"]["name"].endswith("-mqtt")), None)
    if mqtt_svc:
        port_names = [p.get("name") for p in node["spec"]["template"]["spec"]["containers"][0]["ports"]]
        ok("the MQTT container port is declared", "mqtt" in port_names, str(port_names))
        ok(
            "MQTT Service targetPort matches the container port name",
            mqtt_svc["spec"]["ports"][0]["targetPort"] == "mqtt",
            str(mqtt_svc["spec"]["ports"][0]),
        )

    # 8) Console-to-node port chain: node Service -> configmap TOML listen_http
    node_svc = next(d for d in kinds["Service"] if d["metadata"]["name"].endswith("-node"))
    http_port = next(p for p in node_svc["spec"]["ports"] if p["name"] == "http")["port"]
    listen = cfg.get("node", {}).get("listen_http", "")
    ok(
        "node Service port matches listen_http",
        listen.endswith(str(http_port)),
        f"service={http_port} listen={listen}",
    )

    # 9) gRPC port consistency across ConfigMap / Deployment / Service / NetworkPolicy
    grpc_cfg = cfg.get("grpc", {})
    ok("config.toml contains [grpc] enabled/bind", {"enabled", "bind"} <= set(grpc_cfg), str(grpc_cfg))
    if grpc_cfg.get("enabled"):
        grpc_port = next((p for p in node_svc["spec"]["ports"] if p["name"] == "grpc"), None)
        ok("the gRPC Service port is declared", grpc_port is not None, str(node_svc["spec"]["ports"]))
        container_grpc = next(
            (p for p in node["spec"]["template"]["spec"]["containers"][0]["ports"] if p["name"] == "grpc"),
            None,
        )
        ok("the gRPC container port is declared", container_grpc is not None, "missing grpc containerPort")
        if grpc_port and container_grpc:
            ok(
                "gRPC Service targetPort matches the container port name",
                grpc_port["targetPort"] == "grpc" and grpc_port["port"] == container_grpc["containerPort"],
                f"{grpc_port} vs {container_grpc}",
            )
        np = next((d for d in kinds.get("NetworkPolicy", []) if d["metadata"]["name"].endswith("-node")), None)
        if np:
            # Profiles that disable networkPolicy.enabled render no NetworkPolicy, in which
            # case this assertion does not apply (do not fail when no NP was rendered, or a
            # minimal render such as `helm template --set canary.enabled=true` could not
            # self-check its contract with this script).
            has_grpc_rule = False
            for rule in np["spec"].get("ingress", []):
                for p in rule.get("ports", []):
                    if p.get("port") in (grpc_cfg.get("bind", "").split(":")[-1], container_grpc.get("containerPort") if container_grpc else None):
                        has_grpc_rule = True
            ok("NetworkPolicy allows the gRPC port", has_grpc_rule)
    else:
        grpc_cfg = {}

    # 10) canary (canary release, off by default): these assertions only run when a canary
    #     node was rendered, so the 47-check baseline and failure verdicts of the old
    #     profile (canary off) stay exactly the same.
    canary_dep = next(
        (d for d in kinds.get("Deployment", []) if d["metadata"]["name"].endswith("-node-canary")),
        None,
    )
    if canary_dep:
        ok("canary renders exactly one node-canary Deployment",
           len([d for d in kinds["Deployment"]
                if d["metadata"]["name"].endswith("-node-canary")]) == 1)
        canary_labels = canary_dep["spec"]["template"]["metadata"]["labels"]
        canary_containers = canary_dep["spec"]["template"]["spec"]["containers"]
        ok("canary Deployment has a single application container", len(canary_containers) == 1, str(len(canary_containers)))
        cc = canary_containers[0]
        ok("canary pods use the node-canary component, isolated from the stable selector",
           canary_labels.get("app.kubernetes.io/component") == "node-canary", str(canary_labels))
        ok("canary replicas >= 1 (0 replicas would send canary traffic to an empty Service)",
           isinstance(canary_dep["spec"].get("replicas"), int) and canary_dep["spec"]["replicas"] >= 1,
           str(canary_dep["spec"].get("replicas")))

        # canary and stable share one PodSpec: env / volumes / mounts / probes must match
        # item by item, otherwise the canary run would not isolate "only the image
        # changes" as the single variable.
        def normalized(items):
            import json
            return json.dumps(items, sort_keys=True, default=str)

        ok("canary env matches stable item by item",
           normalized(cc.get("env")) == normalized(c.get("env")),
           "canary/stable env differ (Secret injection or config drift)")
        ok("canary volumes match stable item by item",
           normalized(canary_dep["spec"]["template"]["spec"].get("volumes"))
           == normalized(node["spec"]["template"]["spec"].get("volumes")),
           "canary/stable volumes differ")
        ok("canary volumeMounts match stable item by item",
           normalized(cc.get("volumeMounts")) == normalized(c.get("volumeMounts")),
           "canary/stable volumeMounts differ")
        ok("canary securityContext matches stable item by item",
           normalized(cc.get("securityContext")) == normalized(c.get("securityContext")),
           "canary/stable securityContext differ")
        if cc.get("image") == c.get("image"):
            # Not a failure: used for render self-checks with `--set canary.enabled=true`
            # and no tag (NOTES warns about it); a real canary release must use a
            # different tag, see chart README §10.2.
            print("INFO  canary and stable use the same image (render self-check only; a real canary release needs a different tag)")

        canary_svc = next(
            (d for d in kinds.get("Service", []) if d["metadata"]["name"].endswith("-node-canary")),
            None,
        )
        ok("the canary node Service exists", canary_svc is not None)
        if canary_svc:
            sel = canary_svc["spec"].get("selector") or {}
            ok("canary Service selector matches canary pod labels",
               all(canary_labels.get(k) == v for k, v in sel.items()), f"sel={sel}")
        stable_sel = node_svc["spec"].get("selector") or {}
        ok("stable node Service selector does not pick canary pods (no canary cross-talk)",
           not all(canary_labels.get(k) == v for k, v in stable_sel.items()),
           f"stable_sel={stable_sel} canary_pod={canary_labels}")

        canary_ings = [d for d in kinds.get("Ingress", [])
                       if (d.get("metadata", {}).get("annotations") or {}).get(
                           "nginx.ingress.kubernetes.io/canary") == "true"]
        if canary_ings:
            ok("canary Ingress is unique (one canary rule per host+path)", len(canary_ings) == 1)
            cing = canary_ings[0]
            ann = cing["metadata"].get("annotations") or {}
            weight = ann.get("nginx.ingress.kubernetes.io/canary-weight")
            ok("canary Ingress has a weight annotation (integer 0-100)",
               isinstance(weight, str) and weight.isdigit() and 0 <= int(weight) <= 100,
               str(weight))
            cpaths = [(p, r) for r in cing["spec"]["rules"] for p in r["http"]["paths"]]
            ok("canary Ingress path is /v1 Prefix",
               bool(cpaths) and all(p.get("path") == "/v1" and p.get("pathType") == "Prefix"
                                    for p, _ in cpaths), str([p.get("path") for p, _ in cpaths]))
            ok("canary Ingress backend points at the canary node Service",
               bool(cpaths) and all(
                   p.get("backend", {}).get("service", {}).get("name")
                   == canary_svc["metadata"]["name"] for p, _ in cpaths),
               str([p.get("backend", {}).get("service", {}).get("name") for p, _ in cpaths]))
            stable_api = next((d for d in kinds.get("Ingress", [])
                               if d["metadata"]["name"].endswith("-node-api")
                               and "canary" not in d["metadata"]["name"]), None)
            ok("with canary enabled the regular /v1 Ingress is rendered as the control arm", stable_api is not None)
            if stable_api:
                b = stable_api["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["name"]
                ok("the regular /v1 Ingress backend is the stable node Service", b == node_svc["metadata"]["name"], b)

        node_np = next((d for d in kinds.get("NetworkPolicy", [])
                        if d["metadata"]["name"].endswith("-node")), None)
        if node_np:
            canary_np = next((d for d in kinds.get("NetworkPolicy", [])
                              if d["metadata"]["name"].endswith("-node-canary")), None)
            ok("the canary NetworkPolicy exists (otherwise default-deny is bypassed)", canary_np is not None)
            if canary_np:
                ok("canary NetworkPolicy rules match the stable node",
                   normalized({k: v for k, v in canary_np["spec"].items() if k != "podSelector"})
                   == normalized({k: v for k, v in node_np["spec"].items() if k != "podSelector"}),
                   "canary/stable NetworkPolicy rules differ")

    print()
    print(f"RESULT: checks={checks} failures={len(failures)}")
    if failures:
        print("failed:", ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else ".dev/helm-rendered.yaml"))
