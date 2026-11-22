{{/*
 shared template fragments for node (single source of truth).

 Why extracted: canary releases render a second canary node Deployment; if the PodSpec (Secret env injection,
 volumes, securityContext, probes, topology spread) were duplicated, stable and canary would eventually drift—"changed only the image,
 forgot to sync some security/injection setting" is exactly the most dangerous canary failure mode. Here stable and canary share one
 PodSpec, and template parameters may change only: image, image pull policy, selector labels. Everything else (including env/volumes/probes) is decided solely by this
 template, and `scripts/helm-canary-validate.py` asserts that both have identical env/volumes item by item.
*/}}

{{- define "lattice.node.podSpec" -}}
{{- $root := .root -}}
{{- $v := $root.Values -}}
spec:
  serviceAccountName: {{ include "lattice.serviceAccountName" $root }}
  # nodes do not call the K8s API: no ServiceAccount token is mounted (least privilege, and a smaller token-leak surface)
  automountServiceAccountToken: false
  terminationGracePeriodSeconds: {{ $v.node.terminationGracePeriodSeconds }}
  securityContext:
    # nodes run as non-root (the image already creates the lattice user); the root filesystem is read-only,
    # and directories that need writes (WAL, /tmp) are mounted explicitly as emptyDirs.
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: {{ $v.security.seccompProfile }}
  containers:
    - name: node
      image: {{ .image | quote }}
      imagePullPolicy: {{ .pullPolicy }}
      args: ["--config", "/etc/lattice/config.toml"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: {{ $v.security.node.readOnlyRootFilesystem }}
        capabilities:
          drop: ["ALL"]
      ports:
        - name: http
          containerPort: 8080
          protocol: TCP
        - name: metrics
          containerPort: 9100
          protocol: TCP
        {{- if $v.mqtt.enabled }}
        - name: mqtt
          containerPort: {{ $v.mqtt.service.port }}
          protocol: TCP
        {{- end }}
        {{- if and $v.tls.enabled $v.tls.mqtt.enabled }}
        - name: mqtt-tls
          containerPort: {{ $v.tls.mqtt.port }}
          protocol: TCP
        {{- end }}
        {{- if $v.grpc.enabled }}
        - name: grpc
          containerPort: {{ $v.grpc.port }}
          protocol: TCP
        {{- end }}
        {{- if and $v.tls.enabled $v.tls.quic.enabled }}
        - name: quic
          containerPort: {{ $v.tls.quic.port }}
          protocol: UDP
        {{- end }}
      env:
        # secrets are injected only via env vars (apply_env overrides TOML); no credentials appear in the ConfigMap.
        - name: LATTICE__PG__URL
          valueFrom:
            secretKeyRef:
              name: {{ include "lattice.secretName" $root }}
              key: pg-url
        - name: LATTICE__REDIS__URL
          valueFrom:
            secretKeyRef:
              name: {{ include "lattice.secretName" $root }}
              key: redis-url
        - name: LATTICE__S3__ACCESS_KEY
          valueFrom:
            secretKeyRef:
              name: {{ include "lattice.secretName" $root }}
              key: s3-access-key
        - name: LATTICE__S3__SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: {{ include "lattice.secretName" $root }}
              key: s3-secret-key
        - name: LATTICE__ADMIN__BOOTSTRAP_PASSWORD
          valueFrom:
            secretKeyRef:
              name: {{ include "lattice.secretName" $root }}
              key: admin-bootstrap-password
        - name: LATTICE__NODE__METRICS
          value: {{ $v.node.metrics | quote }}
        - name: RUST_LOG
          value: "info,lattice_node=info"
        {{- with $v.node.extraEnv }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      lifecycle:
        preStop:
          exec:
            # wait for Endpoints/LB drain to propagate, then let kubelet send SIGTERM: the node goes draining →
            #             /v1/ready 503 + WS byef + gRPC shutdown (see ② §7.2 and the node drain implementation).
            command: ["sh", "-c", "sleep {{ $v.node.preStopSleepSeconds }}"]
      readinessProbe:
        httpGet:
          path: /v1/ready
          port: http
        initialDelaySeconds: 5
        periodSeconds: 5
        timeoutSeconds: 3
        failureThreshold: 3
      livenessProbe:
        httpGet:
          path: /v1/health
          port: http
        initialDelaySeconds: 15
        periodSeconds: 10
        timeoutSeconds: 3
        failureThreshold: 3
      startupProbe:
        httpGet:
          path: /v1/health
          port: http
        periodSeconds: 3
        failureThreshold: 40
      resources:
        {{- toYaml $v.node.resources | nindent 8 }}
      volumeMounts:
        - name: config
          mountPath: /etc/lattice/config.toml
          subPath: config.toml
          readOnly: true
        - name: jwt-keys
          mountPath: {{ $v.auth.keyDir }}
          readOnly: true
        {{- if and $v.grpc.enabled (include "lattice.grpcTlsEnabled" $root) }}
        - name: grpc-tls
          mountPath: {{ include "lattice.grpcTlsMountPath" $root }}
          readOnly: true
        {{- end }}
        {{- if and $v.tls.enabled $v.tls.mqtt.enabled }}
        - name: mqtt-tls
          mountPath: {{ printf "%s/mqtt" $v.tls.mountPath }}
          readOnly: true
        {{- end }}
        {{- if and $v.tls.enabled $v.tls.quic.enabled }}
        - name: quic-tls
          mountPath: {{ printf "%s/quic" $v.tls.mountPath }}
          readOnly: true
        {{- end }}
        - name: wal
          mountPath: /var/lib/lattice
        {{- range $v.security.node.writableEmptyDirs }}
        - name: {{ .name }}
          mountPath: {{ .mountPath }}
        {{- end }}
  volumes:
    - name: config
      configMap:
        name: {{ include "lattice.node.fullname" $root }}-config
    - name: jwt-keys
      secret:
        secretName: {{ $v.auth.keysSecret }}
        defaultMode: 0400
        items:
          - key: {{ $v.auth.keysSecretKey }}
            path: jwt.key.pem
    {{- if and $v.grpc.enabled (include "lattice.grpcTlsEnabled" $root) }}
    - name: grpc-tls
      secret:
        secretName: {{ include "lattice.grpcTlsSecretName" $root }}
        defaultMode: 0400
    {{- end }}
    {{- if and $v.tls.enabled $v.tls.mqtt.enabled }}
    - name: mqtt-tls
      secret:
        # device certificates and keys mount only into this Pod; defaultMode 0400 + fsGroup make them group-readable
        secretName: {{ $v.tls.mqtt.secretName }}
        defaultMode: 0400
    {{- end }}
    {{- if and $v.tls.enabled $v.tls.quic.enabled }}
    - name: quic-tls
      secret:
        secretName: {{ $v.tls.quic.secretName }}
        defaultMode: 0400
    {{- end }}
    - name: wal
      emptyDir:
        sizeLimit: 2Gi
    {{- range $v.security.node.writableEmptyDirs }}
    - name: {{ .name }}
      emptyDir:
        sizeLimit: {{ .sizeLimit }}
    {{- end }}
  {{- with $v.node.nodeSelector }}
  nodeSelector:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with $v.node.tolerations }}
  tolerations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with $v.node.affinity }}
  affinity:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: ScheduleAnyway
      labelSelector:
        matchLabels:
          {{- .labels | nindent 10 }}
{{- end -}}

{{/*
 node NetworkPolicy rules (single source of truth): the stable node and canary node share the same
 "deny ingress by default, allow by port" rules, differing only in podSelector. Duplicating the rules would let canary Pods silently
 bypass default-deny in a hardened cluster (K8s semantics: a Pod selected by no NetworkPolicy is allow-all).
 The caller includes this template after spec.podSelector (nindent 2).
*/}}
{{- define "lattice.node.networkPolicyRules" -}}
{{- $root := . -}}
{{- $v := $root.Values -}}
policyTypes:
  - Ingress
  {{- if $v.networkPolicy.egress.enabled }}
  - Egress
  {{- end }}
ingress:
  # web → node:8080
  - from:
      - podSelector:
          matchLabels:
            {{- include "lattice.web.selectorLabels" $root | nindent 12 }}
      {{- with $v.networkPolicy.ingressFrom }}
      {{- toYaml . | nindent 6 }}
      {{- end }}
    ports:
      - protocol: TCP
        port: 8080
  {{- if $v.networkPolicy.ingressControllerNamespace }}
  # Ingress Controller namespace → node:8080 (HTTP/WS TLS terminates at that layer)
  - from:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: {{ $v.networkPolicy.ingressControllerNamespace | quote }}
    ports:
      - protocol: TCP
        port: 8080
  {{- end }}
  {{- if $v.mqtt.enabled }}
  # MQTT clients (empty mqttFrom = restrict the port only; sources are covered by the LB/firewall)
  - {{- with $v.networkPolicy.mqttFrom }}
    from:
      {{- toYaml . | nindent 6 }}
    {{- end }}
    ports:
      - protocol: TCP
        port: {{ $v.mqtt.service.port }}
      {{- if and $v.tls.enabled $v.tls.mqtt.enabled }}
      - protocol: TCP
        port: {{ $v.tls.mqtt.port }}
      {{- end }}
  {{- end }}
  {{- if $v.grpc.enabled }}
  # internal gRPC: allow only node-to-node calls (Route/FetchChunks/Heartbeat/WatermarkSync)
  - from:
      - podSelector:
          matchLabels:
            {{- include "lattice.node.selectorLabels" $root | nindent 12 }}
    ports:
      - protocol: TCP
        port: {{ $v.grpc.port }}
  {{- end }}
  # metrics port
  - {{- if $v.networkPolicy.metricsNamespace }}
    from:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: {{ $v.networkPolicy.metricsNamespace | quote }}
    {{- end }}
    ports:
      - protocol: TCP
        port: 9100
  {{- if and $v.tls.enabled $v.tls.quic.enabled }}
  # QUIC/WebTransport UDP
  - {{- with $v.networkPolicy.udpFrom }}
    from:
      {{- toYaml . | nindent 6 }}
    {{- end }}
    ports:
      - protocol: UDP
        port: {{ $v.tls.quic.port }}
  {{- end }}
{{- if $v.networkPolicy.egress.enabled }}
egress:
  # DNS (required: otherwise Service names fail to resolve)
  - to:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: {{ $v.networkPolicy.egress.dnsNamespace | quote }}
    ports:
      - protocol: UDP
        port: 53
      - protocol: TCP
        port: 53
  {{- with $v.networkPolicy.egress.allow }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
{{- end }}
{{- end -}}
