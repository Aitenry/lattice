{{/*
 Naming and labels: shared by all templates so each resource does not define its own selector.
*/}}

{{- define "lattice.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "lattice.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "lattice.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "lattice.labels" -}}
helm.sh/chart: {{ include "lattice.chart" . }}
app.kubernetes.io/name: {{ include "lattice.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "lattice.selectorLabels" -}}
app.kubernetes.io/name: {{ include "lattice.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "lattice.node.selectorLabels" -}}
{{ include "lattice.selectorLabels" . }}
app.kubernetes.io/component: node
{{- end -}}

{{- define "lattice.web.selectorLabels" -}}
{{ include "lattice.selectorLabels" . }}
app.kubernetes.io/component: web
{{- end -}}

{{- define "lattice.node.fullname" -}}
{{ include "lattice.fullname" . }}-node
{{- end -}}

{{- define "lattice.node.canary.fullname" -}}
{{ include "lattice.fullname" . }}-node-canary
{{- end -}}

{{/*
 Selector labels for canary Pods: they **must** be distinguishable from the stable node selector.
 A K8s Deployment's selector is immutable, so a track label cannot be appended to the stable selector;
 instead a different component value (node-canary) keeps canary Pods and the stable Service selector
 fully separate (otherwise the stable Service would also send traffic to canary Pods and the canary weights would be wrong).
*/}}
{{- define "lattice.node.canarySelectorLabels" -}}
{{ include "lattice.selectorLabels" . }}
app.kubernetes.io/component: node-canary
{{- end -}}

{{- define "lattice.web.fullname" -}}
{{ include "lattice.fullname" . }}-web
{{- end -}}

{{- define "lattice.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "lattice.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "lattice.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "lattice.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
 TLS compatibility layer: gRPC mTLS has two entry points—
     new: tls.enabled + tls.grpc.enabled (recommended; certificates mount at /etc/lattice/tls/grpc)
     legacy: grpc.tls.enabled (kept only for upgrade compatibility; mount path grpc.tls.mountPath)
 Non-empty checks use hasKey first so values defaults of false do not mask the legacy config.
*/}}
{{- define "lattice.grpcTlsEnabled" -}}
{{- if and .Values.tls.enabled .Values.tls.grpc.enabled -}}true{{- else if .Values.grpc.tls.enabled -}}true{{- end -}}
{{- end -}}

{{- define "lattice.grpcTlsSecretName" -}}
{{- if and .Values.tls.enabled .Values.tls.grpc.enabled -}}
{{- .Values.tls.grpc.secretName -}}
{{- else -}}
{{- .Values.grpc.tls.secretName -}}
{{- end -}}
{{- end -}}

{{- define "lattice.grpcTlsMountPath" -}}
{{- if and .Values.tls.enabled .Values.tls.grpc.enabled -}}
{{- .Values.tls.grpc.mountPath -}}
{{- else -}}
{{- .Values.grpc.tls.mountPath -}}
{{- end -}}
{{- end -}}

{{- define "lattice.webTlsEnabled" -}}
{{- if and .Values.tls.enabled .Values.tls.http.web.enabled -}}true{{- end -}}
{{- end -}}

{{- define "lattice.ingressTlsSecretName" -}}
{{- if and .Values.tls.enabled .Values.tls.http.ingressSecretName -}}
{{- .Values.tls.http.ingressSecretName -}}
{{- else -}}
{{- .Values.ingress.tls.secretName -}}
{{- end -}}
{{- end -}}

