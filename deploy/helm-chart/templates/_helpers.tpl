{{/*
Expand the name of the chart.
*/}}
{{- define "helm-ai-kernel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "helm-ai-kernel.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "helm-ai-kernel.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "helm-ai-kernel.labels" -}}
helm.sh/chart: {{ include "helm-ai-kernel.chart" . }}
{{ include "helm-ai-kernel.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: helm-ai-kernel
{{- end }}

{{/*
Selector labels
*/}}
{{- define "helm-ai-kernel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "helm-ai-kernel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "helm-ai-kernel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "helm-ai-kernel.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the image name
*/}}
{{- define "helm-ai-kernel.image" -}}
{{- if .Values.image.digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" .Values.image.digest) -}}
{{- fail "image.digest must be a sha256 digest with 64 lowercase hex characters" -}}
{{- end -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else if .Values.helm.production -}}
{{- fail "helm.production=true requires image.digest pinned by immutable sha256 digest" -}}
{{- else -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end }}

{{/*
Return the signing key secret name
*/}}
{{- define "helm-ai-kernel.signingSecretName" -}}
{{- if .Values.helm.signing.existingSecret }}
{{- .Values.helm.signing.existingSecret }}
{{- else }}
{{- printf "%s-signing" (include "helm-ai-kernel.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the runtime auth secret name
*/}}
{{- define "helm-ai-kernel.authSecretName" -}}
{{- if .Values.helm.auth.existingSecret }}
{{- .Values.helm.auth.existingSecret }}
{{- else }}
{{- printf "%s-auth" (include "helm-ai-kernel.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the policy ConfigMap name
*/}}
{{- define "helm-ai-kernel.policyConfigMapName" -}}
{{- if .Values.helm.policy.source.mountedFile.existingConfigMap }}
{{- .Values.helm.policy.source.mountedFile.existingConfigMap }}
{{- else if .Values.helm.policy.configMap }}
{{- .Values.helm.policy.configMap }}
{{- else }}
{{- printf "%s-config" (include "helm-ai-kernel.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the policy Secret name for mounted-file delivery, when configured.
*/}}
{{- define "helm-ai-kernel.policySecretName" -}}
{{- .Values.helm.policy.source.mountedFile.existingSecret }}
{{- end }}

{{/*
Return the policy mount path inside the container.
*/}}
{{- define "helm-ai-kernel.policyMountPath" -}}
{{- default .Values.helm.policy.mountPath .Values.helm.policy.source.mountedFile.mountPath }}
{{- end }}

{{/*
Return the serve policy path inside the container
*/}}
{{- define "helm-ai-kernel.policyPath" -}}
{{- printf "%s/%s" ((include "helm-ai-kernel.policyMountPath" .) | trimSuffix "/") .Values.helm.policy.fileName }}
{{- end }}

{{/*
Return the database URL.
If an existing secret is provided, return empty (handled via secretKeyRef in deployment).
Otherwise, construct from individual values.
*/}}
{{- define "helm-ai-kernel.databaseURL" -}}
{{- if and (eq .Values.helm.storage.type "postgres") (not .Values.helm.storage.postgres.existingSecret) }}
{{- printf "postgres://%s:%s@%s:%d/%s?sslmode=%s" .Values.helm.storage.postgres.user .Values.helm.storage.postgres.password .Values.helm.storage.postgres.host (int .Values.helm.storage.postgres.port) .Values.helm.storage.postgres.database .Values.helm.storage.postgres.sslMode }}
{{- end }}
{{- end }}

{{/*
Return the PVC name
*/}}
{{- define "helm-ai-kernel.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- printf "%s-data" (include "helm-ai-kernel.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Effect gateway (helm-gateway) names and labels. The selector labels carry
their own app.kubernetes.io/name, so the kernel's Service and NetworkPolicy
never select a gateway Pod, and the gateway's never select a kernel Pod.
*/}}
{{- define "helm-ai-kernel.gatewayName" -}}
{{- printf "%s-gateway" (include "helm-ai-kernel.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "helm-ai-kernel.gatewaySelectorLabels" -}}
app.kubernetes.io/name: {{ printf "%s-gateway" (include "helm-ai-kernel.name" .) | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: effect-gateway
{{- end }}

{{- define "helm-ai-kernel.gatewayLabels" -}}
helm.sh/chart: {{ include "helm-ai-kernel.chart" . }}
{{ include "helm-ai-kernel.gatewaySelectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: helm-ai-kernel
{{- end }}

{{/*
Render-time checks for the gateway block. Every gateway template includes
this, so a missing value fails `helm template` whichever object renders first.
*/}}
{{- define "helm-ai-kernel.gatewayValidate" -}}
{{- $g := .Values.gateway -}}
{{- if $g.tls.devInsecureLoopback -}}
{{- if .Values.helm.production -}}
{{- fail "gateway.tls.devInsecureLoopback is refused when helm.production=true; set gateway.tls.existingSecret" -}}
{{- end -}}
{{- if $g.tls.existingSecret -}}
{{- fail "gateway.tls.devInsecureLoopback and gateway.tls.existingSecret are mutually exclusive" -}}
{{- end -}}
{{- else -}}
{{- if not $g.tls.existingSecret -}}
{{- fail "gateway.enabled=true requires gateway.tls.existingSecret (tls.crt, tls.key and, for client auth, ca.crt); gateway.tls.devInsecureLoopback=true is the development-only alternative" -}}
{{- end -}}
{{- if not (has $g.tls.clientAuth (list "" "require" "verify-if-given")) -}}
{{- fail "gateway.tls.clientAuth must be \"\", \"require\" or \"verify-if-given\"" -}}
{{- end -}}
{{- end -}}
{{- range $key := list "jwksURL" "issuer" "audience" "actor" -}}
{{- if not (index $g.controlPlaneIdentity $key) -}}
{{- fail (printf "gateway.enabled=true requires gateway.controlPlaneIdentity.%s; the gateway takes identity only from Control Plane tokens" $key) -}}
{{- end -}}
{{- end -}}
{{- if and $g.controlPlaneIdentity.requireCNF (or $g.tls.devInsecureLoopback (not $g.tls.clientAuth)) -}}
{{- fail "gateway.controlPlaneIdentity.requireCNF requires gateway.tls.clientAuth, which supplies the client certificate cnf binds to" -}}
{{- end -}}
{{- if not $g.database.existingSecret -}}
{{- fail "gateway.enabled=true requires gateway.database.existingSecret holding HELM_GATEWAY_DATABASE_URL (the helm_gateway runtime role's DSN)" -}}
{{- end -}}
{{- if and $g.database.bootstrap.enabled $g.database.migrate.existingSecret -}}
{{- fail "gateway.database.bootstrap.enabled and gateway.database.migrate.existingSecret are mutually exclusive: the bootstrap migrates as its owner role" -}}
{{- end -}}
{{- if $g.database.bootstrap.enabled -}}
{{- if not $g.database.bootstrap.existingSecret -}}
{{- fail "gateway.database.bootstrap.enabled=true requires gateway.database.bootstrap.existingSecret holding the administrator DSN" -}}
{{- end -}}
{{- range $key := list "ownerRole" "runtimeRole" "schema" -}}
{{- if not (regexMatch "^[a-z_][a-z0-9_]{0,62}$" (index $g.database.bootstrap $key | toString)) -}}
{{- fail (printf "gateway.database.bootstrap.%s must be a lowercase PostgreSQL identifier" $key) -}}
{{- end -}}
{{- end -}}
{{- if eq $g.database.bootstrap.ownerRole $g.database.bootstrap.runtimeRole -}}
{{- fail "gateway.database.bootstrap.ownerRole and runtimeRole must differ: the serving role must not own the tables" -}}
{{- end -}}
{{- if not (regexMatch "^.+@sha256:[0-9a-f]{64}$" $g.database.bootstrap.image) -}}
{{- fail "gateway.database.bootstrap.image must be pinned by immutable sha256 digest" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.helm.production (not (or $g.database.bootstrap.enabled $g.database.migrate.existingSecret)) -}}
{{- fail "helm.production=true with gateway.enabled requires an owner DSN for migrate (gateway.database.bootstrap.enabled or gateway.database.migrate.existingSecret); migrating with the runtime DSN makes the serving role the table owner" -}}
{{- end -}}
{{- if $g.networkPolicy.enabled -}}
{{- if and (empty $g.networkPolicy.controlPlane.namespaceSelector) (empty $g.networkPolicy.controlPlane.podSelector) -}}
{{- fail "gateway.networkPolicy.enabled=true requires gateway.networkPolicy.controlPlane.namespaceSelector or podSelector: the only callers admitted to the API port" -}}
{{- end -}}
{{- if empty $g.networkPolicy.database.to -}}
{{- fail "gateway.networkPolicy.enabled=true requires gateway.networkPolicy.database.to: the database peers the gateway may reach" -}}
{{- end -}}
{{- else if .Values.helm.production -}}
{{- fail "helm.production=true requires gateway.networkPolicy.enabled=true" -}}
{{- end -}}
{{- end }}
