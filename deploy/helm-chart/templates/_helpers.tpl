{{/*
Expand the name of the chart.
*/}}
{{- define "helm-firewall.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "helm-firewall.fullname" -}}
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
{{- define "helm-firewall.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "helm-firewall.labels" -}}
helm.sh/chart: {{ include "helm-firewall.chart" . }}
{{ include "helm-firewall.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: helm
{{- end }}

{{/*
Selector labels
*/}}
{{- define "helm-firewall.selectorLabels" -}}
app.kubernetes.io/name: {{ include "helm-firewall.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "helm-firewall.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "helm-firewall.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the image name
*/}}
{{- define "helm-firewall.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
Return the signing key secret name
*/}}
{{- define "helm-firewall.signingSecretName" -}}
{{- if .Values.helm.signing.existingSecret }}
{{- .Values.helm.signing.existingSecret }}
{{- else }}
{{- printf "%s-signing" (include "helm-firewall.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the runtime auth secret name
*/}}
{{- define "helm-firewall.authSecretName" -}}
{{- if .Values.helm.auth.existingSecret }}
{{- .Values.helm.auth.existingSecret }}
{{- else }}
{{- printf "%s-auth" (include "helm-firewall.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the policy ConfigMap name
*/}}
{{- define "helm-firewall.policyConfigMapName" -}}
{{- if .Values.helm.policy.source.mountedFile.existingConfigMap }}
{{- .Values.helm.policy.source.mountedFile.existingConfigMap }}
{{- else if .Values.helm.policy.configMap }}
{{- .Values.helm.policy.configMap }}
{{- else }}
{{- printf "%s-config" (include "helm-firewall.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the policy Secret name for mounted-file delivery, when configured.
*/}}
{{- define "helm-firewall.policySecretName" -}}
{{- .Values.helm.policy.source.mountedFile.existingSecret }}
{{- end }}

{{/*
Return the policy mount path inside the container.
*/}}
{{- define "helm-firewall.policyMountPath" -}}
{{- default .Values.helm.policy.mountPath .Values.helm.policy.source.mountedFile.mountPath }}
{{- end }}

{{/*
Return the serve policy path inside the container
*/}}
{{- define "helm-firewall.policyPath" -}}
{{- printf "%s/%s" ((include "helm-firewall.policyMountPath" .) | trimSuffix "/") .Values.helm.policy.fileName }}
{{- end }}

{{/*
Return the database URL.
If an existing secret is provided, return empty (handled via secretKeyRef in deployment).
Otherwise, construct from individual values.
*/}}
{{- define "helm-firewall.databaseURL" -}}
{{- if and (eq .Values.helm.storage.type "postgres") (not .Values.helm.storage.postgres.existingSecret) }}
{{- printf "postgres://%s:%s@%s:%d/%s?sslmode=%s" .Values.helm.storage.postgres.user .Values.helm.storage.postgres.password .Values.helm.storage.postgres.host (int .Values.helm.storage.postgres.port) .Values.helm.storage.postgres.database .Values.helm.storage.postgres.sslMode }}
{{- end }}
{{- end }}

{{/*
Return the PVC name
*/}}
{{- define "helm-firewall.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- printf "%s-data" (include "helm-firewall.fullname" .) }}
{{- end }}
{{- end }}
