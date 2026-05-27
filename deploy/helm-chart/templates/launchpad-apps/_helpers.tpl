{{/*
Resource name for a launchpad app workload (Deployment or Job).
Usage: {{ include "helm-ai-kernel.launchpadApp.fullname" (dict "ctx" . "app" "openclaw") }}
*/}}
{{- define "helm-ai-kernel.launchpadApp.fullname" -}}
{{- $ctx := .ctx -}}
{{- $app := .app -}}
{{- printf "%s-%s" (include "helm-ai-kernel.fullname" $ctx) $app | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels for launchpad app resources.
Usage: {{ include "helm-ai-kernel.launchpadApp.labels" (dict "ctx" . "app" "openclaw") }}
*/}}
{{- define "helm-ai-kernel.launchpadApp.labels" -}}
{{- $ctx := .ctx -}}
{{- $app := .app -}}
{{ include "helm-ai-kernel.labels" $ctx }}
app.kubernetes.io/component: launchpad-app
helm.ai/launchpad-app: {{ $app | quote }}
{{- end -}}

{{/*
Selector labels for launchpad app resources.
Usage: {{ include "helm-ai-kernel.launchpadApp.selectorLabels" (dict "ctx" . "app" "openclaw") }}
*/}}
{{- define "helm-ai-kernel.launchpadApp.selectorLabels" -}}
{{- $ctx := .ctx -}}
{{- $app := .app -}}
{{ include "helm-ai-kernel.selectorLabels" $ctx }}
app.kubernetes.io/component: launchpad-app
helm.ai/launchpad-app: {{ $app | quote }}
{{- end -}}

{{/*
Render an immutable image reference for a launchpad app.
The chart pins each app via {repository, digest} from values.yaml. Tags are
intentionally not supported here — supply chain integrity comes from sha256.
Usage: {{ include "helm-ai-kernel.launchpadApp.image" (dict "image" .Values.launchpadApps.openclaw.image) }}
*/}}
{{- define "helm-ai-kernel.launchpadApp.image" -}}
{{- $img := .image -}}
{{- if not $img.digest -}}
{{- fail "launchpad app images must be pinned by sha256 digest, not by tag" -}}
{{- end -}}
{{- printf "%s@%s" $img.repository $img.digest -}}
{{- end -}}

{{/*
Egress sidecar container spec shared by openclaw and hermes Pods.
The sidecar listens on localhost:<port> and is reachable by the workload
container through the Pod-shared network namespace, mirroring the
DockerSidecarEgressProxy setup used in the local-container runbooks.
Usage: {{ include "helm-ai-kernel.launchpadApp.egressSidecar" (dict "sidecar" .Values.launchpadApps.openclaw.egressSidecar) }}
*/}}
{{- define "helm-ai-kernel.launchpadApp.egressSidecar" -}}
{{- $s := .sidecar -}}
- name: egress-proxy
  {{- if .init }}
  # Native Kubernetes sidecar pattern (k8s >= 1.28): restartPolicy:Always on an
  # initContainer turns it into a sidecar that does not block Pod completion.
  # Used for short-lived workloads (Jobs) so the Pod can transition to Succeeded
  # once the main container exits.
  restartPolicy: Always
  {{- end }}
  image: {{ include "helm-ai-kernel.launchpadApp.image" (dict "image" $s.image) | quote }}
  imagePullPolicy: {{ $s.image.pullPolicy | default "IfNotPresent" }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    capabilities:
      drop:
        - ALL
  env:
    - name: HELM_EGRESS_LISTEN
      value: {{ printf ":%d" (int $s.port) | quote }}
    - name: HELM_EGRESS_ALLOWLIST
      value: {{ join "," $s.allowlist | quote }}
    # The egress proxy binary requires HELM_EGRESS_LAUNCH_ID for receipt scoping.
    # In the launchpad runtime this is the kernel-assigned launch_id; in chart-
    # managed co-deployment there is no launch_id, so derive a stable synthetic
    # one from the Pod UID via downward API. Each Pod restart gets a fresh UID,
    # which matches the per-launch isolation semantic.
    - name: HELM_EGRESS_LAUNCH_ID
      valueFrom:
        fieldRef:
          fieldPath: metadata.uid
    - name: HELM_EGRESS_RECEIPT_DIR
      value: /var/run/launchpad-egress/receipts
  ports:
    - name: egress
      containerPort: {{ $s.port }}
      protocol: TCP
  resources:
    {{- toYaml $s.resources | nindent 4 }}
  volumeMounts:
    - name: egress-receipts
      mountPath: /var/run/launchpad-egress/receipts
{{- end -}}
