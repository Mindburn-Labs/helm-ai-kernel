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
The sidecar runs as a TRANSPARENT proxy: the companion init-container (see
`helm-ai-kernel.launchpadApp.egressInit`) installs an iptables REDIRECT that
funnels every outbound TCP connection from the workload container into this
listener. The sidecar recovers the original destination via SO_ORIGINAL_DST,
checks the allowlist, and writes a receipt for every attempt (allow and deny).
It runs under a dedicated uid (65532, distinct from the app's 65534) so the
iptables rule can exempt the sidecar's own upstream egress and avoid a loop.
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
    # Dedicated uid (NOT the app's 65534) — the egressInit iptables rule exempts
    # this uid so the proxy's own upstream dials are not redirected back into it.
    runAsUser: 65532
    runAsGroup: 65532
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

{{/*
Egress enforcement init-container. Runs once as root with CAP_NET_ADMIN/NET_RAW to
install an iptables REDIRECT that forces ALL outbound TCP from the workload
container through the egress proxy sidecar on port <port>. This is what makes the
"every egress goes through the sidecar and leaves a receipt" guarantee real rather
than honor-based — a direct connection can no longer bypass the proxy. Reuses the
egress-proxy image (which ships iptables). Exemptions: loopback, the sidecar's own
uid (65532), and DNS-over-TCP; DNS-over-UDP is untouched because the OUTPUT jump is
tcp-only, so the workload can still resolve names itself.
Usage: {{ include "helm-ai-kernel.launchpadApp.egressInit" (dict "sidecar" .Values.launchpadApps.openclaw.egressSidecar) }}
*/}}
{{- define "helm-ai-kernel.launchpadApp.egressInit" -}}
{{- $s := .sidecar -}}
- name: egress-init
  image: {{ include "helm-ai-kernel.launchpadApp.image" (dict "image" $s.image) | quote }}
  imagePullPolicy: {{ $s.image.pullPolicy | default "IfNotPresent" }}
  securityContext:
    runAsNonRoot: false
    runAsUser: 0
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: false
    capabilities:
      drop:
        - ALL
      add:
        - NET_ADMIN
        - NET_RAW
  command:
    - /bin/sh
    - -c
    - |
      set -eu
      iptables -t nat -N HELM_EGRESS 2>/dev/null || iptables -t nat -F HELM_EGRESS
      # Exempt loopback, the sidecar's own egress (by uid), and DNS-over-TCP.
      iptables -t nat -A HELM_EGRESS -d 127.0.0.0/8 -j RETURN
      iptables -t nat -A HELM_EGRESS -m owner --uid-owner 65532 -j RETURN
      iptables -t nat -A HELM_EGRESS -p tcp --dport 53 -j RETURN
      # Everything else: redirect into the transparent proxy.
      iptables -t nat -A HELM_EGRESS -p tcp -j REDIRECT --to-ports {{ $s.port }}
      iptables -t nat -C OUTPUT -p tcp -j HELM_EGRESS 2>/dev/null || iptables -t nat -A OUTPUT -p tcp -j HELM_EGRESS
  resources:
    limits:
      cpu: "100m"
      memory: "32Mi"
    requests:
      cpu: "10m"
      memory: "16Mi"
{{- end -}}
