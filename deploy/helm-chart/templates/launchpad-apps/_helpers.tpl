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
Hermes command renderer.
Defaults stay mode-specific: Job runs the promoted single-query smoke path;
Deployment runs the long-lived gateway process. commandOverride replaces the
entire command array for operators with provider-specific runtime evidence.
*/}}
{{- define "helm-ai-kernel.launchpadApp.hermesCommand" -}}
{{- $cfg := .cfg -}}
{{- $mode := .mode -}}
{{- if $cfg.commandOverride -}}
{{- toYaml $cfg.commandOverride -}}
{{- else if eq $mode "deployment" -}}
- "/bin/sh"
- "-c"
- "HOME=/var/lib/hermes exec hermes --gateway"
{{- else -}}
{{- $query := $cfg.query | default "ping" -}}
{{- $provider := $cfg.provider | default "openrouter" -}}
{{- $model := $cfg.model | default "openai/gpt-6-luna" -}}
{{- $shellCommand := printf "HOME=/var/lib/hermes hermes --q %s --provider %s --model %s --ignore_user_config --quiet" ($query | quote) ($provider | quote) ($model | quote) -}}
- "/bin/sh"
- "-c"
- {{ $shellCommand | quote }}
{{- end -}}
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
    seccompProfile:
      type: RuntimeDefault
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
egress-proxy image (which ships iptables and ip6tables). Rules, for the whole Pod:
- TCP/IPv4: redirected to the proxy, except loopback, the sidecar's own uid
  (65532), and TCP/53 to the Pod's nameservers (the cluster DNS in resolv.conf).
- Other IPv4 protocols (UDP, ICMP, ...): rejected, except loopback and UDP/53 to
  those nameservers, so the workload and the sidecar can still resolve names.
- IPv6: rejected except loopback. The proxy recovers IPv4 original destinations
  only, so IPv6 egress would bypass it.
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
    # RuntimeDefault does not break the iptables install: runc's default seccomp
    # profile admits the netfilter syscalls once CAP_NET_ADMIN is granted.
    seccompProfile:
      type: RuntimeDefault
  command:
    - /bin/sh
    - -c
    - |
      set -eu
      # Cluster DNS: the IPv4 nameservers kubelet wrote into this Pod's resolv.conf.
      dns="$(awk '$1 == "nameserver" && $2 !~ /:/ {print $2}' /etc/resolv.conf)"
      iptables -t nat -N HELM_EGRESS 2>/dev/null || iptables -t nat -F HELM_EGRESS
      # Exempt loopback, the sidecar's own egress (by uid), and DNS-over-TCP to cluster DNS only.
      iptables -t nat -A HELM_EGRESS -d 127.0.0.0/8 -j RETURN
      iptables -t nat -A HELM_EGRESS -m owner --uid-owner 65532 -j RETURN
      for ns in $dns; do
        iptables -t nat -A HELM_EGRESS -p tcp -d "$ns" --dport 53 -j RETURN
      done
      # Everything else: redirect into the transparent proxy.
      iptables -t nat -A HELM_EGRESS -p tcp -j REDIRECT --to-ports {{ $s.port }}
      iptables -t nat -C OUTPUT -p tcp -j HELM_EGRESS 2>/dev/null || iptables -t nat -A OUTPUT -p tcp -j HELM_EGRESS
      # Non-TCP IPv4 never reaches the proxy, so reject it outright; only
      # DNS-over-UDP to cluster DNS remains.
      iptables -N HELM_EGRESS 2>/dev/null || iptables -F HELM_EGRESS
      iptables -A HELM_EGRESS -o lo -j RETURN
      iptables -A HELM_EGRESS -p tcp -j RETURN
      for ns in $dns; do
        iptables -A HELM_EGRESS -p udp -d "$ns" --dport 53 -j RETURN
      done
      iptables -A HELM_EGRESS -j REJECT
      iptables -C OUTPUT -j HELM_EGRESS 2>/dev/null || iptables -A OUTPUT -j HELM_EGRESS
      # IPv6 would bypass the IPv4-only redirect: reject all of it but loopback.
      # Without kernel IPv6 support there is no IPv6 egress to close.
      if [ -e /proc/net/if_inet6 ]; then
        ip6tables -N HELM_EGRESS 2>/dev/null || ip6tables -F HELM_EGRESS
        ip6tables -A HELM_EGRESS -o lo -j RETURN
        ip6tables -A HELM_EGRESS -j REJECT
        ip6tables -C OUTPUT -j HELM_EGRESS 2>/dev/null || ip6tables -A OUTPUT -j HELM_EGRESS
      fi
  resources:
    limits:
      cpu: "100m"
      memory: "32Mi"
    requests:
      cpu: "10m"
      memory: "16Mi"
{{- end -}}
