---
title: Launchpad Kubernetes Smoke
last_reviewed: 2026-05-27
---

# Launchpad Kubernetes Smoke

Status: minikube-only first iteration. Generic-cluster mode (vanilla k8s,
EKS, GKE, bare-metal) is tracked as a follow-up.

## Audience

Operators validating that openclaw and hermes deploy cleanly on a real
Kubernetes substrate, that the kernel still rolls out next to them, and
that the bundle tears down without leaks.

## Outcome

You can install the `helm-ai-kernel` chart with `launchpadApps.openclaw`
and `launchpadApps.hermes` enabled, see the openclaw Pod reach Ready and
the hermes Job reach Complete, run `helm test` to confirm kernel health and
launchpad connectivity, and uninstall with no residual resources.

## Topology

This is a **co-deployment** path. openclaw and hermes are pinned chart-
managed Pods that mirror the local-container runbook on a Kubernetes
substrate. The kernel does not launch them via the Kubernetes API in
this topology — there is no `kubernetes` substrate behind these Pods.
The launchpad runtime substrate work is tracked separately under
`launchpad-k8s-minikube-integration-finish` and is not required for this
smoke.

```
Namespace: helm-launchpad-smoke
+---------------------------------------------------------+
| Pod kernel  ──── Service kernel:8080 (clusterIP)        |
|                                                         |
| Pod openclaw                                            |
|   container openclaw       loopback gateway :18789      |
|   container egress-proxy   :8080 → openrouter.ai        |
|   emptyDir tmpfs /tmp, emptyDir /opt/openclaw/.openclaw |
|                                                         |
| Pod hermes (Job, short-lived)                           |
|   container hermes         single `--q ping`            |
|   container egress-proxy   :8080 → openrouter.ai        |
|   emptyDir tmpfs /tmp, emptyDir /var/lib/hermes         |
|                                                         |
| NetworkPolicy launchpad-apps                            |
|   egress: kube-dns + TCP/443 outside cluster CIDRs      |
+---------------------------------------------------------+
```

OpenClaw's gateway binds to `loopback` per
`registry/launchpad/apps/openclaw.yaml` — the same posture used in the
local-container runbook. Smoke reaches the gateway through `kubectl
exec`, not through a Service.

Egress is **enforced transparently**, not honor-based. An `egress-init`
container (`CAP_NET_ADMIN`) installs an iptables `REDIRECT` that funnels
every outbound TCP connection from the workload into the egress proxy
sidecar; a direct connection cannot bypass it. The sidecar recovers the
original destination via `SO_ORIGINAL_DST` (and the hostname via TLS SNI,
best-effort), enforces the per-app allowlist
(`https://openrouter.ai/api/v1`), and writes a receipt for **every**
attempt — allow and deny. The workload needs no `HTTP_PROXY` env.

Caveats — what this does **not** cover: SNI is best-effort (TLS 1.3 ECH,
non-TLS, or IP-literal traffic yields a receipt keyed by IP rather than
hostname); only TCP egress is intercepted, so DNS/UDP/ICMP are out of
scope (DNS-tunnel exfiltration is a separate control). The honest claim
is "every **TCP** egress goes through the sidecar and leaves a receipt".

## Source Truth

- Chart values: `deploy/helm-chart/values.yaml` (`launchpadApps.openclaw`, `launchpadApps.hermes`)
- Chart schema: `deploy/helm-chart/values.schema.json`
- Chart templates: `deploy/helm-chart/templates/launchpad-apps/`
- Helm test Pod: `deploy/helm-chart/templates/tests/launchpad-connectivity.yaml`
- Smoke driver: `scripts/ci/launchpad_k8s_smoke.sh`
- Workflow: `.github/workflows/helm-integration.yml`
- AppSpec ground truth: `registry/launchpad/apps/openclaw.yaml`, `registry/launchpad/apps/hermes.yaml`
- Standalone runbooks the k8s topology mirrors: `my-docs/daily/26-may/launchpad-openclaw-end-to-end-pass.md`, `my-docs/daily/26-may/launchpad-hermes-smoke.md`

## Conformance map

| AppSpec field | k8s mapping |
| --- | --- |
| `install.image` + `install.digest` | `launchpadApps.<app>.image.{repository,digest}` |
| `runtime.command` | container `command` (Deployment for openclaw, Job for hermes) |
| `runtime.timeout` | `Job.spec.activeDeadlineSeconds` (hermes); Deployment liveness probe failureThreshold × periodSeconds (openclaw) |
| `model_gateway_env` + `required_secrets.model_gateway` | Secret reference via `openrouter.apiKeySecretRef`; key injected as `OPENROUTER_API_KEY` env |
| `filesystem_policy.mounts: workspace:rw` | not modeled in this smoke (no kernel-owned workspace materializer yet) |
| `filesystem_policy.mounts: app_state:rw:<target>` | `emptyDir` volume at the target path inside the Pod |
| `network_policy.default: deny` + `allowlist` | `egress-init` iptables REDIRECT → transparent egress proxy enforcing `HELM_EGRESS_ALLOWLIST` (primary); NetworkPolicy object (defense-in-depth second layer) |
| `healthchecks: helm-launchpad-openrouter-check` | Pod `readinessProbe.exec` (openclaw); single Job run with same script invoked by hermes `--q ping` — both reach OpenRouter via transparent intercept, no proxy env needed |
| `mcp_policy.*` | not enforced at the chart level; same as local-container (kernel-side concern) |

## Quick start

```bash
# Build kernel image and load into minikube docker daemon
eval "$(minikube docker-env)"
docker build -t ghcr.io/mindburn-labs/helm-ai-kernel:smoke -f Dockerfile .

# Real-key positive scenario
export GHCR_USERNAME=<github-user>
export GHCR_TOKEN=<github-token-with-read-packages>
export OPENROUTER_API_KEY=<your-key>
bash scripts/ci/launchpad_k8s_smoke.sh --mode positive

# Fake-key negative scenario
unset OPENROUTER_API_KEY
bash scripts/ci/launchpad_k8s_smoke.sh --mode negative

# Chart-only baseline (no launchpad apps)
bash scripts/ci/launchpad_k8s_smoke.sh --mode baseline
```

The driver always starts from a fresh minikube cluster (`minikube delete`
then `minikube start`). Set `LAUNCHPAD_SMOKE_KEEP_CLUSTER=1` to skip the
final delete during iteration.

For `positive` and `negative`, the launchpad app images stay pinned as
`repo@sha256` and are pulled by kubelet from GHCR through a docker-registry
Secret named `ghcr-read` by default. Provide `GHCR_USERNAME` and `GHCR_TOKEN`
(`read:packages`) before running those modes. Do not rely on `minikube image
load` for private digest refs; `LAUNCHPAD_SMOKE_PRE_LOAD_LAUNCHPAD_IMAGES=1`
exists only as a debug path and fails if the digest is not resolvable inside
the minikube node.

## Scenario matrix

| Mode | Setup | Expected outcome |
| --- | --- | --- |
| `baseline` | `launchpadApps.openclaw.enabled=false`, `launchpadApps.hermes.enabled=false` (defaults) | kernel Deployment rolls out, baseline `helm test` PASS, no launchpad-app Pods rendered |
| `positive` | both apps enabled, Secret `openrouter-key` holds a real OpenRouter key | openclaw Pod Ready within ~6m; hermes Job Complete within ~3m; `helm test` PASS; openclaw `kubectl exec helm-launchpad-openrouter-check` exits 0 |
| `negative` | both apps enabled, Secret holds `sk-fake-…` | openclaw Pod fails to reach Ready within 90s; hermes Job reaches Failed within ~3m |

After every scenario the driver runs `helm uninstall` and asserts that
no resources labelled `app.kubernetes.io/part-of=helm-ai-kernel` remain
on the cluster — the k8s analogue of the docker sandbox-leak audit.

## Known limitations

- **Optional image architecture pinning.** The default chart-pinned openclaw,
  hermes, and egress-proxy digests are multi-arch
  `linux/amd64,linux/arm64` manifests. The chart leaves
  `launchpadApps.nodeSelector` empty by default; operators can set it
  explicitly when they need architecture or node pool pinning.
- **CNI enforcement.** The NetworkPolicy object is created
  unconditionally, but enforcement requires a CNI that honors it. The
  smoke driver opts minikube into Calico (`--cni=calico`). On the
  default kindnet CNI the object is recorded but not enforced — useful
  as a positive control, not as proof of isolation.
- **No prompt round-trip.** This smoke validates Pod liveness, the
  OpenRouter healthcheck script, and Job completion. End-to-end
  assistant behaviour (real prompts, MCP runtime quarantine, persistent
  app_state across launches) is tracked under
  `openclaw-extended-functional-coverage` in the working notebook.
- **Compose differential check is out of scope.** The compose-side
  smoke remains a manual runbook in `my-docs/daily/26-may/`. Once it is
  automated, a byte-for-byte receipt comparison with this k8s smoke
  becomes the next conformance gate.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| `ErrImagePull` / `ImagePullBackOff` on openclaw, hermes, or egress-proxy | Confirm Secret `ghcr-read` exists in the release namespace and that `GHCR_TOKEN` has `read:packages` for `ghcr.io/mindburn-labs/helm-launchpad/*`. |
| openclaw Pod never reaches Ready on positive | `kubectl logs <pod> -c egress-proxy`, then `kubectl logs <pod> -c openclaw`. Common causes: missing `OPENROUTER_API_KEY`, OpenRouter rate-limit, private GHCR pull-secret failure, or kernel pulling images on a slow link. |
| hermes Job hangs at Running | `shareProcessNamespace` and the workload's `preStop` SIGTERM are how the sidecar exits. If the sidecar image changes its process name from `egress-proxy`, the `pkill` pattern in `hermes-job.yaml` needs updating. |
| Leftover resources after uninstall | The leak audit query `kubectl get all -A -l app.kubernetes.io/part-of=helm-ai-kernel`. Any non-empty result means something other than helm owns the resource — start with `kubectl describe` to see ownerReferences. |
| `helm test` reports `no hooks for test`  | The baseline kernel health hook should always render. Check that `deploy/helm-chart/templates/tests/test-connection.yaml` is present and the chart was installed from the expected revision. |
