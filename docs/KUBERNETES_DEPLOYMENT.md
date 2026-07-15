---
title: Kubernetes Deployment
last_reviewed: 2026-07-15
---

# Kubernetes Deployment

This page documents the repository-owned HELM AI Kernel chart for self-hosted
evaluation and staging smoke tests. It is not a managed-service runbook and it
does not publish tenant, control-plane, signing, or operator-secret procedures.

## Audience

Kubernetes operators who need to render the chart, understand the Kernel
runtime boundary, and run a staging smoke path for health, receipts, and
evidence persistence.

## Outcome

After this page you should be able to lint the chart, render manifests, install
a staging release with local test material, and verify that health and receipt
persistence behave as expected.

## Source Truth

The chart source is `deploy/helm-chart`. Runtime container wiring is in
`deploy/helm-chart/templates/deployment.yaml`; values are in
`deploy/helm-chart/values.yaml`.

## Validate The Chart

```bash
make helm-chart-smoke
helm lint deploy/helm-chart
helm template helm-ai-kernel deploy/helm-chart
```

Expected output: lint succeeds, `helm template` emits Deployment, Service,
ConfigMap, Secret, PVC, and optional ServiceMonitor manifests, and
`make helm-chart-smoke` completes without rendering a protected chart that lacks
required local test material.

## Policy Authority Boundary

Kubernetes objects do not become HELM execution authority. The chart deploys the
runtime and configures a `policy.source` backend. The runtime reconciler owns
policy truth: it reads the active head, loads the canonical bundle, verifies the
expected hash and signature/provenance, compiles a snapshot, validates it, then
atomically swaps the per-scope `EffectivePolicySnapshot`.

## Local Signing Authority Boundary

The signing Secret is mounted only into the digest-pinned,
root-only `prepare-authority-state` init container. Before the non-root kernel
starts, it sets `helm.dataDir` to exact `0700` and the configured
`podSecurityContext.runAsUser`/`runAsGroup`, then copies the secret seed to a
regular `root.key` with exact `0600` and the same owner. The kernel container
receives the data volume, not a signing-key Secret `subPath`.

If a durable `root.key` exists, it must match the signing Secret. A mismatch
fails closed instead of silently changing receipt-signing authority. Treat a
key change as an explicit operator migration; do not rely on `fsGroup`, a live
Secret update, or broader directory permissions to repair startup.

## Staging Install Skeleton

Use existing Kubernetes Secrets for any sensitive values. Do not put real keys
in shell history or public issues.

```bash
kubectl create secret generic helm-auth \
  --from-literal=HELM_ADMIN_API_KEY='<local-test-admin-key>' \
  --from-literal=HELM_SERVICE_API_KEY='<local-test-service-key>'

helm upgrade --install helm-ai-kernel deploy/helm-chart \
  --set helm.auth.existingSecret=helm-auth \
  --set persistence.enabled=true
```

## Values That Control Runtime Behavior

| Value | Default | Source-backed behavior |
| --- | --- | --- |
| `image.repository` | `ghcr.io/mindburn-labs/helm-ai-kernel` | Container image used by the Deployment. |
| `image.tag` | chart `appVersion` | The source target is `v0.7.2` from `Chart.yaml`. It is not a published image until the tag-driven release workflow publishes and verifies it; use only a source-owned image tag (or local override) you can verify. |
| `helm.bindAddr` | `0.0.0.0` | Required because the pod must bind beyond loopback. |
| `service.port` | `8080` | Runtime HTTP port passed to `helm-ai-kernel serve --port`. |
| `service.healthPort` | `8081` | Health probe port via `HELM_HEALTH_PORT`. |
| `helm.dataDir` | `/data` | Mounted from the chart PVC or `emptyDir`; the authority-state initializer makes it runtime-owned and exact-mode private. |
| `runtimeInit.image` | digest-pinned Alpine Helm image | Root-only init image that materializes the private root key before the kernel starts. |
| `helm.proxy.enabled` | `true` | Sets `HELM_ENABLE_OPENAI_PROXY=1` and `HELM_UPSTREAM_URL`. |
| `helm.storage.type` | `sqlite` | Uses local SQLite unless another supported store is configured. |
| `persistence.enabled` | `true` | Creates or reuses a PVC for receipts, state, and artifacts. |
| `ingress.enabled` | `false` | Optional ingress; provide TLS and ingress class explicitly. |

## Smoke Checks

```bash
kubectl rollout status deploy/helm-ai-kernel
kubectl port-forward svc/helm-ai-kernel 8080:8080
curl -fsS http://127.0.0.1:8080/health
```

Then run a governed request through the public API or OpenAI-compatible proxy
and verify that receipts persist after pod restart when `persistence.enabled`
is true.

For a failed startup, collect the initializer evidence before changing any
volume permissions:

```bash
kubectl get pods -l app.kubernetes.io/instance=helm-ai-kernel
kubectl describe pod <kernel-pod>
kubectl logs <kernel-pod> -c prepare-authority-state
kubectl logs <kernel-pod> -c helm-ai-kernel
```

## Not Covered

Managed deployments, tenant migrations, SSO, SIEM, retention controls, private
control-plane wiring, and operator key ceremonies belong outside the anonymous
public Kernel docs.
