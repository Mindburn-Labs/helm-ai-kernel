---
title: Kubernetes Deployment
last_reviewed: 2026-07-10
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

## Staging Install Skeleton

Use existing Kubernetes Secrets for any sensitive values. Do not put real keys
in shell history or public issues.

```bash
kubectl create secret generic helm-auth \
  --from-literal=HELM_ADMIN_API_KEY='<local-test-admin-key>' \
  --from-literal=HELM_SERVICE_API_KEY='<local-test-service-key>'

kubectl create secret generic helm-upstream \
  --from-literal=HELM_UPSTREAM_API_KEY='<local-test-provider-key>'

helm upgrade --install helm-ai-kernel deploy/helm-chart \
  --set helm.auth.existingSecret=helm-auth \
  --set helm.proxy.enabled=true \
  --set helm.proxy.upstream=https://api.openai.com/v1 \
  --set helm.proxy.existingSecret=helm-upstream \
  --set persistence.enabled=true
```

The upstream Secret is intentionally distinct from `helm-auth`: the runtime
uses it only for the provider request and never forwards its admin bearer
upstream.

## Values That Control Runtime Behavior

| Value | Default | Source-backed behavior |
| --- | --- | --- |
| `image.repository` | `ghcr.io/mindburn-labs/helm-ai-kernel` | Container image used by the Deployment. |
| `image.tag` | chart `appVersion` | The source target is `v0.7.2` from `Chart.yaml`. It is not a published image until the tag-driven release workflow publishes and verifies it; use only a source-owned image tag (or local override) you can verify. |
| `helm.bindAddr` | `0.0.0.0` | Required because the pod must bind beyond loopback. |
| `service.port` | `8080` | Runtime HTTP port passed to `helm-ai-kernel serve --port`. |
| `service.healthPort` | `8081` | Health probe port via `HELM_HEALTH_PORT`. |
| `helm.dataDir` | `/data` | Mounted from the chart PVC or `emptyDir`. |
| `helm.proxy.enabled` | `false` | Opts into provider forwarding and requires `helm.proxy.upstream` plus a distinct `helm.proxy.existingSecret`. |
| `helm.proxy.existingSecret` | empty | Existing Secret containing the server-owned `HELM_UPSTREAM_API_KEY`. |
| `helm.storage.type` | `sqlite` | Uses local SQLite unless another supported store is configured. |
| `persistence.enabled` | `true` | Creates or reuses a PVC for receipts, state, and artifacts. |
| `ingress.enabled` | `false` | Optional ingress; provide TLS and ingress class explicitly. |

## Smoke Checks

```bash
kubectl rollout status deploy/helm-ai-kernel
kubectl port-forward svc/helm-ai-kernel 8080:8080
curl -fsS http://127.0.0.1:8080/health
```

Then run a governed request through the public API or, when explicitly
configured with an upstream Secret, the OpenAI-compatible route. Verify that
receipts persist after pod restart when `persistence.enabled` is true.

## Not Covered

Managed deployments, tenant migrations, SSO, SIEM, retention controls, private
control-plane wiring, and operator key ceremonies belong outside the anonymous
public Kernel docs.
