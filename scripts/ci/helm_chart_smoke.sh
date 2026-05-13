#!/usr/bin/env bash
# Validate the Kubernetes Helm chart with an actual Kubernetes Helm CLI.
#
# Use the Kubernetes Helm CLI for chart rendering. Set KUBE_HELM_CMD to an
# explicit binary, or let the script use a pinned containerized Helm runner.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART="${HELM_CHART_PATH:-deploy/helm-chart}"
RELEASE="${HELM_CHART_RELEASE:-helm-smoke}"
NAMESPACE="${HELM_CHART_NAMESPACE:-helm-smoke}"
KUBE_HELM_IMAGE="${KUBE_HELM_IMAGE:-alpine/helm:3.15.4}"
SIGNING_KEY="${HELM_CHART_SMOKE_SIGNING_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
TRUST_PUBLIC_KEY="${HELM_CHART_SMOKE_POLICY_TRUST_PUBLIC_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
ADMIN_KEY="${HELM_SMOKE_ADMIN_KEY:-helm-admin-smoke}"
SERVICE_KEY="${HELM_SMOKE_SERVICE_KEY:-helm-service-smoke}"
RENDER_DIR="${HELM_CHART_RENDER_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/helm-ai-kernel-chart.XXXXXX")}"

cleanup() {
    if [ -z "${HELM_CHART_RENDER_DIR:-}" ]; then
        rm -rf "$RENDER_DIR"
    fi
}
trap cleanup EXIT

helm_runner() {
    if [ -n "${KUBE_HELM_CMD:-}" ]; then
        "$KUBE_HELM_CMD" "$@"
        return
    fi
    if command -v kube-helm >/dev/null 2>&1; then
        kube-helm "$@"
        return
    fi
    if command -v helm >/dev/null 2>&1 && helm-ai-kernel version --short >/dev/null 2>&1 && helm template --help >/dev/null 2>&1; then
        helm "$@"
        return
    fi
    command -v docker >/dev/null 2>&1 || {
        echo "::error::Kubernetes Helm not found. Set KUBE_HELM_CMD or install docker for ${KUBE_HELM_IMAGE}."
        exit 1
    }
    docker run --rm -v "$ROOT:/work" -w /work "$KUBE_HELM_IMAGE" "$@"
}

assert_contains() {
    file="$1"
    pattern="$2"
    if ! grep -q -- "$pattern" "$file"; then
        echo "::error::rendered chart missing pattern: $pattern"
        exit 1
    fi
}

assert_not_contains() {
    file="$1"
    pattern="$2"
    if grep -q -- "$pattern" "$file"; then
        echo "::error::rendered chart unexpectedly contained pattern: $pattern"
        exit 1
    fi
}

default_rendered="$RENDER_DIR/rendered-default.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >"$default_rendered"

assert_contains "$default_rendered" "kind: Deployment"
assert_contains "$default_rendered" "HELM_POLICY_SOURCE_KIND"
assert_contains "$default_rendered" "mountedFile"
assert_contains "$default_rendered" "HELM_POLICY_SIGNATURE_REQUIRED"
assert_contains "$default_rendered" "/etc/helm-ai-kernel/policy/serve-policy.toml"
assert_contains "$default_rendered" "automountServiceAccountToken: false"
assert_not_contains "$default_rendered" "HELM_POLICY_TRUST_PUBLIC_KEY"
assert_not_contains "$default_rendered" "checksum/config"
assert_not_contains "$default_rendered" "configmap-reload"
assert_not_contains "$default_rendered" "kind: CustomResourceDefinition"
assert_not_contains "$default_rendered" "HelmPolicyBundle"
assert_not_contains "$default_rendered" "policy-reader"

fail_log="$RENDER_DIR/production-missing-key.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true >"$RENDER_DIR/production-missing-key.yaml" 2>"$fail_log"; then
    echo "::error::production render without signing key unexpectedly succeeded"
    exit 1
fi
assert_contains "$fail_log" "requires helm.signing.key"

helm_runner lint "$CHART" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >/dev/null

rendered="$RENDER_DIR/rendered.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >"$rendered"

assert_contains "$rendered" "kind: Deployment"
assert_contains "$rendered" "serve"
assert_contains "$rendered" "--policy"
assert_contains "$rendered" "/etc/helm-ai-kernel/policy/serve-policy.toml"
assert_contains "$rendered" "--data-dir"
assert_contains "$rendered" "/data"
assert_contains "$rendered" "HELM_PRODUCTION"
assert_contains "$rendered" "HELM_POLICY_SOURCE_KIND"
assert_contains "$rendered" "mountedFile"
assert_contains "$rendered" "HELM_POLICY_POLL_INTERVAL"
assert_contains "$rendered" "HELM_POLICY_SIGNATURE_REQUIRED"
assert_contains "$rendered" "/internal/policy/reconcile"
assert_contains "$rendered" "EVIDENCE_SIGNING_KEY"
assert_contains "$rendered" "HELM_ADMIN_API_KEY"
assert_contains "$rendered" "HELM_SERVICE_API_KEY"
assert_contains "$rendered" "readOnlyRootFilesystem: true"
assert_contains "$rendered" "runAsNonRoot: true"
assert_contains "$rendered" "persistentVolumeClaim:"
assert_contains "$rendered" "path: /health"
assert_contains "$rendered" "kind: Secret"
assert_contains "$rendered" "kind: ConfigMap"
assert_not_contains "$rendered" "configmap-reload"
assert_not_contains "$rendered" "kind: CustomResourceDefinition"
assert_not_contains "$rendered" "HelmPolicyBundle"
assert_not_contains "$rendered" "policy-reader"

controlplane_fail_log="$RENDER_DIR/controlplane-missing-url.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.policy.source.kind=controlplane >"$RENDER_DIR/controlplane-missing-url.yaml" 2>"$controlplane_fail_log"; then
    echo "::error::production controlplane render without URL unexpectedly succeeded"
    exit 1
fi
assert_contains "$controlplane_fail_log" "helm.policy.source.controlplane.url"

controlplane_unsigned_log="$RENDER_DIR/controlplane-missing-signature.log"
if helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.policy.source.kind=controlplane \
    --set helm.policy.source.controlplane.url=https://helm-controlplane.example.internal >"$RENDER_DIR/controlplane-missing-signature.yaml" 2>"$controlplane_unsigned_log"; then
    echo "::error::production controlplane render without required policy signatures unexpectedly succeeded"
    exit 1
fi
assert_contains "$controlplane_unsigned_log" "helm.policy.signature.required=true"

controlplane_rendered="$RENDER_DIR/rendered-controlplane.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.policy.source.kind=controlplane \
    --set helm.policy.source.controlplane.url=https://helm-controlplane.example.internal \
    --set helm.policy.signature.required=true \
    --set helm.policy.signature.publicKey="$TRUST_PUBLIC_KEY" \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >"$controlplane_rendered"

assert_contains "$controlplane_rendered" "HELM_POLICY_SOURCE_KIND"
assert_contains "$controlplane_rendered" "controlplane"
assert_contains "$controlplane_rendered" "HELM_POLICY_CONTROLPLANE_URL"
assert_contains "$controlplane_rendered" "https://helm-controlplane.example.internal"
assert_contains "$controlplane_rendered" "HELM_POLICY_SIGNATURE_REQUIRED"
assert_contains "$controlplane_rendered" "HELM_POLICY_TRUST_PUBLIC_KEY"
assert_not_contains "$controlplane_rendered" "configmap-reload"
assert_not_contains "$controlplane_rendered" "kind: CustomResourceDefinition"
assert_not_contains "$controlplane_rendered" "policy-reader"

crd_rendered="$RENDER_DIR/rendered-crd.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set helm.policy.source.kind=crd \
    --set helm.policy.source.crd.install=true \
    --set image.repository=ghcr.io/mindburn-labs/helm-ai-kernel \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >"$crd_rendered"

assert_contains "$crd_rendered" "kind: CustomResourceDefinition"
assert_contains "$crd_rendered" "HelmPolicyBundle"
assert_contains "$crd_rendered" "kind: Role"
assert_contains "$crd_rendered" "helmpolicybundles"
assert_contains "$crd_rendered" "automountServiceAccountToken: true"

echo "helm chart smoke passed"
