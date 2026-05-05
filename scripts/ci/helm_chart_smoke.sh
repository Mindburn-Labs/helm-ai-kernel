#!/usr/bin/env bash
# Validate the Kubernetes Helm chart with an actual Kubernetes Helm CLI.
#
# The repository's own CLI is named `helm`, so this script deliberately avoids
# trusting PATH. Set KUBE_HELM_CMD to an explicit Kubernetes Helm binary, or let
# the script use a pinned containerized Helm runner.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART="${HELM_CHART_PATH:-deploy/helm-chart}"
RELEASE="${HELM_CHART_RELEASE:-helm-smoke}"
NAMESPACE="${HELM_CHART_NAMESPACE:-helm-smoke}"
KUBE_HELM_IMAGE="${KUBE_HELM_IMAGE:-alpine/helm:3.15.4}"
SIGNING_KEY="${HELM_CHART_SMOKE_SIGNING_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
ADMIN_KEY="${HELM_SMOKE_ADMIN_KEY:-helm-admin-smoke}"
SERVICE_KEY="${HELM_SMOKE_SERVICE_KEY:-helm-service-smoke}"
RENDER_DIR="${HELM_CHART_RENDER_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/helm-oss-chart.XXXXXX")}"

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
    if command -v helm >/dev/null 2>&1 && helm version --short >/dev/null 2>&1 && helm template --help >/dev/null 2>&1; then
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
    --set image.repository=ghcr.io/mindburn-labs/helm-oss \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >/dev/null

rendered="$RENDER_DIR/rendered.yaml"
helm_runner template "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set helm.production=true \
    --set helm.signing.key="$SIGNING_KEY" \
    --set helm.auth.adminAPIKey="$ADMIN_KEY" \
    --set helm.auth.serviceAPIKey="$SERVICE_KEY" \
    --set image.repository=ghcr.io/mindburn-labs/helm-oss \
    --set image.tag=local \
    --set image.pullPolicy=IfNotPresent >"$rendered"

assert_contains "$rendered" "kind: Deployment"
assert_contains "$rendered" "serve"
assert_contains "$rendered" "--policy"
assert_contains "$rendered" "/etc/helm/policy/serve-policy.toml"
assert_contains "$rendered" "--data-dir"
assert_contains "$rendered" "/data"
assert_contains "$rendered" "HELM_PRODUCTION"
assert_contains "$rendered" "EVIDENCE_SIGNING_KEY"
assert_contains "$rendered" "HELM_ADMIN_API_KEY"
assert_contains "$rendered" "HELM_SERVICE_API_KEY"
assert_contains "$rendered" "readOnlyRootFilesystem: true"
assert_contains "$rendered" "runAsNonRoot: true"
assert_contains "$rendered" "persistentVolumeClaim:"
assert_contains "$rendered" "path: /health"
assert_contains "$rendered" "kind: Secret"
assert_contains "$rendered" "kind: ConfigMap"

echo "helm chart smoke passed"
