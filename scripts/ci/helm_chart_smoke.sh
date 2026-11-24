#!/usr/bin/env bash
# Validate the Kubernetes Helm chart with an actual Kubernetes Helm CLI.
#
# Use the Kubernetes Helm CLI for chart rendering. Set KUBE_HELM_CMD to an
# explicit binary, or let the script use a pinned containerized Helm runner.
#
# quantum_posture: renders and inspects chart wiring for classical Ed25519
# keys (the kernel command keyring, the gateway receipt seed); it signs and
# verifies nothing and makes no post-quantum claim.
# shellcheck source-path=SCRIPTDIR/helm_chart_smoke
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART="${HELM_CHART_PATH:-deploy/helm-chart}"
RELEASE="${HELM_CHART_RELEASE:-helm-smoke}"
NAMESPACE="${HELM_CHART_NAMESPACE:-helm-smoke}"
KUBE_HELM_IMAGE="${KUBE_HELM_IMAGE:-docker.io/alpine/helm@sha256:105741fa6621ed9a3ea944066de78bb27d4b9bb93a56ce8e7cb4d621e1e4bbf2}"
SIGNING_KEY="${HELM_CHART_SMOKE_SIGNING_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
TRUST_PUBLIC_KEY="${HELM_CHART_SMOKE_POLICY_TRUST_PUBLIC_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
# The kernel refuses the published literals, so each run generates its own keys.
ADMIN_KEY="${HELM_SMOKE_ADMIN_KEY:-$(openssl rand -hex 24)}"
SERVICE_KEY="${HELM_SMOKE_SERVICE_KEY:-$(openssl rand -hex 24)}"
TENANT_ID="${HELM_SMOKE_TENANT_ID:-tenant-smoke}"
AGENT_ID="${HELM_SMOKE_AGENT_ID:-agent.smoke}"
PRODUCTION_IMAGE_DIGEST="${HELM_CHART_SMOKE_IMAGE_DIGEST:-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
REPLAY_KEYRING='{"keyring_version":"emergency-stop-fence-command-replay-keyring.v1","keys":[{"command_key_id":"cp-stop-before-rotation","command_audience":"kernel-before-rotation","command_public_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}'
RENDER_DIR="${HELM_CHART_RENDER_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/helm-ai-kernel-chart.XXXXXX")}"

cleanup() {
    if [ -z "${HELM_CHART_RENDER_DIR:-}" ]; then
        rm -rf "$RENDER_DIR"
    fi
}
trap cleanup EXIT

require_pinned_helm_image() {
    if [[ ! "$KUBE_HELM_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]]; then
        echo "::error::KUBE_HELM_IMAGE must be pinned by immutable sha256 digest, got: ${KUBE_HELM_IMAGE}"
        exit 1
    fi
}

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
    require_pinned_helm_image
    docker run --rm -v "$ROOT:/work" -w /work "$KUBE_HELM_IMAGE" "$@"
}

# These assertions check literal strings from the rendered chart, so both
# helpers match fixed strings. Without -F, grep reads the pattern as a BRE and
# `.` matches any character: `helm.sh/hook-delete-policy` would also accept
# `helmXsh/...`, which is a test that can pass on the wrong output.
assert_contains() {
    file="$1"
    pattern="$2"
    if ! grep -qF -- "$pattern" "$file"; then
        echo "::error::rendered chart missing pattern: $pattern"
        exit 1
    fi
}

assert_not_contains() {
    file="$1"
    pattern="$2"
    if grep -qF -- "$pattern" "$file"; then
        echo "::error::rendered chart unexpectedly contained pattern: $pattern"
        exit 1
    fi
}

# Helm versions report JSON-schema locations either as dotted keys or JSON
# pointers. Both must identify the exact field in the failed render.
assert_schema_path() {
    file="$1"
    path="$2"
    pointer="/${path//./\/}"
    if ! grep -qF -- "$path" "$file" && ! grep -qF -- "$pointer" "$file"; then
        echo "::error::schema refusal did not identify $path"
        cat "$file"
        exit 1
    fi
}

PRODUCTION_NETWORK_POLICY_VALUES="scripts/ci/helm_production_network_policy_values.yaml"

production_helm_runner() {
    helm_runner "$@" \
        --values "$PRODUCTION_NETWORK_POLICY_VALUES" \
        --set image.digest="$PRODUCTION_IMAGE_DIGEST"
}

production_controlplane_helm_runner() {
    production_helm_runner "$@" \
        --set helm.policy.source.kind=controlplane \
        --set helm.policy.source.controlplane.url=https://helm-controlplane.example.internal \
        --set helm.policy.source.controlplane.tls.existingSecret=helm-policy-controlplane-ca \
        --set helm.policy.signature.required=true \
        --set helm.policy.signature.publicKey="$TRUST_PUBLIC_KEY"
}

SCENARIO_DIR="$ROOT/scripts/ci/helm_chart_smoke"

source "$SCENARIO_DIR/runtime.sh"
source "$SCENARIO_DIR/production.sh"
source "$SCENARIO_DIR/policy_sources.sh"
source "$SCENARIO_DIR/api_authentication.sh"
source "$SCENARIO_DIR/gateway.sh"
# The gateway episode and serving scenarios reuse the fixtures above.
source "$SCENARIO_DIR/gateway_episode_services.sh"
source "$SCENARIO_DIR/gateway_serving_image.sh"

echo "helm chart smoke passed"
