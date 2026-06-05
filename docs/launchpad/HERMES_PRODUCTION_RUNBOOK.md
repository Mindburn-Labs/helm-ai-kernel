# Hermes Production Proof Runbook

This runbook produces the first Mindburn-owned production proof for Hermes on
HELM. It uses the existing `hermes-mindburn` VPS, explicit live mode,
OpenRouter-only model access, a launch-scoped egress proxy, teardown, and a
team-grade sealed EvidencePack.

## Claim boundary

- Claim: Hermes ran through HELM's fail-closed boundary in a Mindburn-owned
  production environment, with receipts, teardown, sealed EvidencePack, and
  offline verification.
- Do not claim: customer-grade or high-assurance proof. Those require an
  external signer, external anchor, and immutable off-host storage receipt.
- Never use default `auto` mode for this proof. Use `--live`.
- Rotate any exposed provider key before starting this runbook.

## Prerequisites

- SSH alias `hermes-mindburn` reaches the VPS with key-only auth and strict
  host-key checking.
- Docker is running on the VPS.
- `gh`, `jq`, `sha256sum`, `curl`, and `cosign` are available on the VPS.
- `OPENROUTER_API_KEY` is set in the shell that starts the launch.

## Install verified HELM

```bash
set -euo pipefail

export HELM_VERSION=v0.5.10
export HELM_ARCH=linux-amd64
export HELM_RELEASE_URL="https://github.com/Mindburn-Labs/helm-ai-kernel/releases/download/${HELM_VERSION}"
mkdir -p "$HOME/.local/bin" "$HOME/.cache/helm-ai-kernel/${HELM_VERSION}"
cd "$HOME/.cache/helm-ai-kernel/${HELM_VERSION}"

curl -fsSLO "${HELM_RELEASE_URL}/helm-ai-kernel-${HELM_ARCH}"
curl -fsSLO "${HELM_RELEASE_URL}/helm-ai-kernel-${HELM_ARCH}.cosign.bundle"
curl -fsSLO "${HELM_RELEASE_URL}/SHA256SUMS.txt"
curl -fsSLO "${HELM_RELEASE_URL}/SHA256SUMS.txt.cosign.bundle"

cosign verify-blob \
  --bundle "helm-ai-kernel-${HELM_ARCH}.cosign.bundle" \
  --certificate-identity-regexp "https://github.com/Mindburn-Labs/helm-ai-kernel" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "helm-ai-kernel-${HELM_ARCH}"
cosign verify-blob \
  --bundle SHA256SUMS.txt.cosign.bundle \
  --certificate-identity-regexp "https://github.com/Mindburn-Labs/helm-ai-kernel" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt
grep "helm-ai-kernel-${HELM_ARCH}$" SHA256SUMS.txt | sha256sum -c -
install -m 0755 "helm-ai-kernel-${HELM_ARCH}" "$HOME/.local/bin/helm-ai-kernel"

"$HOME/.local/bin/helm-ai-kernel" version
```

The version output must report `v0.5.10`.

## Select registry root

Use the reviewed source revision that contains the OpenRouter-only Hermes
AppSpec until that AppSpec is included in the next release artifact bundle.

```bash
set -euo pipefail

export HELM_SOURCE_REF=codex/hermes-production-proof
export HELM_SOURCE_ROOT="$HOME/src/helm-ai-kernel-hermes-production-proof"
mkdir -p "$HOME/src"

if [ -d "$HELM_SOURCE_ROOT/.git" ]; then
  git -C "$HELM_SOURCE_ROOT" fetch origin "$HELM_SOURCE_REF" --depth 1
  git -C "$HELM_SOURCE_ROOT" checkout -q "$HELM_SOURCE_REF"
  git -C "$HELM_SOURCE_ROOT" reset --hard -q "origin/$HELM_SOURCE_REF"
else
  git clone --depth 1 --branch "$HELM_SOURCE_REF" \
    https://github.com/Mindburn-Labs/helm-ai-kernel.git \
    "$HELM_SOURCE_ROOT"
fi

export HELM_LAUNCHPAD_REGISTRY_ROOT="$HELM_SOURCE_ROOT"
grep -A4 '^model_gateway:' \
  "$HELM_LAUNCHPAD_REGISTRY_ROOT/registry/launchpad/apps/hermes.yaml"
grep -A4 '^model_gateway:' \
  "$HELM_LAUNCHPAD_REGISTRY_ROOT/registry/launchpad/apps/hermes.yaml" |
  grep -q 'openrouter'

helm-ai-kernel up hermes --target local --verify-only --json --no-open |
  jq -e '
    .mode == "verify-only" and
    .started_runtime == false and
    .plan.kernel_verdict == "ALLOW" and
    .plan.model_gateway_env == ["OPENROUTER_API_KEY"] and
    (.plan.network_allowlist | sort) ==
      (["https://api.openrouter.ai/api/v1", "https://openrouter.ai/api/v1"] | sort)
  '
```

## Configure proof state

```bash
set -euo pipefail

export HELM_LAUNCHPAD_HOME="$HOME/.helm/launchpad-production"
export HELM_LAUNCHPAD_REGISTRY_ROOT="$HELM_SOURCE_ROOT"
mkdir -p "$HELM_LAUNCHPAD_HOME"
chmod 700 "$HELM_LAUNCHPAD_HOME"

helm-ai-kernel evidence trust init \
  --profile team \
  --signer file-dev \
  --anchor local-dev \
  --store local-dev \
  --data-dir "$HELM_LAUNCHPAD_HOME"

test -n "${OPENROUTER_API_KEY:-}"
helm-ai-kernel launch secrets set model_gateway \
  --provider openrouter \
  --value-env OPENROUTER_API_KEY

helm-ai-kernel launch secrets status
```

Secret status must show `model_gateway/openrouter` as available. The key value
must never be printed or copied into files.

## Resolve the egress proxy image

```bash
set -euo pipefail

export HELM_LAUNCHPAD_ARTIFACT_RUN_ID=26198407296
mkdir -p "$HELM_LAUNCHPAD_HOME/artifact-manifest"
gh run download "$HELM_LAUNCHPAD_ARTIFACT_RUN_ID" \
  --repo Mindburn-Labs/helm-ai-kernel \
  -n launchpad-artifact-manifest \
  -D "$HELM_LAUNCHPAD_HOME/artifact-manifest"

export HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE="$(
  jq -r '.egress_proxy.image // empty' \
    "$HELM_LAUNCHPAD_HOME/artifact-manifest/launchpad-artifact-manifest.json"
)"
test -n "$HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE"
case "$HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE" in
  *@sha256:*) ;;
  *) echo "egress proxy image is not pinned by digest" >&2; exit 1 ;;
esac
```

## Run live Hermes

```bash
set -euo pipefail

mkdir -p "$HELM_LAUNCHPAD_HOME/proof"
proof_json="$HELM_LAUNCHPAD_HOME/proof/hermes-live.json"

helm-ai-kernel up hermes --target local --live --json --no-open | tee "$proof_json"

jq -e '
  .mode == "live" and
  .started_runtime == true and
  .run.kernel_verdict == "ALLOW" and
  .run.state == "RUNNING" and
  (.run.runtime_handles.container_id | length > 0) and
  ((.run.egress_receipt_refs // []) | length > 0) and
  ((.run.evidence_pack_refs // []) | length > 0) and
  (.offline_verify_command | length > 0)
' "$proof_json"
```

If the run reaches `REPAIR_REQUIRED`, preserve the JSON and run:

```bash
jq '{mode, started_runtime, run: {launch_id: .run.launch_id, state: .run.state, reason: .run.reason, runtime_handles: .run.runtime_handles, evidence_pack_refs: .run.evidence_pack_refs}}' "$proof_json"
```

Do not call the run production-ready until the predicate above passes.

## Teardown and verify

```bash
set -euo pipefail

launch_id="$(jq -r '.run.launch_id' "$proof_json")"
teardown_json="$HELM_LAUNCHPAD_HOME/proof/hermes-teardown-${launch_id}.json"

helm-ai-kernel launch delete "$launch_id" --cascade | tee "$teardown_json"

final_pack="$(
  jq -r '(.evidence_pack_refs // [])[]' "$teardown_json" |
    grep '\.tar$' |
    tail -n 1
)"
test -n "$final_pack"

helm-ai-kernel verify --bundle "$final_pack"
```

Verifier output must include `VERIFIED` and `trust team`.

## Secret-fragment audit

Run the audit from a checkout of `helm-ai-kernel` on the VPS:

```bash
python3 scripts/launch/secret_fragment_audit.py \
  --secret-env OPENROUTER_API_KEY \
  --root "$HELM_LAUNCHPAD_HOME/proof" \
  --root "$HELM_LAUNCHPAD_HOME/evidencepacks"
```

The audit must return `PASS`. If it fails, preserve the report and do not share
the evidence bundle externally.

## Private-by-default network check

```bash
(ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || true) |
  awk 'NR==1 || /(:9119|:7714|:8642|:8644|:22)/'
```

Expected posture:

- SSH is reachable on port `22`.
- Hermes dashboard and HELM kernel, if running, bind only to `127.0.0.1`.
- No public listener exists for `9119`, `7714`, `8642`, or `8644`.

## Evidence handoff

Record these fields in the operator handoff:

- `helm-ai-kernel` version.
- Artifact workflow run id: `26198407296`.
- Egress proxy image digest.
- Launch id.
- Runtime container id.
- Egress receipt refs.
- Teardown receipt refs.
- Final EvidencePack path and verifier output.
- Secret-fragment audit status.
- Network listener check output.
