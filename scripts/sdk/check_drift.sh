#!/usr/bin/env bash
# HELM SDK regenerate-and-diff gate (HELM-W3).
#
# Full mode (default): regenerate every SDK from the canonical OpenAPI spec
# with the digest-pinned generator, verify each generated.manifest.json, and
# fail if the working tree drifts from the committed generated files.
#
# Verify-only mode (--verify-only): validate committed generated files against
# their manifest hashes without Docker. This catches manual edits to generated
# files but cannot detect spec/generator drift; use full mode for that.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SDK_DIRS=(sdk/ts sdk/python sdk/go sdk/rust sdk/java)
GATED_PATHS=(
    sdk/ts/src/types.gen.ts
    sdk/ts/generated.manifest.json
    sdk/python/helm_sdk/types_gen.py
    sdk/python/generated.manifest.json
    sdk/go/client/types_gen.go
    sdk/go/generated.manifest.json
    sdk/rust/src/types_gen.rs
    sdk/rust/generated.manifest.json
    sdk/java/src/main/java/labs/mindburn/helm/TypesGen.java
    sdk/java/generated.manifest.json
)

verify_manifests() {
    local sdk_dir
    for sdk_dir in "${SDK_DIRS[@]}"; do
        python3 "$SCRIPT_DIR/manifest.py" verify "$PROJECT_ROOT/$sdk_dir"
    done
}

mode="${1:-}"
case "$mode" in
    --verify-only)
        echo "HELM SDK manifest verification (no regeneration)"
        verify_manifests
        echo "✅ all generated files match their committed manifests"
        exit 0
        ;;
    "") ;;
    *)
        echo "usage: $0 [--verify-only]" >&2
        exit 2
        ;;
esac

echo "HELM SDK regenerate-and-diff gate"
echo "═════════════════════════════════"

git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
    echo "❌ $PROJECT_ROOT is not a git work tree; the drift gate requires git" >&2
    exit 1
}

bash "$SCRIPT_DIR/gen.sh"
verify_manifests

drift=0
if ! git -C "$PROJECT_ROOT" diff --exit-code --stat -- "${GATED_PATHS[@]}"; then
    drift=1
fi
untracked="$(git -C "$PROJECT_ROOT" status --porcelain -- "${GATED_PATHS[@]}" | grep '^??' || true)"
if [ -n "$untracked" ]; then
    echo "$untracked"
    drift=1
fi

if [ "$drift" -ne 0 ]; then
    cat >&2 <<'MSG'
❌ SDK drift detected: committed generated files differ from a fresh,
   deterministic regeneration.

   If the OpenAPI spec or generator changed intentionally:
       bash scripts/sdk/gen.sh
       git add sdk/ && git commit
   If the generated files were edited by hand: revert those edits — generated
   files are owned by scripts/sdk/gen.sh.
MSG
    exit 1
fi

echo ""
echo "✅ SDKs are in sync with api/openapi/helm.openapi.yaml"
