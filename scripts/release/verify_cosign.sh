#!/usr/bin/env bash
# Verify cosign-keyless signatures on every helm-ai-kernel release artifact in a
# given directory tree. Used as a smoke check post-release and as the
# canonical verification recipe documented in docs/VERIFICATION.md.
#
# Usage: verify_cosign.sh [dir]   # default: ./dist
#
# Caller: Makefile target `verify-cosign`. Documented in docs/VERIFICATION.md.
set -euo pipefail

DIR="${1:-dist}"
IDENTITY_REGEX="${COSIGN_IDENTITY_REGEX:-https://github.com/Mindburn-Labs/helm-ai-kernel}"
ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

if ! command -v cosign >/dev/null 2>&1; then
    echo "::error::cosign not installed; install via https://github.com/sigstore/cosign/releases"
    exit 1
fi

if [ ! -d "$DIR" ]; then
    echo "::error::artifact directory not found: $DIR"
    exit 1
fi

ok=0
fail=0
while IFS= read -r bundle; do
    artifact="${bundle%.cosign.bundle}"
    if [ ! -f "$artifact" ]; then
        echo "::warning::no artifact next to bundle $bundle; skipping"
        continue
    fi
    echo "verifying $artifact"
    if cosign verify-blob \
        --bundle "$bundle" \
        --certificate-identity-regexp "$IDENTITY_REGEX" \
        --certificate-oidc-issuer "$ISSUER" \
        "$artifact" >/dev/null 2>&1; then
        echo "  ok"
        ok=$((ok + 1))
    else
        echo "  FAIL"
        fail=$((fail + 1))
    fi
done < <(find "$DIR" -name "*.cosign.bundle" -type f)

echo "verified=$ok failed=$fail"
exit $((fail > 0 ? 1 : 0))
