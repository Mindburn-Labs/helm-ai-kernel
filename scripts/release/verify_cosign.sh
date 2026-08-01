#!/usr/bin/env bash
# quantum_posture: verifies existing classical Sigstore/Cosign evidence only;
# it does not create or claim post-quantum cryptographic assurance.
# Verify cosign-keyless signatures on every helm-ai-kernel release artifact in a
# given directory tree. Used as a smoke check post-release and as the
# canonical verification recipe documented in docs/VERIFICATION.md.
#
# Usage: verify_cosign.sh [dir]   # default: ./dist
# A directory containing the Console local-sidecar contract derives its exact
# Kernel tag from the signed Console manifest; other local artifact checks use
# the generic workflow identity below.
#
# Caller: Makefile target `verify-cosign`. Documented in docs/VERIFICATION.md.
set -euo pipefail

DIR="${1:-dist}"
DEFAULT_IDENTITY_REGEX='^https://github\.com/Mindburn-Labs/helm-ai-kernel/\.github/workflows/release\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+.*)$'
IDENTITY_REGEX="${COSIGN_IDENTITY_REGEX:-$DEFAULT_IDENTITY_REGEX}"
ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
CONSOLE_MANIFEST="helm-console-local-sidecar-release-manifest.json"
CONSOLE_PRODUCER_BUNDLE="${CONSOLE_MANIFEST}.cosign.bundle"
KERNEL_MANIFEST_BUNDLE="helm-console-local-sidecar-release-manifest.json.kernel.cosign.bundle"
CONSOLE_PRODUCER_IDENTITY="https://github.com/Mindburn-Labs/app-helm-console/.github/workflows/release-local-sidecar.yml@refs/heads/main"
KERNEL_RELEASE_IDENTITY=""

if ! printf '%s' "$IDENTITY_REGEX" | grep -Eq '^\^https://github\\?\.com/Mindburn-Labs/helm-ai-kernel/\\?\.github/workflows/[A-Za-z0-9_.-]+\\?\.ya?ml@refs/'; then
    echo "::error::COSIGN_IDENTITY_REGEX must be anchored to a helm-ai-kernel GitHub Actions workflow identity and refs"
    exit 1
fi

if ! command -v cosign >/dev/null 2>&1; then
    echo "::error::cosign not installed; install via https://github.com/sigstore/cosign/releases"
    exit 1
fi

if [ ! -d "$DIR" ]; then
    echo "::error::artifact directory not found: $DIR"
    exit 1
fi

console_contract=0
if find "$DIR" -type f \( -name "$CONSOLE_MANIFEST" -o -name "$CONSOLE_PRODUCER_BUNDLE" -o -name "$KERNEL_MANIFEST_BUNDLE" \) -print -quit | grep -q .; then
    console_contract=1
fi

if [ "$console_contract" = "1" ]; then
    console_manifest_path="$(find "$DIR" -type f -name "$CONSOLE_MANIFEST" -print -quit)"
    console_manifest_count="$(find "$DIR" -type f -name "$CONSOLE_MANIFEST" -print | wc -l | tr -d ' ')"
    console_producer_count="$(find "$DIR" -type f -name "$CONSOLE_PRODUCER_BUNDLE" -print | wc -l | tr -d ' ')"
    console_kernel_count="$(find "$DIR" -type f -name "$KERNEL_MANIFEST_BUNDLE" -print | wc -l | tr -d ' ')"
    if [ "$console_manifest_count" != "1" ] || [ "$console_producer_count" != "1" ] || [ "$console_kernel_count" != "1" ]; then
        echo "::error::Kernel release verification requires exactly one Console manifest plus both producer and Kernel bundles"
        exit 1
    fi
    console_dir="$(dirname "$console_manifest_path")"
    if [ ! -f "$console_dir/$CONSOLE_PRODUCER_BUNDLE" ] || [ ! -f "$console_dir/$KERNEL_MANIFEST_BUNDLE" ]; then
        echo "::error::Kernel release verification requires Console manifest bundles beside the manifest"
        exit 1
    fi
    if ! kernel_release_tag="$(python3 - "$console_manifest_path" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
tag = manifest.get("kernel_release_version") if isinstance(manifest, dict) else None
if not isinstance(tag, str) or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
    raise SystemExit("Console manifest kernel_release_version must be an exact semantic release tag")
print(tag)
PY
    )"; then
        echo "::error::Console release verification requires an exact Kernel tag in the Console manifest"
        exit 1
    fi
    KERNEL_RELEASE_IDENTITY="https://github.com/Mindburn-Labs/helm-ai-kernel/.github/workflows/release.yml@refs/tags/${kernel_release_tag}"
fi

ok=0
fail=0
while IFS= read -r bundle; do
    case "$(basename "$bundle")" in
        "$CONSOLE_PRODUCER_BUNDLE")
            # The Console source tuple is immutable, while its producer
            # workflow is protected-main trust. The tag-bound Kernel bundle
            # below is the public-release binding for this manifest.
            if [ -z "$KERNEL_RELEASE_IDENTITY" ]; then
                echo "::error::Console producer bundle requires an exact Kernel release identity"
                exit 1
            fi
            artifact="${bundle%.cosign.bundle}"
            verify_args=(
                verify-blob
                --bundle "$bundle"
                --certificate-identity "$CONSOLE_PRODUCER_IDENTITY"
                --certificate-oidc-issuer "$ISSUER"
                "$artifact"
            )
            ;;
        *)
            case "$bundle" in
                *.kernel.cosign.bundle) artifact="${bundle%.kernel.cosign.bundle}" ;;
                *.cosign.bundle) artifact="${bundle%.cosign.bundle}" ;;
                *) echo "::error::unsupported cosign bundle suffix: $bundle"; exit 1 ;;
            esac
            if [ -n "$KERNEL_RELEASE_IDENTITY" ]; then
                verify_args=(
                    verify-blob
                    --bundle "$bundle"
                    --certificate-identity "$KERNEL_RELEASE_IDENTITY"
                    --certificate-oidc-issuer "$ISSUER"
                    "$artifact"
                )
            else
                verify_args=(
                    verify-blob
                    --bundle "$bundle"
                    --certificate-identity-regexp "$IDENTITY_REGEX"
                    --certificate-oidc-issuer "$ISSUER"
                    "$artifact"
                )
            fi
            ;;
    esac
    if [ ! -f "$artifact" ]; then
        echo "::warning::no artifact next to bundle $bundle; skipping"
        continue
    fi
    echo "verifying $artifact"
    if cosign "${verify_args[@]}" >/dev/null 2>&1; then
        echo "  ok"
        ok=$((ok + 1))
    else
        echo "  FAIL"
        fail=$((fail + 1))
    fi
done < <(find "$DIR" -name "*.cosign.bundle" -type f)

echo "verified=$ok failed=$fail"
exit $((fail > 0 ? 1 : 0))
