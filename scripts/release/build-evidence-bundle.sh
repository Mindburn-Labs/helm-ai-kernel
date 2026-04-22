#!/usr/bin/env bash
# ─── HELM Evidence Bundle Builder ────────────────────────────────────────────
# Builds an evidence bundle tarball, computes hashes, signs attestation.
#
# Usage: ./scripts/release/build-evidence-bundle.sh <version> <bundle-dir> <output-dir>
# Example: ./scripts/release/build-evidence-bundle.sh v0.9.1 artifacts/conformance/latest dist/
#
# Requires:
#   - openssl (Ed25519 signing)
#   - jq (JSON processing)
#   - shasum (SHA-256)
#   - tar (archive creation)
#
# Environment:
#   HELM_SIGNING_KEY  Path to Ed25519 private key (PEM format)
#                     If not set, creates unsigned attestation.

set -euo pipefail

VERSION="${1:?Usage: $0 <version> <bundle-dir> <output-dir>}"
BUNDLE_DIR="${2:?Usage: $0 <version> <bundle-dir> <output-dir>}"
OUTPUT_DIR="${3:?Usage: $0 <version> <bundle-dir> <output-dir>}"

# ── Validate ──────────────────────────────────────────────────────────────────

if [ ! -f "${BUNDLE_DIR}/00_INDEX.json" ]; then
    echo "❌ No 00_INDEX.json found in ${BUNDLE_DIR}"
    exit 1
fi

if [ ! -f "${BUNDLE_DIR}/01_SCORE.json" ]; then
    echo "❌ No 01_SCORE.json found in ${BUNDLE_DIR}"
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

ASSET_NAME="helm-evidence-${VERSION}.tar.gz"
ATTESTATION_NAME="helm-attestation-${VERSION}.json"
SIGNATURE_NAME="helm-attestation-${VERSION}.sig"

echo "📦 Building evidence bundle: ${ASSET_NAME}"

# ── Create tarball ────────────────────────────────────────────────────────────

tar -czf "${OUTPUT_DIR}/${ASSET_NAME}" -C "$(dirname "${BUNDLE_DIR}")" "$(basename "${BUNDLE_DIR}")"
echo "   ✓ Tarball created"

# ── Compute asset SHA-256 ─────────────────────────────────────────────────────

ASSET_SHA256=$(shasum -a 256 "${OUTPUT_DIR}/${ASSET_NAME}" | awk '{print $1}')
echo "   ✓ Asset SHA-256: ${ASSET_SHA256}"

# ── Compute manifest root hash ───────────────────────────────────────────────

MANIFEST_ROOT_HASH=$(shasum -a 256 "${BUNDLE_DIR}/00_INDEX.json" | awk '{print $1}')
echo "   ✓ Manifest root hash: ${MANIFEST_ROOT_HASH}"

# ── Compute Merkle root ──────────────────────────────────────────────────────
# Extract sha256 values sorted by path from 00_INDEX.json, then compute tree.
# This is a simplified bash implementation — the CLI does the canonical version.

# Extract sorted entry hashes
ENTRY_HASHES=$(jq -r '.entries | sort_by(.path) | .[].sha256' "${BUNDLE_DIR}/00_INDEX.json")

# Compute Merkle root using Node.js crypto (reuse the CLI for correctness)
MERKLE_ROOT=$(node -e "
const { computeMerkleRoot } = await import('./packages/mindburn-helm-cli/dist/crypto.js');
const entries = $(jq -c '.entries' "${BUNDLE_DIR}/00_INDEX.json");
console.log(computeMerkleRoot(entries));
" 2>/dev/null || echo "COMPUTE_FAILED")

if [ "${MERKLE_ROOT}" = "COMPUTE_FAILED" ]; then
    # Fallback: use single hash of concatenated entry hashes
    MERKLE_ROOT=$(echo -n "${ENTRY_HASHES}" | tr '\n' ' ' | shasum -a 256 | awk '{print $1}')
    echo "   ⚠ Merkle root (fallback): ${MERKLE_ROOT}"
else
    echo "   ✓ Merkle root: ${MERKLE_ROOT}"
fi

# ── Build attestation JSON ────────────────────────────────────────────────────

CREATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PROFILES_VERSION=$(jq -r '.version // "1.0.0"' packages/mindburn-helm-cli/src/profiles.json 2>/dev/null || echo "1.0.0")
PROFILES_SHA256=$(shasum -a 256 packages/mindburn-helm-cli/src/profiles.json 2>/dev/null | awk '{print $1}' || echo "")
KEYS_KEY_ID="helm-oss-v1"

cat > "${OUTPUT_DIR}/${ATTESTATION_NAME}" <<EOF
{
  "format": "helm-attestation-v3",
  "release_tag": "${VERSION}",
  "asset_name": "${ASSET_NAME}",
  "asset_sha256": "${ASSET_SHA256}",
  "manifest_root_hash": "${MANIFEST_ROOT_HASH}",
  "merkle_root": "${MERKLE_ROOT}",
  "created_at": "${CREATED_AT}",
  "profiles_version": "${PROFILES_VERSION}",
  "profiles_manifest_sha256": "${PROFILES_SHA256}",
  "keys_key_id": "${KEYS_KEY_ID}",
  "producer": {
    "name": "helm-release-pipeline",
    "version": "${VERSION}",
    "commit": "$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  }
}
EOF

echo "   ✓ Attestation JSON written"

# ── Sign attestation (Ed25519) ────────────────────────────────────────────────

if [ -n "${HELM_SIGNING_KEY:-}" ] && [ -f "${HELM_SIGNING_KEY}" ]; then
    # Sign sha256(canonical bytes of attestation JSON)
    ATTESTATION_HASH=$(shasum -a 256 "${OUTPUT_DIR}/${ATTESTATION_NAME}" | awk '{print $1}')
    echo -n "${ATTESTATION_HASH}" | xxd -r -p | \
        openssl pkeyutl -sign -inkey "${HELM_SIGNING_KEY}" -rawin | \
        base64 > "${OUTPUT_DIR}/${SIGNATURE_NAME}"
    echo "   ✓ Ed25519 signature written"
else
    echo "   ⚠ HELM_SIGNING_KEY not set — unsigned attestation"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "📋 Bundle ready for release:"
echo "   ${OUTPUT_DIR}/${ASSET_NAME}"
echo "   ${OUTPUT_DIR}/${ATTESTATION_NAME}"
if [ -f "${OUTPUT_DIR}/${SIGNATURE_NAME}" ]; then
    echo "   ${OUTPUT_DIR}/${SIGNATURE_NAME}"
fi
echo ""
echo "   manifest_root_hash: ${MANIFEST_ROOT_HASH}"
echo "   merkle_root:        ${MERKLE_ROOT}"
echo "   asset_sha256:       ${ASSET_SHA256}"
