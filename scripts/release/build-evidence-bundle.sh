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
# Hash entries sorted by path using the EvidencePack Merkle domain separators.

MERKLE_ROOT=$(python3 - "${BUNDLE_DIR}/00_INDEX.json" <<'PY'
import hashlib
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    index = json.load(f)

leaves = []
for entry in sorted(index.get("entries", []), key=lambda item: item.get("path", "")):
    leaves.append(hashlib.sha256(b"\x00" + bytes.fromhex(entry["sha256"])).digest())

if not leaves:
    print(hashlib.sha256(b"").hexdigest())
    raise SystemExit(0)

while len(leaves) > 1:
    next_level = []
    for i in range(0, len(leaves), 2):
        left = leaves[i]
        right = leaves[i + 1] if i + 1 < len(leaves) else left
        next_level.append(hashlib.sha256(b"\x01" + left + right).digest())
    leaves = next_level

print(leaves[0].hex())
PY
)
echo "   ✓ Merkle root: ${MERKLE_ROOT}"

# ── Build attestation JSON ────────────────────────────────────────────────────

CREATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PROFILE_CHECKLIST="tests/conformance/profile-v1/checklist.yaml"
PROFILES_VERSION=$(python3 - "${PROFILE_CHECKLIST}" <<'PY'
import re
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    text = f.read()
match = re.search(r'^version:\s*"?([^"\n]+)"?', text, re.MULTILINE)
print(match.group(1) if match else "v1.0.0")
PY
)
PROFILES_SHA256=$(shasum -a 256 "${PROFILE_CHECKLIST}" | awk '{print $1}')
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
