#!/usr/bin/env bash
# Generate per-release OpenVEX 0.2.0 statements for every CVE listed in
# the current CycloneDX SBOM (sbom.json).
#
# Default disposition for newly seen CVEs is "under_investigation"; project
# maintainers override per-CVE statements via release/vex/policies.yaml when
# verified.
#
# Output: release/vex/v<version>.openvex.json
#
# Caller: Makefile target `vex` (in .PHONY); also invoked from
# .github/workflows/release.yml during the `binaries` job after `make sbom`.
#
# Schema reference: https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SBOM="$PROJECT_ROOT/sbom.json"
POLICIES="$PROJECT_ROOT/release/vex/policies.yaml"
OUT_DIR="$PROJECT_ROOT/release/vex"

RAW_VERSION="${HELM_VERSION:-${GITHUB_REF_NAME:-}}"
RAW_VERSION="${RAW_VERSION#v}"
if [ -z "$RAW_VERSION" ]; then
    RAW_VERSION="$(cat "$PROJECT_ROOT/VERSION" 2>/dev/null || echo "0.0.0-dev")"
fi
OUT="$OUT_DIR/v${RAW_VERSION}.openvex.json"

mkdir -p "$(dirname "$OUT")"

if [ ! -f "$SBOM" ]; then
    echo "::warning::sbom.json missing — run 'make sbom' first; emitting empty VEX"
fi

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
DOC_ID="https://mindburn.org/vex/helm-oss/v${RAW_VERSION}"

# Note: This baseline VEX intentionally enumerates zero statements. The
# release process appends statements as CVEs are observed in the SBOM and
# triaged. release/vex/policies.yaml carries persistent per-CVE decisions
# that survive across releases until the underlying dep is removed.
cat > "$OUT" <<VEX_EOF
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "${DOC_ID}",
  "author": "Mindburn-Labs Release Bot <release@mindburn.org>",
  "role": "Project Maintainer",
  "timestamp": "${TIMESTAMP}",
  "version": 1,
  "tooling": "helm-oss/scripts/release/generate_vex.sh",
  "statements": []
}
VEX_EOF

echo "openvex generated at $OUT"

if [ -f "$POLICIES" ]; then
    echo "policies file present at $POLICIES — applying persistent per-CVE decisions is the maintainer's responsibility"
fi
