#!/bin/bash
# generate-manifest.sh — Generates the canonical protected.manifest
# Run from the OSS repo root to produce tools/boundary/protected.manifest
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

MANIFEST="tools/boundary/protected.manifest"
mkdir -p "$(dirname "$MANIFEST")"

PROTECTED_DIRS=(
  core/pkg/kernel
  core/pkg/contracts
  core/pkg/crypto
  core/pkg/evidencepack
  core/pkg/proofgraph
  core/pkg/receipts
  core/pkg/verifier
  core/pkg/connectors/sandbox
  core/pkg/conformance
  core/pkg/audit
  core/pkg/integrations/receipts
  core/pkg/integrations/capgraph
  core/pkg/integrations/manifest
  core/pkg/api
  core/pkg/trust/registry
  core/pkg/guardian
  protocols
  schemas
)

{
  echo "# HELM Protected Manifest"
  echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Commit: $(git rev-parse HEAD)"
  echo "# Format: SHA256  PATH"
  echo "#"
  for dir in "${PROTECTED_DIRS[@]}"; do
    if [ -d "$dir" ]; then
      find "$dir" -type f | sort | while read -r f; do
        hash=$(shasum -a 256 "$f" | cut -d' ' -f1)
        echo "$hash  $f"
      done
    fi
  done
} > "$MANIFEST"

TOTAL=$(grep -c -v '^#' "$MANIFEST" || echo 0)
echo "Generated $MANIFEST ($TOTAL files)"
