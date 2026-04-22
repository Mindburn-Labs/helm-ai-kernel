#!/usr/bin/env bash
# Generate CycloneDX SBOM from Go module dependencies.
# Output: sbom.json (CycloneDX 1.5 format)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CORE_DIR="$PROJECT_ROOT/core"
OUTPUT="$PROJECT_ROOT/sbom.json"
DEPS_OUTPUT="$PROJECT_ROOT/deps.txt"
RAW_VERSION="${HELM_VERSION:-${GITHUB_REF_NAME:-}}"
RAW_VERSION="${RAW_VERSION#v}"
if [ -z "$RAW_VERSION" ]; then
    RAW_VERSION="0.0.0-dev"
fi
ROOT_MODULE_PURL="pkg:golang/github.com/Mindburn-Labs/helm-oss/core@${RAW_VERSION}"

cd "$CORE_DIR"

# Generate deps.txt (debug artifact, replaces old SBOM.txt)
echo "--- Go Module Info ---" > "$DEPS_OUTPUT"
go version -m "$PROJECT_ROOT/bin/helm" >> "$DEPS_OUTPUT" 2>/dev/null || echo "(binary not built yet — run 'make build' first)" >> "$DEPS_OUTPUT"
echo "" >> "$DEPS_OUTPUT"
echo "--- All Dependencies ---" >> "$DEPS_OUTPUT"
go list -m all >> "$DEPS_OUTPUT"
echo "✅ deps.txt generated"

# Generate CycloneDX JSON SBOM
COMPONENTS=""
FIRST=true

while IFS= read -r line; do
    MODULE=$(echo "$line" | awk '{print $1}')
    VERSION=$(echo "$line" | awk '{print $2}')
    
    # Skip the root module
    if [ -z "$VERSION" ]; then
        continue
    fi
    
    PURL="pkg:golang/${MODULE}@${VERSION}"
    
    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        COMPONENTS="${COMPONENTS},"
    fi
    
    COMPONENTS="${COMPONENTS}
    {
      \"type\": \"library\",
      \"name\": \"${MODULE}\",
      \"version\": \"${VERSION}\",
      \"purl\": \"${PURL}\"
    }"
done < <(go list -m all 2>/dev/null | tail -n +2)

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

cat > "$OUTPUT" << SBOM_EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "${TIMESTAMP}",
    "component": {
      "type": "application",
      "name": "helm",
      "version": "${RAW_VERSION}",
      "purl": "${ROOT_MODULE_PURL}"
    },
    "tools": [
      {
        "name": "helm-sbom-generator",
        "version": "1.0.0"
      }
    ]
  },
  "components": [${COMPONENTS}
  ]
}
SBOM_EOF

echo "✅ sbom.json generated (CycloneDX 1.5) with $(echo "$COMPONENTS" | grep -c '"type"' || echo 0) components"
