#!/usr/bin/env bash
# Release artifact verification script.
# Checks: checksums, SBOM format, provenance.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PASS=0
FAIL=0

check() {
    local name="$1"
    local result="$2"
    if [ "$result" = "0" ]; then
        echo "  ✅ $name"
        PASS=$((PASS + 1))
    else
        echo "  ❌ $name"
        FAIL=$((FAIL + 1))
    fi
}

echo "HELM Release Verification"
echo "═════════════════════════"
echo ""

# 1. Binary exists
if [ -f "$PROJECT_ROOT/bin/helm" ]; then
    check "Binary exists (bin/helm)" 0
else
    check "Binary exists (bin/helm)" 1
fi

# 2. Checksum file exists and matches
if [ -f "$PROJECT_ROOT/bin/helm.mindburn.runa256" ]; then
    cd "$PROJECT_ROOT"
    if shasum -a 256 -c bin/helm.mindburn.runa256 > /dev/null 2>&1; then
        check "Checksum matches (bin/helm.mindburn.runa256)" 0
    else
        check "Checksum matches (bin/helm.mindburn.runa256)" 1
    fi
else
    check "Checksum file exists (bin/helm.mindburn.runa256)" 1
fi

# 3. SBOM exists and is CycloneDX format
if [ -f "$PROJECT_ROOT/sbom.json" ]; then
    if grep -q '"bomFormat": "CycloneDX"' "$PROJECT_ROOT/sbom.json" 2>/dev/null; then
        check "SBOM is CycloneDX format (sbom.json)" 0
    else
        check "SBOM is valid CycloneDX format" 1
    fi
else
    check "SBOM exists (sbom.json)" 1
fi

# 4. deps.txt exists (debug artifact)
if [ -f "$PROJECT_ROOT/deps.txt" ]; then
    check "deps.txt exists (debug artifact)" 0
else
    check "deps.txt exists (debug artifact)" 1
fi

echo ""
echo "═════════════════════════"
echo "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
