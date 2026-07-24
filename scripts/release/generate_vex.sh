#!/usr/bin/env bash
# Generate per-release OpenVEX 0.2.0 statements for every CVE listed in
# the current CycloneDX SBOM (sbom.json).
#
# Default disposition for newly seen CVEs is "under_investigation"; project
# maintainers override per-CVE statements via release/vex/policies.yaml when
# verified. Policy ids may be a CVE (CVE-YYYY-NNNNN) or a Go vulnerability
# database id (GO-YYYY-NNNNN) for advisories with no assigned CVE — e.g.
# golang.org/x/vulndb entries surfaced by govulncheck/OSV.
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
if [[ "$RAW_VERSION" == */* ]]; then
    RAW_VERSION=""
fi
if [ -z "$RAW_VERSION" ]; then
    RAW_VERSION="$(cat "$PROJECT_ROOT/VERSION" 2>/dev/null || echo "0.0.0-dev")"
fi
OUT="$OUT_DIR/v${RAW_VERSION}.openvex.json"
# Same root-component identity generate_sbom.sh assigns the release binary,
# so VEX statements correlate with the SBOM's own component identifiers.
PRODUCT_PURL="pkg:golang/github.com/Mindburn-Labs/helm-ai-kernel/core@${RAW_VERSION}"

mkdir -p "$(dirname "$OUT")"

if [ ! -f "$SBOM" ]; then
    echo "::warning::sbom.json missing — run 'make sbom' first; emitting VEX with policy-only statements"
fi

if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    if ! TIMESTAMP=$(date -u -r "$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null); then
        TIMESTAMP=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
    fi
else
    TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
fi
DOC_ID="https://mindburn.org/vex/helm-ai-kernel/v${RAW_VERSION}"

# ---------------------------------------------------------------------------
# Render release/vex/policies.yaml's persistent per-CVE overrides into
# OpenVEX statement objects. This does not (yet) cross-reference sbom.json's
# live findings — it only emits ids a maintainer has explicitly triaged into
# policies.yaml; anything else stays absent from this document (i.e. implicit
# "under_investigation" by omission, per the default described above).
#
# Parsed with plain awk against the flat "key: value" schema documented at
# the top of policies.yaml — no YAML library dependency, so this behaves
# identically in CI (the `binaries` job that runs `make release-assets` has
# no Python/PyYAML setup step) and locally.
# ---------------------------------------------------------------------------
STATEMENTS_JSON="[]"
if [ -f "$POLICIES" ]; then
    STATEMENTS_JSON="$(awk -v ts="$TIMESTAMP" -v purl="$PRODUCT_PURL" '
        BEGIN {
            valid_status["not_affected"] = 1
            valid_status["affected"] = 1
            valid_status["fixed"] = 1
            valid_status["under_investigation"] = 1
            n = 0
            have = 0
        }
        function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
        function unquote(s,    l) {
            l = length(s)
            if (l >= 2 && substr(s, 1, 1) == "\"" && substr(s, l, 1) == "\"") return substr(s, 2, l - 2)
            return s
        }
        function esc(s) {
            gsub(/\\/, "\\\\", s)
            gsub(/"/, "\\\"", s)
            gsub(/\t/, "\\t", s)
            gsub(/\r/, "\\r", s)
            gsub(/\n/, "\\n", s)
            return s
        }
        function flush() {
            if (!have) return
            have = 0
            if (cve !~ /^(CVE|GO)-[0-9]/) {
                print "::warning::generate_vex.sh: skipping policies.yaml entry with unrecognized id " cve " (expected CVE-* or GO-*)" > "/dev/stderr"
                return
            }
            if (!(status in valid_status)) {
                print "::warning::generate_vex.sh: skipping policies.yaml entry " cve " with invalid status " status > "/dev/stderr"
                return
            }
            if (status == "not_affected" && justification == "") {
                print "::warning::generate_vex.sh: skipping policies.yaml entry " cve ": not_affected requires a justification (see policies.yaml schema)" > "/dev/stderr"
                return
            }
            obj = "{\"vulnerability\":{\"name\":\"" esc(cve) "\"},\"timestamp\":\"" ts "\",\"products\":[{\"@id\":\"" purl "\"}],\"status\":\"" esc(status) "\""
            if (justification != "") obj = obj ",\"justification\":\"" esc(justification) "\""
            if (statement != "") obj = obj ",\"status_notes\":\"" esc(statement) "\""
            obj = obj "}"
            entries[n++] = obj
        }
        /^[ \t]*-[ \t]*cve_id:/ {
            flush()
            cve = $0; sub(/^[ \t]*-[ \t]*cve_id:[ \t]*/, "", cve); cve = unquote(trim(cve))
            status = ""; justification = ""; statement = ""
            have = 1
            next
        }
        /^[ \t]*status:/ {
            v = $0; sub(/^[ \t]*status:[ \t]*/, "", v); status = unquote(trim(v)); next
        }
        /^[ \t]*justification:/ {
            v = $0; sub(/^[ \t]*justification:[ \t]*/, "", v); justification = unquote(trim(v)); next
        }
        /^[ \t]*statement:/ {
            v = $0; sub(/^[ \t]*statement:[ \t]*/, "", v); statement = unquote(trim(v)); next
        }
        END {
            flush()
            printf "["
            for (i = 0; i < n; i++) { if (i > 0) printf ","; printf "%s", entries[i] }
            printf "]"
        }
    ' "$POLICIES")"
fi

cat > "$OUT" <<VEX_EOF
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "${DOC_ID}",
  "author": "Mindburn-Labs Release Bot <release@mindburn.org>",
  "role": "Project Maintainer",
  "timestamp": "${TIMESTAMP}",
  "version": 1,
  "tooling": "helm-ai-kernel/scripts/release/generate_vex.sh",
  "statements": ${STATEMENTS_JSON}
}
VEX_EOF

if command -v jq >/dev/null 2>&1; then
    jq empty "$OUT" || { echo "::error::generate_vex.sh: generated $OUT is not valid JSON" >&2; exit 1; }
fi

echo "openvex generated at $OUT"

if [ -f "$POLICIES" ]; then
    if [ "$STATEMENTS_JSON" = "[]" ]; then
        echo "policies file present at $POLICIES — no applicable persistent statements (see any warnings above for skipped entries)"
    else
        echo "policies file present at $POLICIES — persistent per-CVE statements applied to $OUT"
    fi
fi
