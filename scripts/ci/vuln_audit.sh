#!/usr/bin/env bash
# npm audit of the TypeScript SDK lockfile.
# Rust (cargo audit) runs in the `Rust audit` job of codeql.yml on every PR.
# Go (govulncheck, every module) and the Python SDK (pip-audit) are blocking
# gates in scripts/ci/security_gates.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STRICT="${QUALITY_STRICT:-0}"
STATUS=0

mark_failure() {
    STATUS=1
}

warn_missing() {
    local tool="$1"
    local hint="$2"
    if [ "$STRICT" = "1" ]; then
        echo "::error::$tool is required when QUALITY_STRICT=1. $hint"
        mark_failure
    else
        echo "::warning::$tool is not installed; skipping. $hint"
    fi
}

run_step() {
    local name="$1"
    shift
    echo "==> $name"
    if ! "$@"; then
        echo "::error::$name failed"
        mark_failure
    fi
}

if command -v npm >/dev/null 2>&1; then
    if [ -f "$ROOT/sdk/ts/package-lock.json" ]; then
        run_step "npm audit sdk/ts" \
            bash -c "cd '$ROOT/sdk/ts' && npm audit --audit-level=moderate"
    else
        echo "::error::sdk/ts/package-lock.json is missing; nothing to audit"
        mark_failure
    fi
else
    warn_missing "npm" "Node package audits were skipped."
fi

exit "$STATUS"
