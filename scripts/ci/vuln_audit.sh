#!/usr/bin/env bash
# Run ecosystem vulnerability audits when the relevant tools are available.
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

if command -v govulncheck >/dev/null 2>&1; then
    run_step "Go govulncheck" bash -lc "cd '$ROOT/core' && govulncheck ./..."
else
    warn_missing "govulncheck" "Install with: go install golang.org/x/vuln/cmd/govulncheck@latest"
fi

if command -v npm >/dev/null 2>&1; then
    for dir in "$ROOT/sdk/ts" "$ROOT/apps/console" "$ROOT/packages/design-system-core"; do
        if [ -f "$dir/package-lock.json" ]; then
            rel="${dir#"$ROOT"/}"
            run_step "npm audit $rel" \
                bash -lc "cd '$dir' && npm audit --omit=dev --audit-level=high"
        fi
    done
else
    warn_missing "npm" "Node package audits were skipped."
fi

if command -v cargo-audit >/dev/null 2>&1; then
    run_step "Rust cargo audit" bash -lc "cd '$ROOT/sdk/rust' && cargo audit"
else
    warn_missing "cargo-audit" "Install with: cargo install cargo-audit --locked"
fi

if command -v pip-audit >/dev/null 2>&1; then
    run_step "Python pip-audit" bash -lc "cd '$ROOT/sdk/python' && pip-audit"
else
    warn_missing "pip-audit" "Install with: python -m pip install pip-audit"
fi

exit "$STATUS"
