#!/usr/bin/env bash
# Unreachable-code gate (target architecture R10, §13.1-4).
#
# Runs golang.org/x/tools/cmd/deadcode from every root listed in
# scripts/ci/deadcode-roots.txt (the shipped binaries), for the release target
# linux/amd64 with CGO_ENABLED=0. Every function no root can reach is a finding,
# keyed as "<package path> <function>".
#
# scripts/ci/deadcode-allowlist.txt freezes the unreachable functions that
# existed when the gate landed. The gate fails on a function missing from the
# list (new dead code: wire it, delete it, or make it a declared root) and on a
# listed function that is no longer dead (deleted or now reached). The list
# therefore only shrinks, and deletion PRs must remove their lines.
#
# Before measuring the repo, the gate runs deadcode on a throwaway program with
# one unreachable function and exits 2 unless that function is reported.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOLS="${HELM_CI_TOOLS:-$HOME/.cache/helm-ci-tools}"
FINDINGS="$ROOT/scripts/ci/security_findings.py"
ALLOWLIST="$ROOT/scripts/ci/deadcode-allowlist.txt"
DEADCODE_VERSION=v0.48.0 # golang.org/x/tools; newer releases need Go 1.26
WORK="$(mktemp -d "${TMPDIR:-/tmp}/helm-deadcode.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

DEADCODE="$TOOLS/deadcode-$DEADCODE_VERSION/deadcode"
if [ ! -x "$DEADCODE" ]; then
    GOTOOLCHAIN=local GOWORK=off GOBIN="$(dirname "$DEADCODE")" \
        go install "golang.org/x/tools/cmd/deadcode@$DEADCODE_VERSION"
fi

run_deadcode() { # dir report packages...
    local dir="$1" report="$2"
    shift 2
    (cd "$dir" && GOWORK=off GOOS=linux GOARCH=amd64 CGO_ENABLED=0 "$DEADCODE" -json "$@" >"$report")
}

# Positive control.
control="$WORK/control"
mkdir -p "$control"
printf 'module example.com/deadcodecontrol\n\ngo 1.25\n' >"$control/go.mod"
cat >"$control/main.go" <<'GO'
package main

func used() int { return 1 }

// planted is never called: the gate must report it.
func planted() int { return 2 }

func main() { _ = used() }
GO
run_deadcode "$control" "$WORK/control.json" .
control_keys="$(python3 "$FINDINGS" deadcode-keys "$WORK/control.json")"
if [ "$control_keys" != "example.com/deadcodecontrol planted" ]; then
    echo "::error::deadcode positive control failed: expected exactly the planted function, got: ${control_keys:-nothing}"
    exit 2
fi
echo "deadcode control: flagged the planted function"

# The repo, from the declared roots.
roots=()
while IFS= read -r line; do
    line="${line%%#*}"
    line="$(echo "$line" | tr -d '[:space:]')"
    [ -n "$line" ] || continue
    case "$line" in
        core/*) roots+=("./${line#core/}") ;;
        *) echo "::error::deadcode root $line is outside the core module"; exit 2 ;;
    esac
done <"$ROOT/scripts/ci/deadcode-roots.txt"
if [ "${#roots[@]}" -eq 0 ]; then
    echo "::error::scripts/ci/deadcode-roots.txt lists no roots"
    exit 2
fi
echo "==> deadcode from ${roots[*]}"
run_deadcode "$ROOT/core" "$WORK/deadcode.json" "${roots[@]}"
python3 "$FINDINGS" deadcode-keys "$WORK/deadcode.json" >"$WORK/deadcode.keys"
if ! python3 "$FINDINGS" compare "$ALLOWLIST" "$WORK/deadcode.keys"; then
    echo "A new line above is unreachable from every shipped binary: call it from a shipped path, delete it, or declare its binary in scripts/ci/deadcode-roots.txt."
    echo "A stale line above means code was deleted or is now reached: remove that line from scripts/ci/deadcode-allowlist.txt in the same PR."
    exit 1
fi
