#!/usr/bin/env bash
# Unreachable-code gate (target architecture R10, §13.1-4).
#
# Runs golang.org/x/tools/cmd/deadcode from every root listed in
# scripts/ci/deadcode-roots.txt (the shipped binaries), for linux/amd64 and any
# declared js/wasm roots, with CGO_ENABLED=0. A function no root can reach is a finding,
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

run_deadcode() { # dir report target packages...
    local dir="$1" report="$2" target="$3"
    shift 3
    (cd "$dir" && GOWORK=off GOOS="${target%/*}" GOARCH="${target#*/}" CGO_ENABLED=0 "$DEADCODE" -json "$@" >"$report")
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

func nativeOnly() int { return 3 }
func wasmOnly() int { return 4 }

func main() { _ = used(); platformUsed() }
GO
cat >"$control/native.go" <<'GO'
//go:build !js || !wasm
package main
func platformUsed() { _ = nativeOnly() }
GO
cat >"$control/wasm.go" <<'GO'
//go:build js && wasm
package main
func platformUsed() { _ = wasmOnly() }
GO
run_deadcode "$control" "$WORK/control.json" linux/amd64 .
control_keys="$(python3 "$FINDINGS" deadcode-keys "$WORK/control.json")"
expected_control=$'example.com/deadcodecontrol planted\nexample.com/deadcodecontrol wasmOnly'
if [ "$control_keys" != "$expected_control" ]; then
    echo "::error::deadcode positive control failed: expected planted and the other target's function, got: ${control_keys:-nothing}"
    exit 2
fi
echo "deadcode control: flagged the planted function"

# The repo, from the declared roots.
roots=()
wasm_roots=()
while IFS= read -r line; do
    line="${line%%#*}"
    line="$(echo "$line" | tr -d '[:space:]')"
    [ -n "$line" ] || continue
    target=linux/amd64
    case "$line" in js/wasm:*) target=js/wasm; line="${line#js/wasm:}" ;; esac
    case "$line" in
        core/*)
            if [ "$target" = js/wasm ]; then wasm_roots+=("./${line#core/}")
            else roots+=("./${line#core/}"); fi ;;
        *) echo "::error::deadcode root $line is outside the core module"; exit 2 ;;
    esac
done <"$ROOT/scripts/ci/deadcode-roots.txt"
if [ "${#roots[@]}" -eq 0 ]; then
    echo "::error::scripts/ci/deadcode-roots.txt lists no roots"
    exit 2
fi
echo "==> deadcode from ${roots[*]}"
run_deadcode "$ROOT/core" "$WORK/deadcode.json" linux/amd64 "${roots[@]}"
python3 "$FINDINGS" deadcode-keys "$WORK/deadcode.json" >"$WORK/deadcode.keys"
if [ "${#wasm_roots[@]}" -gt 0 ]; then
    # Only a target that compiled the same source declaration can establish
    # that a finding in another profile is live. Keep the frozen allowlist.
    selected_sources() { # dir report target packages...
        local dir="$1" report="$2" target="$3"
        shift 3
        (cd "$dir" && GOWORK=off GOOS="${target%/*}" GOARCH="${target#*/}" CGO_ENABLED=0 \
            go list -deps -f '{{range .GoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}' "$@" >"$report")
    }
    python3 -m unittest discover -s "$ROOT/scripts/ci" -p deadcode_profiles_test.py
    run_deadcode "$control" "$WORK/control-wasm.json" js/wasm .
    selected_sources "$control" "$WORK/control-native.sources" linux/amd64 .
    selected_sources "$control" "$WORK/control-wasm.sources" js/wasm .
    control_union="$(python3 "$ROOT/scripts/ci/deadcode_profiles.py" --module-dir "$control" \
        --profile "$WORK/control.json" "$WORK/control-native.sources" \
        --profile "$WORK/control-wasm.json" "$WORK/control-wasm.sources")"
    test "$control_union" = "example.com/deadcodecontrol planted"
    echo "deadcode control: both target-specific calls are live; the planted function remains dead"
    echo "==> js/wasm deadcode from ${wasm_roots[*]}"
    run_deadcode "$ROOT/core" "$WORK/deadcode-wasm.json" js/wasm "${wasm_roots[@]}"
    selected_sources "$ROOT/core" "$WORK/native.sources" linux/amd64 "${roots[@]}"
    selected_sources "$ROOT/core" "$WORK/wasm.sources" js/wasm "${wasm_roots[@]}"
    python3 "$ROOT/scripts/ci/deadcode_profiles.py" --module-dir "$ROOT/core" \
        --profile "$WORK/deadcode.json" "$WORK/native.sources" \
        --profile "$WORK/deadcode-wasm.json" "$WORK/wasm.sources" >"$WORK/deadcode.keys"
fi
if ! python3 "$FINDINGS" compare "$ALLOWLIST" "$WORK/deadcode.keys"; then
    echo "A new line above is unreachable from every shipped binary: call it from a shipped path, delete it, or declare its binary in scripts/ci/deadcode-roots.txt."
    echo "A stale line above means code was deleted or is now reached: remove that line from scripts/ci/deadcode-allowlist.txt in the same PR."
    exit 1
fi
