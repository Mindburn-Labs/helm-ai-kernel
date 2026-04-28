#!/usr/bin/env bash
# OSS-Fuzz build script for helm-oss.
#
# Discovers every Fuzz* function under core/pkg/... and compiles each into
# a libFuzzer-compatible binary at $OUT/.
#
# Known fuzz target packages on the day this file was written:
#   core/pkg/canonicalize        (jcs_fuzz_test.go)
#   core/pkg/proofgraph          (node_fuzz_test.go)
#   core/pkg/crypto              (keyring_fuzz_test.go)
#   core/pkg/a2a                 (envelope_fuzz_test.go)
#   core/pkg/contracts           (receipt_fuzz_test.go)
#   core/pkg/saga                (orchestrator_fuzz_test.go)
#   core/pkg/threatscan          (scanner_fuzz_test.go)
#   core/pkg/guardian            (decision_fuzz_test.go)
#   core/pkg/compliance/jkg      (jkg_fuzz_test.go)
#   core/pkg/compliance/compiler (compiler_fuzz_test.go)
#   core/pkg/kernel              (csnf_fuzz_test.go)
# Net-new harnesses for parser, builder, store, and egress packages will
# be picked up automatically once they ship.
set -euo pipefail

cd "$SRC/helm-oss/core"

# Discover every package that contains at least one Fuzz* function.
# `go test -list 'Fuzz.*' ./...` emits Fuzz* identifiers followed by an
# `ok <pkg>` summary line per package. We track the package via the ok
# line and pair it with the preceding Fuzz* identifiers.
current_pkg=""
buffered_targets=()

flush_targets() {
    if [ -z "$current_pkg" ]; then
        buffered_targets=()
        return
    fi
    for target_name in "${buffered_targets[@]}"; do
        echo "compiling fuzz target: $current_pkg :: $target_name"
        compile_native_go_fuzzer "$current_pkg" "$target_name" "${target_name}_fuzzer"
    done
    buffered_targets=()
}

while IFS= read -r line; do
    case "$line" in
        ok\ *)
            current_pkg="$(printf '%s\n' "$line" | awk '{print $2}')"
            flush_targets
            ;;
        Fuzz*)
            buffered_targets+=("$line")
            ;;
    esac
done < <(go test -list 'Fuzz.*' ./... 2>/dev/null)

echo "fuzz binaries produced under $OUT/"
ls -la "$OUT/" || true
