#!/usr/bin/env bash
# quantum_posture: native and JavaScript/WASM checks use classical fixtures only.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/helm-receipt-wasm.XXXXXX")"
trap 'rm -rf "${scratch}"' EXIT
output="${1:-${scratch}/bundle}"
bash "${root}/scripts/build_receipt_verifier_wasm.sh" "${output}"
corpus="${root}/core/pkg/receiptverify/testdata/wasm-json-corpus.json"
(
  cd "${root}/core"
  GOWORK=off go run -mod=readonly ./pkg/receiptverify/testdata/native_corpus.go "${corpus}"
) >"${scratch}/native.json"
node --wasm-max-mem-pages=2048 "${root}/scripts/test_receipt_verifier_wasm.mjs" "${output}" "${corpus}" "${scratch}/native.json"
