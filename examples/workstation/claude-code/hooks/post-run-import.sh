#!/usr/bin/env bash
set -euo pipefail

artifact_dir="${1:?artifact directory required}"
receipt_out="${2:-/tmp/helm-workstation-claude-code-receipt.json}"
helm_bin="${HELM_BIN:-helm-ai-kernel}"

$helm_bin workstation import \
  --artifacts "$artifact_dir" \
  --out "$receipt_out"

$helm_bin workstation view --receipt "$receipt_out"
