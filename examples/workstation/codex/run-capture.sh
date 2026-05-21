#!/usr/bin/env bash
set -euo pipefail

goal="${1:-Codex workstation capture example}"
validation_command="${2:-go test ./core/pkg/workstation}"
workspace="${WORKSPACE:-$(pwd)}"
artifact_dir="${ARTIFACT_DIR:-/tmp/helm-workstation-codex-artifacts}"
receipt_out="${RECEIPT_OUT:-/tmp/helm-workstation-codex-receipt.json}"
helm_bin="${HELM_BIN:-helm-ai-kernel}"

rm -rf "$artifact_dir"

$helm_bin workstation capture start \
  --surface codex \
  --workspace "$workspace" \
  --goal "$goal" \
  --out "$artifact_dir"

$helm_bin workstation capture finish \
  --artifacts "$artifact_dir" \
  --validation-command "$validation_command" \
  --out "$receipt_out"

$helm_bin workstation view --receipt "$receipt_out"
