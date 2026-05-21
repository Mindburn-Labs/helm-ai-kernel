#!/usr/bin/env bash
set -euo pipefail

goal="${1:-Claude Code workstation capture example}"
validation_command="${2:-go test ./core/pkg/workstation}"
workspace="${WORKSPACE:-$(pwd)}"
artifact_dir="${ARTIFACT_DIR:-/tmp/helm-workstation-claude-code-artifacts}"
receipt_out="${RECEIPT_OUT:-/tmp/helm-workstation-claude-code-receipt.json}"
helm_bin="${HELM_BIN:-helm-ai-kernel}"

rm -rf "$artifact_dir"

$helm_bin workstation capture start \
  --surface claude-code \
  --workspace "$workspace" \
  --goal "$goal" \
  --out "$artifact_dir"

$helm_bin workstation capture finish \
  --artifacts "$artifact_dir" \
  --validation-command "$validation_command" \
  --out "$receipt_out"

$helm_bin workstation view --receipt "$receipt_out"
