#!/usr/bin/env bash
set -euo pipefail

target="${1:-mcp://unknown-server/tool}"
receipt_dir="${HELM_WORKSTATION_RECEIPT_DIR:-/tmp/helm-workstation-decisions}"
helm_bin="${HELM_BIN:-helm-ai-kernel}"

$helm_bin workstation capture wrap \
  --class mcp \
  --target "$target" \
  --receipt-dir "$receipt_dir"
