#!/usr/bin/env bash
set -euo pipefail

target="${1:-memory://candidate}"
receipt_dir="${HELM_WORKSTATION_RECEIPT_DIR:-/tmp/helm-workstation-decisions}"
helm_bin="${HELM_BIN:-helm-ai-kernel}"

$helm_bin workstation capture wrap \
  --class memory \
  --target "$target" \
  --receipt-dir "$receipt_dir"
