#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
core_dir="$repo_root/core"
helm_bin="${HELM_BIN:-go run ./cmd/helm-ai-kernel}"
work_dir="${WORK_DIR:-/tmp/helm-workstation-demo}"
artifact_dir="$work_dir/artifacts"
receipt_out="$work_dir/agent-run-receipt.json"
evidence_dir="$work_dir/evidencepack"

rm -rf "$work_dir"
mkdir -p "$work_dir"
mkdir -p "$artifact_dir"
cp -R "$repo_root/fixtures/workstation/demo/." "$artifact_dir/"

cd "$core_dir"

$helm_bin workstation import \
  --artifacts "$artifact_dir" \
  --out "$receipt_out"

$helm_bin workstation view --receipt "$receipt_out"
$helm_bin workstation denied --input "$receipt_out"
$helm_bin workstation memory --input "$receipt_out"
$helm_bin workstation loops --input "$receipt_out"
$helm_bin workstation evidence --receipt "$receipt_out" --out "$evidence_dir"
$helm_bin workstation certify --fixtures "$repo_root/fixtures/workstation" --mode high-risk-effect-capable

cat <<EOF

Demo artifacts:
  artifacts:    $artifact_dir
  receipt:      $receipt_out
  evidencepack: $evidence_dir

Console import example:
  curl -X POST \\
    -H 'Content-Type: application/json' \\
    --data-binary @$receipt_out \\
    http://localhost:8080/api/v1/workspaces/<workspace-id>/workstation/receipts/import
EOF
