#!/usr/bin/env bash
set -euo pipefail
assets=console-release-assets
layout_input=console-layout-input
mkdir -p "${assets}" "${layout_input}"
python3 scripts/release/console_local_sidecar.py stage \
  --input-dir console-local-sidecar \
  --output-dir "${assets}" \
  --pins release/console-local-sidecar-pins.json \
  --kernel-release "${GITHUB_REF_NAME}" \
  --expected-manifest-sha256 "${CONSOLE_LOCAL_SIDECAR_MANIFEST_SHA256}"
cp "${assets}"/* "${layout_input}/"
cp \
  bin/helm-ai-kernel-linux-amd64 \
  bin/helm-ai-kernel-linux-arm64 \
  bin/helm-ai-kernel-darwin-amd64 \
  bin/helm-ai-kernel-darwin-arm64 \
  "${layout_input}/"
python3 scripts/release/console_local_sidecar.py layout \
  --input-dir "${layout_input}" \
  --output-dir "${assets}" \
  --pins release/console-local-sidecar-pins.json \
  --kernel-release "${GITHUB_REF_NAME}" \
  --expected-manifest-sha256 "${CONSOLE_LOCAL_SIDECAR_MANIFEST_SHA256}"
