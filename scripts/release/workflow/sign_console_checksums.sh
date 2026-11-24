#!/usr/bin/env bash
# quantum_posture: invokes cosign to sign the release checksum manifest.
set -euo pipefail
cd console-release-assets
find . -maxdepth 1 -type f \
  \( \
    -name 'helm-console-local-sidecar-*' \
    -o -name 'helm-ai-kernel-*-console.tar.gz' \
    -o -name 'helm-ai-kernel-*-console.tar.gz.cosign.bundle' \
  \) \
  -print0 | sort -z | xargs -0 sha256sum > CONSOLE-SHA256SUMS.txt
test -s CONSOLE-SHA256SUMS.txt
cosign sign-blob --yes \
  --bundle CONSOLE-SHA256SUMS.txt.cosign.bundle \
  CONSOLE-SHA256SUMS.txt
