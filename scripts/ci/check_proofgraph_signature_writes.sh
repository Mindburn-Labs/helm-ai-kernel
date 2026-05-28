#!/usr/bin/env bash
set -euo pipefail

violations="$(
  rg -n '\.Sig\s*=' \
    --glob '*.go' \
    --glob '!**/*_test.go' \
    --glob '!core/pkg/proofgraph/node.go' \
    . || true
)"

if [[ -n "${violations}" ]]; then
  echo "Node.Sig may only be assigned through core/pkg/proofgraph/node.go:"
  echo "${violations}"
  exit 1
fi
