#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if rg -n 'AllowMock\s*[:=]\s*true|HELM_TEE_ALLOW_MOCK\s*[:=]\s*(1|true|yes)' .github/workflows scripts/release; then
  echo "FAIL: release verification must not enable mock TEE attestation" >&2
  exit 1
fi

echo "release TEE mock check passed"
