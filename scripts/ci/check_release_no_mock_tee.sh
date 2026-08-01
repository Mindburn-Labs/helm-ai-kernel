#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# Fail closed: git grep exit 0 = forbidden match, 1 = clean, >1 = scanner error
# (including a scanned path that no longer exists). The old `if rg ...` treated
# a missing rg binary (exit 127) as "no matches" and passed while inert.
matches="$(git grep -nE 'AllowMock[[:space:]]*[:=][[:space:]]*true|HELM_TEE_ALLOW_MOCK[[:space:]]*[:=][[:space:]]*(1|true|yes)' -- .github/workflows scripts/release)" && rc=0 || rc=$?
if (( rc > 1 )); then
  echo "scanner error: git grep exited ${rc}" >&2
  exit "${rc}"
fi

if [[ -n "${matches}" ]]; then
  echo "${matches}"
  echo "FAIL: release verification must not enable mock TEE attestation" >&2
  exit 1
fi

echo "release TEE mock check passed"
