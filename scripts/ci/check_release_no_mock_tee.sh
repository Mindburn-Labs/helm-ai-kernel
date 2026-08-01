#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# Fail closed: a missing scan path or a scanner error must fail the step, never
# pass it. git grep exits 1 both for "no matches" and for pathspecs matching
# nothing (verified on git 2.53), so path existence is asserted explicitly;
# exit codes: 0 = forbidden match, 1 = clean, >1 = scanner error. The old
# `if rg ...` treated a missing rg binary (exit 127) as "no matches".
scan_paths=(.github/workflows scripts/release)
for p in "${scan_paths[@]}"; do
  [[ -e "${p}" ]] || { echo "scan path missing: ${p}" >&2; exit 2; }
done

matches="$(git grep -nE 'AllowMock[[:space:]]*[:=][[:space:]]*true|HELM_TEE_ALLOW_MOCK[[:space:]]*[:=][[:space:]]*(1|true|yes)' -- "${scan_paths[@]}")" && rc=0 || rc=$?
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
