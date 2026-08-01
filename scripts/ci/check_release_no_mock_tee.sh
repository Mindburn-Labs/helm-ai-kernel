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
  # Each scan surface must be a real, non-symlink directory with tracked
  # content: git grep reads a symlink's blob (its target string), not the
  # linked files, and an emptied directory scans as clean — either would
  # silently narrow the guard instead of failing it.
  if [[ -L "${p}" || ! -d "${p}" ]]; then
    echo "scan path missing or a symlink: ${p}" >&2
    exit 2
  fi
  if [[ -z "$(git ls-files -- "${p}")" ]]; then
    echo "scan path has no tracked files: ${p}" >&2
    exit 2
  fi
  # Every tracked entry under a scan surface must be a regular file. Symlinks
  # (120000) scan as their target string, and gitlinks/submodules (160000) are
  # not descended into by git grep — either evades the scan. Whitelisting the
  # two regular-blob modes closes the entry-mode taxonomy outright.
  irregular="$(git ls-files -s -- "${p}" | awk '$1 != "100644" && $1 != "100755"')"
  if [[ -n "${irregular}" ]]; then
    echo "non-regular tracked entries under scan path ${p}:" >&2
    echo "${irregular}" >&2
    exit 2
  fi
done

# Self-test: the engine must find a known literal (this file's own pattern
# text) before an empty scan below can be trusted.
git grep -qE 'HELM_TEE_ALLOW_MOCK' -- scripts/ci/check_release_no_mock_tee.sh || {
  echo "self-test failed: scanner cannot find a known literal; scanner is inert" >&2
  exit 2
}

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
