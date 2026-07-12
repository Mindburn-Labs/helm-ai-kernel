#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v rg >/dev/null 2>&1; then
  echo "presentation hygiene check requires ripgrep (rg) on PATH" >&2
  exit 127
fi

PATTERN='PLACEHOLDER|PlaceholderKey|ErrNotImplemented|simulated output|sha256-pending|viral adoption wedge|Verifiable AI Governance|Models propose|TODO|FIXME|WIP|coming soon|scaffold-only|placeholder public key'

set +e
rg -n --hidden -S "$PATTERN" \
  README.md CONTRIBUTING.md install.sh api core deploy docs examples protocols scripts tests \
  --glob '!**/node_modules/**' \
  --glob '!**/dist/**' \
  --glob '!**/target/**' \
  --glob '!**/package-lock.json' \
  --glob '!**/go.sum' \
  --glob '!sdk/**/generated/**' \
  --glob '!sdk/go/gen/**' \
  --glob '!sdk/python/helm_sdk/generated/**' \
  --glob '!scripts/check_documentation_*.py' \
  --glob '!scripts/sdk/gen.sh' \
  --glob '!tools/verify-presentation.sh'
presentation_status=$?
set -e

case "$presentation_status" in
  0)
    echo "presentation hygiene check failed: remove retained placeholder, unfinished, or marketing copy above" >&2
    exit 1
    ;;
  1)
    ;;
  *)
    echo "presentation hygiene search failed (rg exited $presentation_status)" >&2
    exit "$presentation_status"
    ;;
esac

set +e
git ls-files | rg '\.(db|sqlite|log|tar|tar\.gz|zip|exe|dll|so|dylib|pem|key|crt|p12|pfx|env)$' | rg -v '^reference_packs/.*evidence-?pack\.tar$'
pipeline_statuses=("${PIPESTATUS[@]}")
set -e

for rg_status in "${pipeline_statuses[@]:1}"; do
  if [[ "$rg_status" -gt 1 ]]; then
    echo "tracked artifact hygiene search failed (pipeline statuses: ${pipeline_statuses[*]})" >&2
    exit "$rg_status"
  fi
done

if [[ "${pipeline_statuses[0]}" -ne 0 ]]; then
  echo "tracked artifact hygiene inventory failed (git ls-files exited ${pipeline_statuses[0]})" >&2
  exit "${pipeline_statuses[0]}"
fi

if [[ "${pipeline_statuses[2]}" -eq 0 ]]; then
  echo "tracked artifact hygiene check failed" >&2
  exit 1
fi

exit 0
