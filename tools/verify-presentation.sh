#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PATTERN='PLACEHOLDER|PlaceholderKey|ErrNotImplemented|simulated output|sha256-pending|viral adoption wedge|Verifiable AI Governance|Models propose|TODO|FIXME|WIP|coming soon|scaffold-only|placeholder public key'

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
  --glob '!tools/verify-presentation.sh' && {
    echo "presentation hygiene check failed: remove retained placeholder, unfinished, or marketing copy above" >&2
    exit 1
  }

git ls-files | rg '\.(db|sqlite|log|tar|tar\.gz|zip|exe|dll|so|dylib|pem|key|crt|p12|pfx|env)$' && {
  echo "tracked artifact hygiene check failed" >&2
  exit 1
}

exit 0
