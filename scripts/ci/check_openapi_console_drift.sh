#!/usr/bin/env bash
# Verify that the Console OpenAPI TypeScript schema is generated from source.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/helm-openapi-drift.XXXXXX")"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cd "$ROOT/apps/console"
npm ci

GENERATED="$TMP_DIR/schema.ts"
./node_modules/.bin/openapi-typescript ../../api/openapi/helm.openapi.yaml -o "$GENERATED"

diff -u src/api/schema.ts "$GENERATED" || {
    echo "::error::apps/console/src/api/schema.ts is out of sync with api/openapi/helm.openapi.yaml"
    echo "Run: cd apps/console && npm run generate:api"
    exit 1
}

echo "OpenAPI console generated type drift check passed."
