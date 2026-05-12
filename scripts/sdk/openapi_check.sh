#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FILES=(
  "sdk/go/client/types_gen.go"
  "sdk/java/src/main/java/labs/mindburn/helm/TypesGen.java"
  "sdk/python/helm_sdk/types_gen.py"
  "sdk/rust/src/types_gen.rs"
  "sdk/ts/src/types.gen.ts"
)

for file in "${FILES[@]}"; do
  mkdir -p "$TMP/$(dirname "$file")"
  cp "$ROOT/$file" "$TMP/$file"
done

bash "$ROOT/scripts/sdk/gen.sh"

status=0
for file in "${FILES[@]}"; do
  if ! cmp -s "$TMP/$file" "$ROOT/$file"; then
    echo "OpenAPI SDK drift: $file"
    diff -u "$TMP/$file" "$ROOT/$file" || true
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo "Regenerate SDK types with: bash scripts/sdk/gen.sh"
  exit "$status"
fi

echo "OpenAPI SDK types are current."
