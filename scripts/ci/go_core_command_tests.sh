#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../core"
export GOWORK=off

# Capture discovery before selecting packages so a failed go list cannot turn
# into a successful empty test run. make test owns pkg and receipt_verify.
module=$(go list -m)
inventory=$(go list ./...)
packages=()
while IFS= read -r package; do
  case "$package" in
    "$module/pkg"|"$module/pkg/"*|"$module/cmd/receipt_verify"|"$module/cmd/receipt_verify/"*) ;;
    "") ;;
    *) packages+=("$package") ;;
  esac
done <<< "$inventory"

if [[ ${#packages[@]} -eq 0 ]]; then
  echo "core command tests: no packages discovered" >&2
  exit 1
fi

echo "==> Core packages outside pkg and receipt_verify: ${#packages[@]}"
go test "${packages[@]}" -count=1
