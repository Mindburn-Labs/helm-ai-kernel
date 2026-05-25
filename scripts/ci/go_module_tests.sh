#!/usr/bin/env bash
set -euo pipefail

mapfile -t modules < <(git ls-files '**/go.mod' 'go.mod' | xargs -n1 dirname | sort -u)

for module in "${modules[@]}"; do
  echo "==> GOWORK=off go test ./... (${module})"
  (cd "${module}" && GOWORK=off go test ./...)
done
