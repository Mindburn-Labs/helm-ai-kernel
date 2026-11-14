#!/usr/bin/env bash
set -euo pipefail

mapfile -t modules < <(git ls-files '**/go.mod' 'go.mod' | xargs -n1 dirname | sort -u)

for module in "${modules[@]}"; do
  # Core is partitioned between make test (pkg and receipt_verify) and
  # make test-cli (all remaining packages). Do not run that suite again.
  [[ "$module" == core ]] && continue
  echo "==> GOWORK=off go test ./... (${module})"
  (cd "${module}" && GOWORK=off go test ./...)
done
