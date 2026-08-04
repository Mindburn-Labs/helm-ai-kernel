#!/usr/bin/env bash
set -euo pipefail

# Fail-closed guard: Node.Sig may only be assigned in core/pkg/proofgraph/node.go.
# Uses git grep (always present in a checkout) instead of rg: on runners without
# rg the old `rg ... || true` swallowed exit 127 and the guard passed while inert.
# git grep exit codes: 0 = matches, 1 = no matches, anything else = scanner error.
pattern='\.Sig[[:space:]]*='
allowed='core/pkg/proofgraph/node.go'

# Self-test: the scanner must find the allowed assignment before an empty repo
# scan below can be trusted — a missing tool or broken pattern fails the step.
git grep -qE "${pattern}" -- "${allowed}" || {
  echo "self-test failed: pattern matched nothing in ${allowed}; scanner is inert" >&2
  exit 2
}

violations="$(git grep -nE "${pattern}" -- '*.go' ':!*_test.go' ":!${allowed}")" && rc=0 || rc=$?
if (( rc > 1 )); then
  echo "scanner error: git grep exited ${rc}" >&2
  exit "${rc}"
fi

if [[ -n "${violations}" ]]; then
  echo "Node.Sig may only be assigned through ${allowed}:"
  echo "${violations}"
  exit 1
fi
