#!/usr/bin/env bash
# Runs the invariant amendment-marker gate over the commits this change brings:
# base..HEAD on a pull request or merge group, the pushed commit on main.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
base="origin/${GITHUB_BASE_REF:-main}"
range="${base}..HEAD"
if ! git rev-parse --verify --quiet "${base}^{commit}" >/dev/null || [[ "$(git rev-list --count "${range}")" -eq 0 ]]; then
  range="HEAD~1..HEAD"
fi
echo "concept-gate range: ${range}"
make concept-gate CONCEPT_RANGE="${range}"
