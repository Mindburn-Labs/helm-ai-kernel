#!/usr/bin/env bash
set -uo pipefail
set +e
VERSION="${GITHUB_REF_NAME#v}"
skip_args=()
if [ "$EVENTUAL_CONVERGED" = "false" ]; then
  for surface in $EVENTUALLY_CONSISTENT_SURFACES; do
    skip_args+=(--skip "$surface")
  done
fi
python3 scripts/release/check_version_drift.py \
  --expected-version "$VERSION" \
  --write-status version-status.json \
  published \
  "${skip_args[@]}"
status=$?
if [ "$status" -eq 75 ]; then
  echo "::warning::At least one published surface could not be read (rate limited); version-status.json records it as unknown, not drift."
  exit 0
fi
exit "$status"
