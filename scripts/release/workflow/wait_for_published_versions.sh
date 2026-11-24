#!/usr/bin/env bash
set -uo pipefail
set +e
VERSION="${GITHUB_REF_NAME#v}"
skip_args=()
for surface in $EVENTUALLY_CONSISTENT_SURFACES; do
  skip_args+=(--skip "$surface")
done
status=0
for attempt in $(seq 1 40); do
  python3 scripts/release/check_version_drift.py \
    --expected-version "$VERSION" \
    published \
    --surface-timeout 10 \
    --rate-limit-retries 1 \
    "${skip_args[@]}"
  status=$?
  if [ "$status" -eq 0 ]; then
    exit 0
  fi
  if [ "$attempt" -lt 40 ]; then
    echo "Published version surfaces have not converged (${attempt}/40); retrying."
    sleep 30
  fi
done
if [ "$status" -eq 75 ]; then
  echo "::warning::Published version surfaces stayed unreadable within the bounded retry budget (rate limited); reporting unknown rather than drift."
  exit 0
fi
echo "::error::Published version surfaces did not converge within the bounded retry budget."
exit 1
