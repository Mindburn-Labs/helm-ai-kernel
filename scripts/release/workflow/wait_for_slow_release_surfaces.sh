#!/usr/bin/env bash
set -uo pipefail
set +e
VERSION="${GITHUB_REF_NAME#v}"
only_args=()
for surface in $EVENTUALLY_CONSISTENT_SURFACES; do
  only_args+=(--only "$surface")
done
for attempt in $(seq 1 20); do
  if python3 scripts/release/check_version_drift.py \
    --expected-version "$VERSION" \
    published \
    --surface-timeout 10 \
    --rate-limit-retries 1 \
    "${only_args[@]}"; then
    echo "converged=true" >> "$GITHUB_OUTPUT"
    exit 0
  fi
  if [ "$attempt" -lt 20 ]; then
    echo "Eventually consistent surfaces have not converged (${attempt}/20); retrying."
    sleep 60
  fi
done
echo "converged=false" >> "$GITHUB_OUTPUT"
echo "::warning::Eventually consistent surfaces (${EVENTUALLY_CONSISTENT_SURFACES}) have not converged yet; the daily Version Drift Monitor reports drift if they stay behind."
exit 0
