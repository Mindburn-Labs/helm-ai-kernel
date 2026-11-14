#!/usr/bin/env bash
# setup-commands of .github/workflows/ci.yml: prepares the runner for `make check`.
#
# A push to main is the exact commit the merge queue already gated: the queue
# squashes, tests the result as a merge_group run, then moves main to that same
# sha. Re-running the whole merge profile on it repeated about 46 runner-minutes
# per merge and proved nothing new. On a push to main this asks the Actions API
# for a successful merge_group CI run of this sha. If there is one, it records
# the run in $GITHUB_ENV and `make check` reports it instead of re-running the
# profile (scripts/ci/quality.py). If there is none (an admin push, an API
# error), it installs the tools and the full profile runs as on any change.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ "${GITHUB_EVENT_NAME:-}" == "push" && "${GITHUB_REF:-}" == "refs/heads/main" ]]; then
    : "${GITHUB_ENV:?GITHUB_ENV is required}"
    run_id="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml/runs?head_sha=${GITHUB_SHA}&event=merge_group&status=success&per_page=1" \
        --jq '.workflow_runs[0] | select(.head_sha == env.GITHUB_SHA and .conclusion == "success") | .id' 2>/dev/null || true)"
    if [[ "${run_id}" =~ ^[0-9]+$ ]]; then
        echo "main commit ${GITHUB_SHA} was gated by merge_group CI run ${run_id}"
        {
            echo "HELM_GATED_SHA=${GITHUB_SHA}"
            echo "HELM_GATED_BY_RUN=${run_id}"
        } >>"${GITHUB_ENV}"
        exit 0
    fi
    echo "::warning::no successful merge_group CI run found for ${GITHUB_SHA}; running the full merge profile"
fi

bash "${ROOT}/scripts/ci/install_check_tools.sh"
