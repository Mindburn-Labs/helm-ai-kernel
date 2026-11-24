#!/usr/bin/env bash
set -euo pipefail
command -v gh >/dev/null
case "${CONSOLE_WORKFLOW_REF}" in
  refs/tags/*) ;;
  *)
    echo "::error::Console workflow_ref must be an immutable refs/tags/... source pin."
    exit 1
    ;;
esac
workflow_tag="${CONSOLE_WORKFLOW_REF#refs/tags/}"
workflow_sha="$(gh api "repos/${CONSOLE_REPOSITORY}/commits/${workflow_tag}" --jq '.sha')"
if [ "${workflow_sha}" != "${CONSOLE_SOURCE_SHA}" ]; then
  echo "::error::Console workflow_ref ${CONSOLE_WORKFLOW_REF} resolves to ${workflow_sha}, not pinned source ${CONSOLE_SOURCE_SHA}. Create a protected immutable tag at the pinned source before releasing."
  exit 1
fi
prior_runs="${RUNNER_TEMP}/console-local-sidecar-prior-runs.txt"
gh run list \
  --repo "${CONSOLE_REPOSITORY}" \
  --workflow release-local-sidecar.yml \
  --event workflow_dispatch \
  --limit 100 \
  --json databaseId \
  --jq '.[].databaseId' | sort > "${prior_runs}"
gh workflow run release-local-sidecar.yml \
  --repo "${CONSOLE_REPOSITORY}" \
  --ref "${workflow_tag}" \
  -f source_sha="${CONSOLE_SOURCE_SHA}" \
  -f kernel_release_version="${GITHUB_REF_NAME}"

expected_title="local-sidecar ${GITHUB_REF_NAME} ${CONSOLE_SOURCE_SHA}"
run_id=""
for _ in $(seq 1 60); do
  run_id="$(gh run list \
    --repo "${CONSOLE_REPOSITORY}" \
    --workflow release-local-sidecar.yml \
    --event workflow_dispatch \
    --limit 100 \
    --json databaseId,displayTitle \
    | python3 -c 'import json, pathlib, sys; expected, prior_path = sys.argv[1:]; prior = set(pathlib.Path(prior_path).read_text(encoding="utf-8").splitlines()); matches = [str(run["databaseId"]) for run in json.load(sys.stdin) if run.get("displayTitle") == expected and str(run["databaseId"]) not in prior]; sys.exit("multiple newly-dispatched Console sidecar runs matched the exact title") if len(matches) > 1 else print(matches[0] if matches else "")' "${expected_title}" "${prior_runs}")"
  if [ -n "${run_id}" ]; then
    break
  fi
  sleep 2
done
if [ -z "${run_id}" ]; then
  echo "::error::Console sidecar workflow did not expose one exact dispatched run"
  exit 1
fi

for _ in $(seq 1 180); do
  state="$(gh run view "${run_id}" --repo "${CONSOLE_REPOSITORY}" --json status,conclusion \
    | python3 -c 'import json, sys; run = json.load(sys.stdin); print(run.get("status", ""), run.get("conclusion") or "")')"
  status="${state%% *}"
  conclusion="${state#* }"
  if [ "${status}" = "completed" ]; then
    if [ "${conclusion}" != "success" ]; then
      echo "::error::Console sidecar workflow ${run_id} completed with ${conclusion}"
      exit 1
    fi
    echo "run_id=${run_id}" >> "${GITHUB_OUTPUT}"
    exit 0
  fi
  sleep 5
done
echo "::error::Console sidecar workflow ${run_id} did not complete"
exit 1
