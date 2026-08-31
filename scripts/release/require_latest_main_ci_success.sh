#!/usr/bin/env sh
set -eu

if [ "$#" -ne 2 ]; then
  echo 'usage: require_latest_main_ci_success.sh <repository> <source-sha>' >&2
  exit 2
fi

repository=$1
source_sha=$2

latest="$(jq -s -r \
  --arg repository "$repository" \
  --arg source_sha "$source_sha" '
    [
      .[] | .workflow_runs[]? |
      select(
        .head_repository.full_name == $repository and
        .head_branch == "main" and
        .head_sha == $source_sha
      )
    ] |
    if length == 0 then
      empty
    else
      max_by([.run_number, .run_attempt, .id]) |
      [.id, .status, (.conclusion // "")] | @tsv
    end
  ')"

if [ -z "$latest" ]; then
  echo "no same-repository main CI run found for $source_sha" >&2
  exit 1
fi

run_id="$(printf '%s\n' "$latest" | cut -f 1)"
status="$(printf '%s\n' "$latest" | cut -f 2)"
conclusion="$(printf '%s\n' "$latest" | cut -f 3)"
if [ "$status" != completed ]; then
  echo "newest CI run $run_id is $status; refusing publication" >&2
  exit 1
fi
if [ "$conclusion" != success ]; then
  echo "newest CI run $run_id concluded $conclusion; refusing publication" >&2
  exit 1
fi

echo "newest CI run $run_id completed successfully"
