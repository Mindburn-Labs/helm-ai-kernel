#!/usr/bin/env bash
set -euo pipefail
if ! [[ "${PUSH_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::Push event after value is not a full commit SHA: ${PUSH_COMMIT}"
  exit 1
fi
if ! [[ "${WORKFLOW_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::Workflow commit is not a full commit SHA: ${WORKFLOW_COMMIT}"
  exit 1
fi
# A tag push supplies the annotated tag object's SHA and the workflow
# runs on its target commit. Check both against the live ref.
ref_json="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${GITHUB_REF_NAME}")"
ref_type="$(jq -er '.object.type' <<<"${ref_json}")"
live_tag_object="$(jq -er '.object.sha' <<<"${ref_json}")"
if [ "${ref_type}" != "tag" ]; then
  echo "::error::Release ref ${GITHUB_REF_NAME} is ${ref_type}, not an annotated tag object."
  exit 1
fi
if [ "${PUSH_COMMIT}" != "${live_tag_object}" ]; then
  echo "::error::Pushed tag object ${PUSH_COMMIT} does not match the live ref object ${live_tag_object}; the tag moved after the push."
  exit 1
fi
tag_json="$(gh api "repos/${GITHUB_REPOSITORY}/git/tags/${live_tag_object}")"
target_type="$(jq -er '.object.type' <<<"${tag_json}")"
target_commit="$(jq -er '.object.sha' <<<"${tag_json}")"
if [ "${target_type}" != "commit" ]; then
  echo "::error::Annotated release tag points to ${target_type}, not a commit."
  exit 1
fi
if [ "${target_commit}" != "${WORKFLOW_COMMIT}" ]; then
  echo "::error::Annotated release tag resolves to ${target_commit}, not workflow commit ${WORKFLOW_COMMIT}."
  exit 1
fi
