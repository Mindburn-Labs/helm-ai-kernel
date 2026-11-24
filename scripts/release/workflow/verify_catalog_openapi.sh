#!/usr/bin/env bash
set -euo pipefail
if [ -z "${GH_TOKEN:-}" ]; then
  echo "::error::DOWNSTREAM_FANOUT_TOKEN with contents:read on Mindburn-Labs/contracts-catalog is required before release publication."
  exit 1
fi
kernel_blob="$(git hash-object --no-filters api/openapi/helm.openapi.yaml)"
catalog_blob="$(gh api 'repos/Mindburn-Labs/contracts-catalog/contents/api/specs/helm.openapi.yaml?ref=main' --jq '.sha')"
if [ "$kernel_blob" != "$catalog_blob" ]; then
  echo "::error::contracts-catalog main OpenAPI does not match this tag. Sync and merge the catalog before tagging ${GITHUB_REF_NAME}."
  exit 1
fi
