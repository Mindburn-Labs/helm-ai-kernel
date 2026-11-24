#!/usr/bin/env bash
# quantum_posture: uses gh to verify the signed image provenance.
set -euo pipefail
mkdir -p image-provenance
for variant in main slim; do
  digest="${MAIN_DIGEST}"
  if [[ "${variant}" == slim ]]; then digest="${SLIM_DIGEST}"; fi
  gh attestation verify "oci://${REGISTRY}/${IMAGE_NAME}@${digest}" \
    --repo "${GITHUB_REPOSITORY}" \
    --cert-identity "${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/.github/workflows/release.yml@${GITHUB_REF}" \
    --source-digest "${GITHUB_SHA}" --source-ref "${GITHUB_REF}" \
    --predicate-type https://slsa.dev/provenance/v1 \
    --format json > "image-provenance/${variant}.json"
done
