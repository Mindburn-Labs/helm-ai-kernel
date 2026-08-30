#!/usr/bin/env sh
# quantum_posture: this text-level guard checks classical Cosign evidence
# plumbing; it does not implement cryptographic controls.
# Workflow contract strings intentionally include literal GitHub expressions.
# shellcheck disable=SC2016
set -eu

require() {
  grep -Fq -- "$1" "$2" || {
    echo "missing AI OS image contract: $1 in $2" >&2
    exit 1
  }
}

workflow=${1:-.github/workflows/release-ai-os-image.yml}
legacy_workflow=${2:-.github/workflows/release.yml}
dockerfile=Dockerfile
build_doc=docs/supply-chain/kernel-image-build-v1.md
evidence_doc=docs/supply-chain/kernel-image-release-evidence-v1.md
build_uri=https://github.com/Mindburn-Labs/helm-ai-kernel/blob/main/docs/supply-chain/kernel-image-build-v1.md
evidence_uri=https://github.com/Mindburn-Labs/helm-ai-kernel/blob/main/docs/supply-chain/kernel-image-release-evidence-v1.md

require 'golang:1.25.13-alpine@sha256:' "$dockerfile"
require 'gcr.io/distroless/static-debian12:nonroot@sha256:' "$dockerfile"
require 'ENTRYPOINT ["helm-ai-kernel"]' "$dockerfile"
require 'CMD ["serve", "--policy", "/etc/helm-ai-kernel/release.high_risk.v3.toml", "--addr", "0.0.0.0", "--port", "8080", "--data-dir", "/var/lib/helm-ai-kernel"]' "$dockerfile"
require "$build_uri" "$build_doc"
require "$evidence_uri" "$evidence_doc"

if grep -E '^FROM ' "$dockerfile" | grep -Ev '@sha256:[0-9a-f]{64}([[:space:]]|$)' >/dev/null; then
  echo 'every Docker base must be pinned to a full SHA-256 digest' >&2
  exit 1
fi
if [ "$(grep -E '^USER ' "$dockerfile" | tail -n 1)" != 'USER nonroot:nonroot' ]; then
  echo 'the final Docker user must remain nonroot:nonroot' >&2
  exit 1
fi
if grep -Eq '^(ARG|ENV)[[:space:]].*(TOKEN|PRIVATE_KEY|PASSWORD|DATABASE_URL)' "$dockerfile"; then
  echo 'Dockerfile must not declare credential inputs or values' >&2
  exit 1
fi

for helper in \
  scripts/release/promote_immutable_image_tag.sh \
  scripts/release/require_latest_main_ci_success.sh \
  scripts/release/test_ai_os_image_release_contract.sh; do
  if [ ! -x "$helper" ]; then
    echo "release helper must be executable: $helper" >&2
    exit 1
  fi
done

require 'name: AI OS Kernel image' "$workflow"
require 'workflow_dispatch:' "$workflow"
require 'source_sha:' "$workflow"
require 'group: ai-os-kernel-image-${{ inputs.source_sha }}' "$workflow"
require 'cancel-in-progress: false' "$workflow"
require 'IMAGE_NAME: ghcr.io/mindburn-labs/helm-ai-kernel' "$workflow"
require "SLSA_BUILD_TYPE: $build_uri" "$workflow"
require "RELEASE_EVIDENCE_TYPE: $evidence_uri" "$workflow"
require 'STAGING_TAG: staging-${{ inputs.source_sha }}-${{ github.run_id }}-${{ github.run_attempt }}' "$workflow"
require 'WORKFLOW_IDENTITY: https://github.com/${{ github.repository }}/.github/workflows/release-ai-os-image.yml@refs/heads/main' "$workflow"
require 'name: release-production' "$workflow"
require 'RELEASE_ACTORS_JSON: ${{ vars.HELM_AI_OS_IMAGE_RELEASE_ACTORS }}' "$workflow"
require 'RELEASE_AUTHORITY_ARMED: ${{ vars.HELM_RELEASE_AUTHORITY_ARMED }}' "$workflow"
require 'REQUEST_ACTOR: ${{ github.actor }}' "$workflow"
require 'TRIGGERING_ACTOR: ${{ github.triggering_actor }}' "$workflow"
require 'jq -e --arg actor "${candidate}"' "$workflow"
require 'if [[ "${SOURCE_SHA}" != "${WORKFLOW_SHA}" ]]; then' "$workflow"
require 'if [[ "${SOURCE_SHA}" != "${main_tip}" ]]; then' "$workflow"
require 'if [[ "${SOURCE_SHA}" != "${promotion_main_tip}" ]]; then' "$workflow"
require 'head_sha=${SOURCE_SHA}&branch=main&status=completed' "$workflow"
require './scripts/release/require_latest_main_ci_success.sh "${GITHUB_REPOSITORY}" "${SOURCE_SHA}"' "$workflow"
require 'source_date_epoch="$(git show -s --format=%ct "${SOURCE_SHA}")"' "$workflow"
require 'created="$(date -u -d "@${source_date_epoch}" +%Y-%m-%dT%H:%M:%SZ)"' "$workflow"
require 'SOURCE_DATE_EPOCH=${{ steps.metadata.outputs.source_date_epoch }}' "$workflow"
require 'platforms: linux/amd64,linux/arm64' "$workflow"
require 'tags: ${{ env.IMAGE_NAME }}:${{ env.STAGING_TAG }}' "$workflow"
require 'org.opencontainers.image.source=https://github.com/${{ github.repository }}' "$workflow"
require 'org.opencontainers.image.revision=${{ env.SOURCE_SHA }}' "$workflow"
require "git+https://github.com/" "$workflow"
require '@refs/heads/main' "$workflow"
require 'output-file: sbom-linux-amd64.spdx.json' "$workflow"
require 'output-file: sbom-linux-arm64.spdx.json' "$workflow"
require 'cosign sign --yes "${image_ref}"' "$workflow"
require 'cosign attest --yes --type slsaprovenance1 --predicate slsa-provenance.json "${image_ref}"' "$workflow"
require 'cosign attest --yes --type spdxjson --predicate sbom-linux-amd64.spdx.json "${amd64_ref}"' "$workflow"
require 'cosign attest --yes --type spdxjson --predicate sbom-linux-arm64.spdx.json "${arm64_ref}"' "$workflow"
require '.predicate == $expected[0] and' "$workflow"
require '.subject[0].digest.sha256 == $expected_digest' "$workflow"
require '--predicate release-evidence.json' "$workflow"
require '--type "${RELEASE_EVIDENCE_TYPE}"' "$workflow"
require 'final_digest="$(./scripts/release/promote_immutable_image_tag.sh "${staging_ref}" "${final_tag}" "${expected_digest}")"' "$workflow"
require 'docker buildx imagetools inspect --raw "${final_tag}" > final-image-index.json' "$workflow"
require 'final-tag-digest-platforms-signature-and-evidence-verified' "$workflow"
require '${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:dev-sha-${{ inputs.source_sha }}' "$legacy_workflow"

trigger_count="$(awk '
  /^on:$/ { in_on = 1; next }
  in_on && /^[^[:space:]]/ { exit }
  in_on && /^  [[:alnum:]_]+:/ { count++ }
  END { print count + 0 }
' "$workflow")"
if [ "$trigger_count" -ne 1 ]; then
  echo 'release-ai-os-image.yml must remain manual-only' >&2
  exit 1
fi

if [ "$(grep -Fc 'git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc './scripts/release/require_latest_main_ci_success.sh "${GITHUB_REPOSITORY}" "${SOURCE_SHA}"' "$workflow")" -ne 2 ]; then
  echo 'current main and newest completed CI must be checked initially and immediately before promotion' >&2
  exit 1
fi
if [ "$(grep -Fc 'upload-artifact: false' "$workflow")" -ne 2 ]; then
  echo 'both platform SBOM actions must disable duplicate intermediate artifacts' >&2
  exit 1
fi
if [ "$(grep -Fc -- '--type spdxjson' "$workflow")" -ne 4 ]; then
  echo 'both platform SPDX predicates must be attested and verified' >&2
  exit 1
fi
if [ "$(grep -Ec '^[[:space:]]+tags:' "$workflow")" -ne 1 ]; then
  echo 'the build may publish exactly one staging tag before promotion' >&2
  exit 1
fi
if grep -Fq 'https://actions.github.io/buildtypes/workflow/v1' "$workflow"; then
  echo 'custom provenance must not claim the GitHub-hosted build type' >&2
  exit 1
fi
if grep -Fq 'git merge-base --is-ancestor' "$workflow"; then
  echo 'publication requires the exact current main tip, not an ancestor' >&2
  exit 1
fi
if grep -Fq 'docker buildx imagetools create --tag "${final_tag}"' "$workflow"; then
  echo 'immutable final-tag changes must use the tested fail-closed helper' >&2
  exit 1
fi
if grep -Eq 'date[[:space:]]+-u[[:space:]]+\+%Y' "$workflow"; then
  echo 'governed image metadata must derive from the source commit, not wall-clock time' >&2
  exit 1
fi
if grep -E '^[[:space:]]*uses:' "$workflow" | grep -Ev '@[0-9a-f]{40}([[:space:]]+#.*)?$' >/dev/null; then
  echo 'release-ai-os-image.yml contains an action that is not pinned to a commit SHA' >&2
  exit 1
fi

first_line() {
  grep -nF -- "$1" "$workflow" | head -n 1 | cut -d: -f 1
}

last_line() {
  grep -nF -- "$1" "$workflow" | tail -n 1 | cut -d: -f 1
}

authority_line="$(first_line '- name: Validate publication authority')"
checkout_line="$(first_line 'uses: actions/checkout@')"
staging_line="$(first_line 'tags: ${{ env.IMAGE_NAME }}:${{ env.STAGING_TAG }}')"
sbom_line="$(first_line 'output-file: sbom-linux-amd64.spdx.json')"
signature_line="$(first_line 'cosign sign --yes "${image_ref}"')"
evidence_line="$(first_line '> release-evidence.json')"
evidence_attest_line="$(first_line '--predicate release-evidence.json')"
promotion_ci_line="$(last_line './scripts/release/require_latest_main_ci_success.sh')"
promotion_line="$(first_line 'final_digest="$(./scripts/release/promote_immutable_image_tag.sh')"
final_platform_line="$(first_line 'final-image-index.json')"

if ! [ "$authority_line" -lt "$checkout_line" ] ||
  ! [ "$checkout_line" -lt "$staging_line" ] ||
  ! [ "$staging_line" -lt "$sbom_line" ] ||
  ! [ "$sbom_line" -lt "$signature_line" ] ||
  ! [ "$signature_line" -lt "$evidence_line" ] ||
  ! [ "$evidence_line" -lt "$evidence_attest_line" ] ||
  ! [ "$evidence_attest_line" -lt "$promotion_ci_line" ] ||
  ! [ "$promotion_ci_line" -lt "$promotion_line" ] ||
  ! [ "$promotion_line" -lt "$final_platform_line" ]; then
  echo 'release authority, staging evidence, and immutable promotion ordering is invalid' >&2
  exit 1
fi

echo 'AI OS Kernel image contract OK'
