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

last_instruction() {
  keyword=$1
  grep -Ei "^[[:space:]]*${keyword}[[:space:]]" "$dockerfile" |
    tail -n 1 |
    awk -v keyword="$keyword" '{
      sub(/^[[:space:]]*/, "")
      sub(/^[^[:space:]]+[[:space:]]+/, "")
      sub(/[[:space:]]+$/, "")
      print keyword " " $0
    }'
}

logical_run_instructions() {
  awk '
    {
      line = $0
      sub(/\r$/, "", line)
      if (continued) {
        sub(/^[[:space:]]*/, "", line)
        instruction = instruction " " line
      } else {
        sub(/^[[:space:]]*/, "", line)
        if (line !~ /^[Rr][Uu][Nn][[:space:]]/) next
        instruction = line
      }
      if (instruction ~ /\\[[:space:]]*$/) {
        sub(/\\[[:space:]]*$/, "", instruction)
        continued = 1
      } else {
        print instruction
        instruction = ""
        continued = 0
      }
    }
    END { if (instruction != "") print instruction }
  ' "$dockerfile"
}

workflow=${1:-.github/workflows/release-ai-os-image.yml}
legacy_workflow=${2:-.github/workflows/release.yml}
dockerfile=${3:-Dockerfile}
dockerignore=${4:-.dockerignore}
build_doc=docs/supply-chain/kernel-image-build-v1.md
evidence_doc=docs/supply-chain/kernel-image-release-evidence-v1.md
build_uri=https://github.com/Mindburn-Labs/helm-ai-kernel/blob/main/docs/supply-chain/kernel-image-build-v1.md
evidence_uri=https://github.com/Mindburn-Labs/helm-ai-kernel/blob/main/docs/supply-chain/kernel-image-release-evidence-v1.md

require 'golang:1.25.13-alpine@sha256:' "$dockerfile"
require 'gcr.io/distroless/static-debian12:nonroot@sha256:' "$dockerfile"
require "$build_uri" "$build_doc"
require "$evidence_uri" "$evidence_doc"

if [ ! -f "$dockerignore" ]; then
  echo "Docker build context contract is missing: $dockerignore" >&2
  exit 1
fi
require_line() {
  grep -Fxq -- "$1" "$2" || {
    echo "missing exact Docker context contract: $1 in $2" >&2
    exit 1
  }
}
for dockerignore_entry in \
  '*' \
  '!Dockerfile' \
  '!core/' \
  '!core/**' \
  '!release.high_risk.v3.toml' \
  '!reference_packs/' \
  '!reference_packs/**' \
  '.git' \
  '.git/**' \
  'buildx-inspect.txt' \
  'ci-runs.json' \
  'promotion-ci-runs.json' \
  'image-index.json' \
  'final-image-index.json' \
  'platform-config-*.json' \
  'platform-labels-*.json' \
  'sbom-*.spdx.json' \
  'slsa-provenance*.json' \
  'release-evidence*.json' \
  'signature-verification.json' \
  'tmp/'; do
  require_line "$dockerignore_entry" "$dockerignore"
done

if grep -Ei '^[[:space:]]*FROM[[:space:]]' "$dockerfile" | grep -Ev '@sha256:[0-9a-f]{64}([[:space:]]|$)' >/dev/null; then
  echo 'every Docker base must be pinned to a full SHA-256 digest' >&2
  exit 1
fi
if [ "$(last_instruction USER)" != 'USER nonroot:nonroot' ]; then
  echo 'the final Docker user must remain nonroot:nonroot' >&2
  exit 1
fi
if [ "$(last_instruction ENTRYPOINT)" != 'ENTRYPOINT ["helm-ai-kernel"]' ]; then
  echo 'the final Docker entrypoint must remain the governed Kernel binary' >&2
  exit 1
fi
if [ "$(last_instruction CMD)" != 'CMD ["serve", "--policy", "/etc/helm-ai-kernel/release.high_risk.v3.toml", "--addr", "0.0.0.0", "--port", "8080", "--data-dir", "/var/lib/helm-ai-kernel"]' ]; then
  echo 'the final Docker command must remain the governed Kernel serve contract' >&2
  exit 1
fi
if grep -Eqi '^[[:space:]]*(ARG|ENV)[[:space:]].*(TOKEN|PRIVATE_KEY|PASSWORD|DATABASE_URL)' "$dockerfile"; then
  echo 'Dockerfile must not declare credential inputs or values' >&2
  exit 1
fi
if logical_run_instructions | grep -Eqi '(^|[[:space:];|&])apk[[:space:]]+([^[:space:];|&]+[[:space:]]+)*add([[:space:];|&]|$)'; then
  echo 'the governed build must not resolve mutable Alpine packages at build time' >&2
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
require 'OWNER_READBACK_TOKEN: ${{ secrets.HELM_GITHUB_OWNER_READ_TOKEN }}' "$workflow"
require 'run_started_at="$(GH_TOKEN="${OWNER_READBACK_TOKEN}" gh api' "$workflow"
require '.run_started_at' "$workflow"
require 'persist-credentials: false' "$workflow"
require 'release_environment_payload="$(GH_TOKEN="${OWNER_READBACK_TOKEN}" gh api' "$workflow"
require 'live_release_environment_payload="$(GH_TOKEN="${OWNER_READBACK_TOKEN}" gh api' "$workflow"
require '/deployment-branch-policies")' "$workflow"
require '.can_admins_bypass == false' "$workflow"
require 'protected_branches: false' "$workflow"
require 'custom_branch_policies: true' "$workflow"
require '[.protection_rules[].type] | sort' "$workflow"
require '== ["branch_policy", "required_reviewers"]' "$workflow"
require 'required_reviewers' "$workflow"
require 'branch_policy' "$workflow"
require '.prevent_self_review == true' "$workflow"
require '.reviewers[0].type == "User"' "$workflow"
require '.reviewers[0].reviewer.id' "$workflow"
require '.reviewers[0].reviewer.login == "mindburnlabs"' "$workflow"
require 'type == "number"' "$workflow"
require '.total_count == 1' "$workflow"
require '.branch_policies[0].name == "main"' "$workflow"
require '.branch_policies[0].type == "branch"' "$workflow"
require '/environments/${RELEASE_ENVIRONMENT}/variables/HELM_RELEASE_AUTHORITY_ARMED' "$workflow"
require '/actions/variables/HELM_AI_OS_IMAGE_RELEASE_ACTORS' "$workflow"
require 'if [[ "${live_release_authority}" != "release-production" ]]; then' "$workflow"
require 'if [[ "${live_release_authority}" != "${RELEASE_AUTHORITY_ARMED}" ]]; then' "$workflow"
require '. == ["mindburnlabs","peycheff-com"]' "$workflow"
require '--argjson configured "${RELEASE_ACTORS_JSON}"' "$workflow"
require 'REQUEST_ACTOR: ${{ github.actor }}' "$workflow"
require 'TRIGGERING_ACTOR: ${{ github.triggering_actor }}' "$workflow"
require 'if [[ "${GITHUB_RUN_ATTEMPT}" != "1" ]]; then' "$workflow"
require 'jq -e --arg actor "${candidate}"' "$workflow"
require '/actions/runs/${GITHUB_RUN_ID}/approvals' "$workflow"
require '.created_at > $run_started_at' "$workflow"
require '.environments | type == "array"' "$workflow"
require 'any(.[]; .name == $release_environment)' "$workflow"
require '.user.login != $request_actor' "$workflow"
require '.user.login != $triggering_actor' "$workflow"
require '/orgs/Mindburn-Labs/memberships/${owner}' "$workflow"
require 'for owner in mindburnlabs peycheff-com; do' "$workflow"
require 'if [[ "${SOURCE_SHA}" != "${WORKFLOW_SHA}" ]]; then' "$workflow"
require 'if [[ "${SOURCE_SHA}" != "${main_tip}" ]]; then' "$workflow"
require 'if [[ "${SOURCE_SHA}" != "${promotion_main_tip}" ]]; then' "$workflow"
require 'head_sha=${SOURCE_SHA}&branch=main&per_page=100' "$workflow"
require './scripts/release/require_latest_main_ci_success.sh "${GITHUB_REPOSITORY}" "${SOURCE_SHA}"' "$workflow"
require 'source_date_epoch="$(git show -s --format=%ct "${SOURCE_SHA}")"' "$workflow"
require 'created="$(date -u -d "@${source_date_epoch}" +%Y-%m-%dT%H:%M:%SZ)"' "$workflow"
require 'SOURCE_DATE_EPOCH=${{ steps.metadata.outputs.source_date_epoch }}' "$workflow"
require 'platforms: linux/amd64,linux/arm64' "$workflow"
require 'BUILDX_VERSION: v0.36.1' "$workflow"
require 'BUILDX_SHA256: 48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778' "$workflow"
require 'BUILDKIT_IMAGE: moby/buildkit:v0.32.2@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8' "$workflow"
require 'test "$(uname -m)" = "x86_64"' "$workflow"
require 'printf '\''%s  %s\n'\'' "${BUILDX_SHA256}" "${buildx_binary}" | sha256sum --check --strict' "$workflow"
require 'docker buildx version | grep -Fq "github.com/docker/buildx ${BUILDX_VERSION} "' "$workflow"
require '--driver-opt "image=${BUILDKIT_IMAGE}"' "$workflow"
require "grep -Eq '^BuildKit version:[[:space:]]+v0\\.32\\.2$' buildx-inspect.txt" "$workflow"
require 'tags: ${{ env.IMAGE_NAME }}:${{ env.STAGING_TAG }}' "$workflow"
require 'org.opencontainers.image.source=https://github.com/${{ github.repository }}' "$workflow"
require 'org.opencontainers.image.revision=${{ env.SOURCE_SHA }}' "$workflow"
require "--format '{{json .Image.Config}}'" "$workflow"
require '.Entrypoint == ["helm-ai-kernel"] and' "$workflow"
require '.Cmd == ["serve", "--policy", "/etc/helm-ai-kernel/release.high_risk.v3.toml", "--addr", "0.0.0.0", "--port", "8080", "--data-dir", "/var/lib/helm-ai-kernel"] and' "$workflow"
require '.User == "nonroot:nonroot" and' "$workflow"
require 'any(.Env[]?; . == "HELM_DATA_DIR=/var/lib/helm-ai-kernel") and' "$workflow"
require '(.ExposedPorts | keys | sort) == ["8080/tcp", "8081/tcp"]' "$workflow"
require 'name: Exercise digest-pinned native runtime and restart persistence' "$workflow"
require 'HELM_SMOKE_IMAGE: ${{ env.IMAGE_NAME }}@${{ steps.platforms.outputs.amd64_digest }}' "$workflow"
require 'docker pull --platform linux/amd64 "${HELM_SMOKE_IMAGE}"' "$workflow"
require 'bash scripts/ci/docker_smoke.sh' "$workflow"
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
require 'smoke: "health-denial-receipt-stop-restart-exact-readback-passed"' "$workflow"
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
run_start_read_pattern='run_started_at="$(GH_TOKEN="${OWNER_READBACK_TOKEN}" gh api'
if [ "$(grep -Fc 'if [[ "${RELEASE_AUTHORITY_ARMED:-}" != "release-production" ]]; then' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc 'RELEASE_ENVIRONMENT: release-production' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc 'for candidate in "${REQUEST_ACTOR}" "${TRIGGERING_ACTOR}"; do' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc 'jq -e --arg actor "${candidate}"' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc 'approval_history="$(GH_TOKEN="${OWNER_READBACK_TOKEN}" gh api "/repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/approvals")"' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc 'for owner in mindburnlabs peycheff-com; do' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '. == ["mindburnlabs","peycheff-com"]' "$workflow")" -ne 4 ] ||
  [ "$(grep -Fc 'GH_TOKEN="${OWNER_READBACK_TOKEN}" gh api' "$workflow")" -ne 14 ] ||
  [ "$(grep -Fc "$run_start_read_pattern" "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '/repos/${GITHUB_REPOSITORY}/environments/${RELEASE_ENVIRONMENT}")' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '/repos/${GITHUB_REPOSITORY}/environments/${RELEASE_ENVIRONMENT}/deployment-branch-policies")' "$workflow")" -ne 2 ]; then
  echo 'owner authority, actor allowlist, and run approval must be read back initially and immediately before promotion' >&2
  exit 1
fi
if [ "$(grep -Fc '.can_admins_bypass == false' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc 'protected_branches: false' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc 'custom_branch_policies: true' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '[.protection_rules[].type] | sort' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '== ["branch_policy", "required_reviewers"]' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '(.protection_rules | type == "array" and length == 2)' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '.prevent_self_review == true' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '(.reviewers | type == "array" and length == 1)' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '.reviewers[0].type == "User"' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '.reviewers[0].reviewer.id' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '.reviewers[0].reviewer.login == "mindburnlabs"' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc 'type == "number"' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '.total_count == 1' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '.branch_policies[0].name == "main"' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '.branch_policies[0].type == "branch"' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '.created_at > $run_started_at' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '.environments | type == "array"' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc 'any(.[]; .name == $release_environment)' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '.user.login != $request_actor' "$workflow")" -ne 2 ] ||
  [ "$(grep -Fc '.user.login != $triggering_actor' "$workflow")" -ne 2 ]; then
  echo 'environment protection and fresh distinct approval predicates must be exact in both checkpoints' >&2
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
if [ "$(grep -Fc -- '--predicate release-evidence.json' "$workflow")" -ne 2 ]; then
  echo 'both pre-promotion and finalized release evidence must be durably attested' >&2
  exit 1
fi
if grep -Fq 'status=completed&per_page=100' "$workflow"; then
  echo 'CI readback must include queued and in-progress newest attempts' >&2
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
config_line="$(first_line "--format '{{json .Image.Config}}'")"
runtime_line="$(first_line '- name: Exercise digest-pinned native runtime and restart persistence')"
sbom_line="$(first_line 'output-file: sbom-linux-amd64.spdx.json')"
signature_line="$(first_line 'cosign sign --yes "${image_ref}"')"
evidence_line="$(first_line '> release-evidence.json')"
evidence_attest_line="$(first_line '--predicate release-evidence.json')"
promotion_ci_line="$(last_line './scripts/release/require_latest_main_ci_success.sh')"
promotion_live_environment_read_line="$(last_line 'live_release_environment_payload="$(GH_TOKEN="${OWNER_READBACK_TOKEN}" gh api')"
promotion_live_branch_read_line="$(last_line 'live_deployment_branch_policies="$(GH_TOKEN="${OWNER_READBACK_TOKEN}" gh api')"
promotion_live_authority_read_line="$(last_line 'live_release_authority="$(GH_TOKEN="${OWNER_READBACK_TOKEN}" gh api')"
promotion_live_actors_read_line="$(last_line 'live_release_actors="$(GH_TOKEN="${OWNER_READBACK_TOKEN}" gh api')"
promotion_environment_validation_line="$(last_line '<<<"${live_release_environment_payload}" >/dev/null; then')"
promotion_branch_validation_line="$(last_line '<<<"${live_deployment_branch_policies}" >/dev/null; then')"
promotion_authority_line="$(last_line 'if [[ "${live_release_authority}" != "release-production" ]]; then')"
promotion_authority_binding_line="$(last_line 'if [[ "${live_release_authority}" != "${RELEASE_AUTHORITY_ARMED}" ]]; then')"
promotion_live_actor_validation_line="$(last_line '. == ["mindburnlabs","peycheff-com"]')"
promotion_actor_loop_line="$(last_line 'for candidate in "${REQUEST_ACTOR}" "${TRIGGERING_ACTOR}"; do')"
promotion_actor_check_line="$(last_line 'jq -e --arg actor "${candidate}"')"
promotion_approval_read_line="$(last_line 'approval_history="$(GH_TOKEN="${OWNER_READBACK_TOKEN}" gh api "/repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/approvals")"')"
promotion_approval_check_line="$(last_line '<<<"${approval_history}" >/dev/null; then')"
promotion_owner_loop_line="$(last_line 'for owner in mindburnlabs peycheff-com; do')"
promotion_owner_read_line="$(last_line '/orgs/Mindburn-Labs/memberships/${owner}')"
promotion_line="$(first_line 'final_digest="$(./scripts/release/promote_immutable_image_tag.sh')"
final_platform_line="$(first_line 'final-image-index.json')"
finalize_evidence_line="$(first_line '.promotion_status = "final-tag-digest-platforms-signature-and-evidence-verified"')"
final_attest_line="$(last_line '--predicate release-evidence.json')"

if ! [ "$authority_line" -lt "$checkout_line" ] ||
  ! [ "$checkout_line" -lt "$staging_line" ] ||
  ! [ "$staging_line" -lt "$config_line" ] ||
  ! [ "$config_line" -lt "$runtime_line" ] ||
  ! [ "$runtime_line" -lt "$sbom_line" ] ||
  ! [ "$sbom_line" -lt "$signature_line" ] ||
  ! [ "$signature_line" -lt "$evidence_line" ] ||
  ! [ "$evidence_line" -lt "$evidence_attest_line" ] ||
  ! [ "$evidence_attest_line" -lt "$promotion_live_environment_read_line" ] ||
  ! [ "$promotion_live_environment_read_line" -lt "$promotion_live_branch_read_line" ] ||
  ! [ "$promotion_live_branch_read_line" -lt "$promotion_live_authority_read_line" ] ||
  ! [ "$promotion_live_authority_read_line" -lt "$promotion_live_actors_read_line" ] ||
  ! [ "$promotion_live_actors_read_line" -lt "$promotion_environment_validation_line" ] ||
  ! [ "$promotion_environment_validation_line" -lt "$promotion_branch_validation_line" ] ||
  ! [ "$promotion_branch_validation_line" -lt "$promotion_authority_line" ] ||
  ! [ "$promotion_authority_line" -lt "$promotion_authority_binding_line" ] ||
  ! [ "$promotion_authority_binding_line" -lt "$promotion_live_actor_validation_line" ] ||
  ! [ "$promotion_live_actor_validation_line" -lt "$promotion_actor_loop_line" ] ||
  ! [ "$promotion_actor_loop_line" -lt "$promotion_actor_check_line" ] ||
  ! [ "$promotion_actor_check_line" -lt "$promotion_approval_read_line" ] ||
  ! [ "$promotion_approval_read_line" -lt "$promotion_approval_check_line" ] ||
  ! [ "$promotion_approval_check_line" -lt "$promotion_owner_loop_line" ] ||
  ! [ "$promotion_owner_loop_line" -lt "$promotion_owner_read_line" ] ||
  ! [ "$promotion_owner_read_line" -lt "$promotion_ci_line" ] ||
  ! [ "$promotion_ci_line" -lt "$promotion_line" ] ||
  ! [ "$promotion_line" -lt "$final_platform_line" ] ||
  ! [ "$final_platform_line" -lt "$finalize_evidence_line" ] ||
  ! [ "$finalize_evidence_line" -lt "$final_attest_line" ]; then
  echo 'release authority, staging evidence, and immutable promotion ordering is invalid' >&2
  exit 1
fi

echo 'AI OS Kernel image contract OK'
