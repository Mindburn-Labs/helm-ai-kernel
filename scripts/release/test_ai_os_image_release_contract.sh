#!/usr/bin/env sh
# quantum_posture: this mutation suite checks classical SHA-256 and Cosign
# release-evidence contracts; it adds no post-quantum cryptographic control.
# Mutation fixtures intentionally match literal GitHub and shell expressions.
# shellcheck disable=SC2016
set -eu

test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM

mock_docker="$test_dir/docker"
mock_log="$test_dir/docker.log"
mock_state="$test_dir/created"
mock_error="$test_dir/error.log"
expected_digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
other_digest=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
source_ref="ghcr.io/mindburn-labs/helm-ai-kernel@${expected_digest}"
final_tag=ghcr.io/mindburn-labs/helm-ai-kernel:sha-cccccccccccccccccccccccccccccccccccccccc

cat > "$mock_docker" <<'MOCK'
#!/usr/bin/env sh
set -eu
printf '%s\n' "$*" >> "$MOCK_DOCKER_LOG"

case "$*" in
  "buildx imagetools inspect "*" --format {{.Manifest.Digest}}")
    if [ -f "$MOCK_DOCKER_STATE" ]; then
      printf '%s\n' "$MOCK_EXPECTED_DIGEST"
      exit 0
    fi
    case "$MOCK_DOCKER_MODE" in
      identical) printf '%s\n' "$MOCK_EXPECTED_DIGEST" ;;
      conflict) printf '%s\n' "$MOCK_OTHER_DIGEST" ;;
      missing) echo 'manifest unknown' >&2; exit 1 ;;
      missing_not_found) echo 'ghcr.io/mindburn-labs/helm-ai-kernel:sha-500deadbeef: not found' >&2; exit 1 ;;
      missing_ghcr) echo 'ERROR: ghcr.io/mindburn-labs/helm-ai-kernel:sha-500deadbeef: not found' >&2; exit 1 ;;
      missing_404) echo '404 Not Found' >&2; exit 1 ;;
      auth) echo 'unauthorized: authentication required' >&2; exit 1 ;;
      transport) echo 'TLS handshake timeout' >&2; exit 1 ;;
      server) echo '500 Internal Server Error: manifest unknown' >&2; exit 1 ;;
      ambiguous) echo 'unexpected registry response' >&2; exit 1 ;;
      rate_limit) echo 'ERROR: 429 Too Many Requests (rate limit exceeded)' >&2; exit 1 ;;
      *) echo 'unknown mock mode' >&2; exit 2 ;;
    esac
    ;;
  "buildx imagetools create --tag "*)
    : > "$MOCK_DOCKER_STATE"
    ;;
  *)
    echo "unexpected docker invocation: $*" >&2
    exit 2
    ;;
esac
MOCK
chmod +x "$mock_docker"

run_promotion() {
  mode=$1
  : > "$mock_log"
  rm -f "$mock_state"
  DOCKER_BIN="$mock_docker" \
    MOCK_DOCKER_LOG="$mock_log" \
    MOCK_DOCKER_STATE="$mock_state" \
    MOCK_DOCKER_MODE="$mode" \
    MOCK_EXPECTED_DIGEST="$expected_digest" \
    MOCK_OTHER_DIGEST="$other_digest" \
    ./scripts/release/promote_immutable_image_tag.sh "$source_ref" "$final_tag" "$expected_digest"
}

if run_promotion conflict >/dev/null 2>"$mock_error"; then
  echo 'conflicting immutable tag was incorrectly repointed' >&2
  exit 1
fi
grep -Fq 'immutable tag conflict' "$mock_error"
if grep -Fq 'buildx imagetools create' "$mock_log"; then
  echo 'conflicting immutable tag reached the create command' >&2
  exit 1
fi

run_promotion identical >/dev/null
if grep -Fq 'buildx imagetools create' "$mock_log"; then
  echo 'identical immutable tag was unnecessarily rewritten' >&2
  exit 1
fi

for mode in missing missing_not_found missing_ghcr missing_404; do
  run_promotion "$mode" >/dev/null
  if [ "$(grep -Fc 'buildx imagetools create' "$mock_log")" -ne 1 ]; then
    echo "$mode immutable tag was not created exactly once" >&2
    exit 1
  fi
done

for mode in auth transport server ambiguous rate_limit; do
  if run_promotion "$mode" >/dev/null 2>"$mock_error"; then
    echo "$mode registry failure was incorrectly treated as a missing tag" >&2
    exit 1
  fi
  case "$mode" in
    auth) grep -Fq 'authorization failure' "$mock_error" ;;
    transport) grep -Fq 'transport failure' "$mock_error" ;;
    server) grep -Fq 'server failure' "$mock_error" ;;
    ambiguous) grep -Fq 'ambiguous registry failure' "$mock_error" ;;
    rate_limit) grep -Fq 'rate-limit response is ambiguous' "$mock_error" ;;
  esac || {
    echo "$mode registry failure was not classified explicitly" >&2
    exit 1
  }
  if grep -Fq 'buildx imagetools create' "$mock_log"; then
    echo "$mode registry failure reached the create command" >&2
    exit 1
  fi
done

repository=Mindburn-Labs/helm-ai-kernel
source_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
selector=./scripts/release/require_latest_main_ci_success.sh

if "$selector" "$repository" "$source_sha" >/dev/null 2>&1 <<'JSON'
{"workflow_runs":[
  {"id":100,"run_number":40,"run_attempt":1,"head_repository":{"full_name":"Mindburn-Labs/helm-ai-kernel"},"head_branch":"main","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"completed","conclusion":"success"},
  {"id":101,"run_number":41,"run_attempt":1,"head_repository":{"full_name":"Mindburn-Labs/helm-ai-kernel"},"head_branch":"main","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"completed","conclusion":"failure"}
]}
JSON
then
  echo 'stale successful CI run incorrectly authorized publication' >&2
  exit 1
fi

"$selector" "$repository" "$source_sha" >/dev/null <<'JSON'
{"workflow_runs":[
  {"id":200,"run_number":50,"run_attempt":1,"head_repository":{"full_name":"Mindburn-Labs/helm-ai-kernel"},"head_branch":"main","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"completed","conclusion":"failure"},
  {"id":201,"run_number":51,"run_attempt":1,"head_repository":{"full_name":"Mindburn-Labs/helm-ai-kernel"},"head_branch":"main","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"completed","conclusion":"success"}
]}
JSON

if "$selector" "$repository" "$source_sha" >/dev/null 2>&1 <<'JSON'
{"workflow_runs":[
  {"id":400,"run_number":70,"run_attempt":1,"head_repository":{"full_name":"Mindburn-Labs/helm-ai-kernel"},"head_branch":"main","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"completed","conclusion":"success"},
  {"id":400,"run_number":70,"run_attempt":2,"head_repository":{"full_name":"Mindburn-Labs/helm-ai-kernel"},"head_branch":"main","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"in_progress","conclusion":null}
]}
JSON
then
  echo 'older successful CI attempt incorrectly authorized while the newest attempt was running' >&2
  exit 1
fi

if "$selector" "$repository" "$source_sha" >/dev/null 2>&1 <<'JSON'
{"workflow_runs":[
  {"id":300,"run_number":60,"run_attempt":1,"head_repository":{"full_name":"fork/helm-ai-kernel"},"head_branch":"main","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"completed","conclusion":"success"},
  {"id":301,"run_number":61,"run_attempt":1,"head_repository":{"full_name":"Mindburn-Labs/helm-ai-kernel"},"head_branch":"feature","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"completed","conclusion":"success"}
]}
JSON
then
  echo 'foreign-repository or non-main CI incorrectly authorized publication' >&2
  exit 1
fi

./scripts/release/check_ai_os_image_contract.sh >/dev/null
workflow=.github/workflows/release-ai-os-image.yml
checker=./scripts/release/check_ai_os_image_contract.sh

# These fixtures mirror the GitHub REST provider shape, including both
# environment protection rules and the deployment-branch policy response.
provider_environment='{"name":"release-production","can_admins_bypass":false,"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true},"protection_rules":[{"id":101,"node_id":"PR_required","type":"required_reviewers","prevent_self_review":true,"reviewers":[{"type":"User","reviewer":{"login":"mindburnlabs","id":123456,"node_id":"U_owner","type":"User","site_admin":false,"avatar_url":"https://avatars.githubusercontent.com/u/123456?v=4","events_url":"https://api.github.com/users/mindburnlabs/events{/privacy}","followers_url":"https://api.github.com/users/mindburnlabs/followers","following_url":"https://api.github.com/users/mindburnlabs/following{/other_user}","gists_url":"https://api.github.com/users/mindburnlabs/gists{/gist_id}","gravatar_id":"","html_url":"https://github.com/mindburnlabs","organizations_url":"https://api.github.com/users/mindburnlabs/orgs","received_events_url":"https://api.github.com/users/mindburnlabs/received_events","repos_url":"https://api.github.com/users/mindburnlabs/repos","starred_url":"https://api.github.com/users/mindburnlabs/starred{/owner}{/repo}","subscriptions_url":"https://api.github.com/users/mindburnlabs/subscriptions","url":"https://api.github.com/users/mindburnlabs","user_view_type":"public"}}]},{"id":102,"node_id":"PR_branch","type":"branch_policy"}]}'
provider_branch_policies='{"total_count":1,"branch_policies":[{"id":201,"node_id":"BP_main","name":"main","type":"branch"}]}'
provider_approval='[{"environments":[{"name":"release-production","id":301}],"state":"approved","user":{"login":"peycheff-com"},"created_at":"2026-09-01T10:00:01Z"}]'
run_started_at=2026-09-01T10:00:00Z

assert_provider_authority() {
  environment_json=$1
  branch_policy_json=$2
  printf '%s\n' "$environment_json" | jq -e --arg environment release-production '
    .name == $environment and
    .can_admins_bypass == false and
    .deployment_branch_policy == {
      protected_branches: false,
      custom_branch_policies: true
    } and
    (.protection_rules | type == "array" and length == 2) and
    (([.protection_rules[].type] | sort) == ["branch_policy", "required_reviewers"]) and
    ([.protection_rules[] | select(.type == "required_reviewers")] | length == 1) and
    (first(.protection_rules[] | select(.type == "required_reviewers")) |
      (keys | sort) == ["id", "node_id", "prevent_self_review", "reviewers", "type"] and
      (.id | type == "number" and (try (floor == . and . > 0) catch false)) and
      (.node_id | type == "string" and length > 0) and
      .prevent_self_review == true and
      (.reviewers | type == "array" and length == 1) and
      (.reviewers[0] | (keys | sort) == ["reviewer", "type"] and .type == "User") and
      (.reviewers[0].reviewer | type == "object") and
      (.reviewers[0].reviewer.id | type == "number" and (try (floor == . and . > 0) catch false)) and
      (.reviewers[0].reviewer.node_id | type == "string" and length > 0) and
      .reviewers[0].reviewer.type == "User" and
      .reviewers[0].reviewer.site_admin == false and
      (.reviewers[0].reviewer.login == "mindburnlabs" or .reviewers[0].reviewer.login == "peycheff-com")) and
    (first(.protection_rules[] | select(.type == "branch_policy")) |
      (keys | sort) == ["id", "node_id", "type"] and
      (.id | type == "number" and (try (floor == . and . > 0) catch false)) and
      (.node_id | type == "string" and length > 0) and
      .type == "branch_policy")
  ' >/dev/null 2>&1 || return 1
  printf '%s\n' "$branch_policy_json" | jq -e '
    .total_count == 1 and
    (.branch_policies | type == "array" and length == 1) and
    (.branch_policies[0] |
      (keys | sort) == ["id", "name", "node_id", "type"] and
      (.id | type == "number" and (try (floor == . and . > 0) catch false)) and
      (.node_id | type == "string" and length > 0) and
      .name == "main" and
      .type == "branch")
  ' >/dev/null 2>&1
}

provider_grype_db_status='{"schemaVersion":"6.1.9","from":"https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9_2026-08-31T00:36:25Z_1788158251.tar.zst?checksum=sha256%3A70e70f6232f41281063bd2a0a20600758ae12d6e60ba571b16070f950e2f99d3","built":"2026-08-31T06:37:31Z","path":"/runner/_temp/grype-db/6/vulnerability.db","valid":true}'

assert_provider_grype_db_status() {
  printf '%s\n' "$1" | jq -e '
    type == "object" and
    (keys | sort) == ["built", "from", "path", "schemaVersion", "valid"] and
    (.schemaVersion | type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+$")) and
    (.from | type == "string" and startswith("https://grype.anchore.io/databases/")) and
    (.built | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
    (.path | type == "string" and length > 0) and
    .valid == true
  ' >/dev/null 2>&1
}

assert_provider_actors() {
  printf '%s\n' "$1" | jq -e '. == ["mindburnlabs","peycheff-com"]' >/dev/null
}

assert_provider_approval() {
  approval_json=$1
  approval_run_started_at=$2
  approval_request_actor=$3
  approval_triggering_actor=$4
  printf '%s\n' "$approval_json" | jq -e \
    --arg run_started_at "$approval_run_started_at" \
    --arg release_environment release-production \
    --arg request_actor "$approval_request_actor" \
    --arg triggering_actor "$approval_triggering_actor" '
    [
      .[] |
      select(
        .state == "approved" and
        (.created_at > $run_started_at) and
        (.environments | type == "array" and any(.[]; .name == $release_environment)) and
        (.user.login == "mindburnlabs" or .user.login == "peycheff-com") and
        .user.login != $request_actor and
        .user.login != $triggering_actor
      )
    ] | length > 0
  ' >/dev/null 2>&1
}

evidence_amd64_digest=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
evidence_arm64_digest=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
evidence_amd64_scan_digest=sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
evidence_arm64_scan_digest=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
evidence_db_status_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111
evidence_build_type=https://github.com/Mindburn-Labs/helm-ai-kernel/blob/main/docs/supply-chain/kernel-image-build-v1.md

assert_release_evidence_shape() {
  evidence_json=$1
  evidence_status=$2
  evidence_final_digest=$3
  printf '%s\n' "$evidence_json" | jq -e \
    --arg expected_status "$evidence_status" \
    --arg expected_final_digest "$evidence_final_digest" \
    --arg index_digest "$expected_digest" \
    --arg amd64_digest "$evidence_amd64_digest" \
    --arg arm64_digest "$evidence_arm64_digest" \
    --arg amd64_scan_digest "$evidence_amd64_scan_digest" \
    --arg arm64_scan_digest "$evidence_arm64_scan_digest" \
    --arg db_status_digest "$evidence_db_status_digest" \
    --arg build_type "$evidence_build_type" '
      (if $expected_status == "staging-digest-verified"
       then (keys | sort) == [
         "actor", "component", "cosign", "cve_gate", "default_command",
         "digest", "entrypoint", "final_tag", "healthcheck", "image",
         "oci_labels", "persistence", "platforms", "promotion_status",
         "release_environment", "runtime_verification", "schema", "slsa",
         "source_ref", "source_repository", "source_sha", "staging_tag",
         "triggering_actor", "workflow_file", "workflow_identity", "workflow_name",
         "workflow_ref", "workflow_run", "workflow_sha"
       ]
       else (keys | sort) == [
         "actor", "component", "cosign", "cve_gate", "default_command",
         "digest", "entrypoint", "final_tag", "final_tag_digest", "healthcheck",
         "image", "oci_labels", "persistence", "platforms", "promotion_status",
         "release_environment", "runtime_verification", "schema", "slsa",
         "source_ref", "source_repository", "source_sha", "staging_tag",
         "triggering_actor", "workflow_file", "workflow_identity", "workflow_name",
         "workflow_ref", "workflow_run", "workflow_sha"
       ]
       end) and
      .schema == "https://github.com/Mindburn-Labs/helm-ai-kernel/blob/main/docs/supply-chain/kernel-image-release-evidence-v1.md" and
      .component == "helm-ai-kernel" and
      .actor == "mindburnlabs" and
      .triggering_actor == "peycheff-com" and
      .release_environment == "release-production" and
      .source_repository == "Mindburn-Labs/helm-ai-kernel" and
      .source_ref == "refs/heads/main" and
      (.source_sha | type == "string" and test("^[0-9a-f]{40}$")) and
      .workflow_name == "AI OS Kernel image" and
      .workflow_file == ".github/workflows/release-ai-os-image.yml" and
      .workflow_ref == "refs/heads/main" and
      (.workflow_sha | type == "string" and test("^[0-9a-f]{40}$")) and
      .image == "ghcr.io/mindburn-labs/helm-ai-kernel" and
      .digest == $index_digest and
      .platforms == [
        {platform: "linux/amd64", digest: $amd64_digest, sbom: "sbom-linux-amd64.spdx.json"},
        {platform: "linux/arm64", digest: $arm64_digest, sbom: "sbom-linux-arm64.spdx.json"}
      ] and
      .cve_gate == {
        tool: "grype",
        scope: "os-and-library",
        fail_on: "high",
        status: "passed",
        database: {status: "grype-db-status.json", status_digest: $db_status_digest},
        platforms: [
          {platform: "linux/amd64", digest: $amd64_digest, report: "grype-linux-amd64.json", report_digest: $amd64_scan_digest},
          {platform: "linux/arm64", digest: $arm64_digest, report: "grype-linux-arm64.json", report_digest: $arm64_scan_digest}
        ]
      } and
      (.cve_gate.database.status_digest | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
      .slsa == {
        build_type: $build_type,
        index: {predicate: "slsa-provenance.json", attestation: "slsa-provenance.attestation.json"},
        platforms: [
          {platform: "linux/amd64", digest: $amd64_digest, predicate: "slsa-provenance-linux-amd64.json", attestation: "slsa-provenance-linux-amd64.attestation.json"},
          {platform: "linux/arm64", digest: $arm64_digest, predicate: "slsa-provenance-linux-arm64.json", attestation: "slsa-provenance-linux-arm64.attestation.json"}
        ]
      } and
      .promotion_status == $expected_status and
      (if $expected_status == "staging-digest-verified"
       then (has("final_tag_digest") | not)
       else .final_tag_digest == $expected_final_digest
       end)
    ' >/dev/null 2>&1
}

if ! assert_provider_authority "$provider_environment" "$provider_branch_policies" ||
  ! assert_provider_actors '["mindburnlabs","peycheff-com"]' ||
  ! assert_provider_approval "$provider_approval" "$run_started_at" mindburnlabs mindburnlabs ||
  ! assert_provider_grype_db_status "$provider_grype_db_status"; then
  echo 'provider-shaped release authority fixtures were not accepted' >&2
  exit 1
fi

for db_status_mutation in \
  "$(printf '%s\n' "$provider_grype_db_status" | jq -c '.extra = true')" \
  "$(printf '%s\n' "$provider_grype_db_status" | jq -c 'del(.schemaVersion)')" \
  "$(printf '%s\n' "$provider_grype_db_status" | jq -c '.schemaVersion = "v6.1.9"')" \
  "$(printf '%s\n' "$provider_grype_db_status" | jq -c '.from = "https://example.test/db"')" \
  "$(printf '%s\n' "$provider_grype_db_status" | jq -c '.built = "not-a-timestamp"')" \
  "$(printf '%s\n' "$provider_grype_db_status" | jq -c '.path = ""')" \
  "$(printf '%s\n' "$provider_grype_db_status" | jq -c '.valid = false')"; do
  if assert_provider_grype_db_status "$db_status_mutation"; then
    echo "invalid Grype database status fixture was accepted: $db_status_mutation" >&2
    exit 1
  fi
done

evidence_fixture="$(jq -cn \
  --arg schema 'https://github.com/Mindburn-Labs/helm-ai-kernel/blob/main/docs/supply-chain/kernel-image-release-evidence-v1.md' \
  --arg build_type "$evidence_build_type" \
  --arg source_sha "$source_sha" \
  --arg index_digest "$expected_digest" \
  --arg amd64_digest "$evidence_amd64_digest" \
  --arg arm64_digest "$evidence_arm64_digest" \
  --arg amd64_scan_digest "$evidence_amd64_scan_digest" \
  --arg arm64_scan_digest "$evidence_arm64_scan_digest" \
  --arg db_status_digest "$evidence_db_status_digest" '
  {
    schema: $schema,
    component: "helm-ai-kernel",
    actor: "mindburnlabs",
    triggering_actor: "peycheff-com",
    release_environment: "release-production",
    source_repository: "Mindburn-Labs/helm-ai-kernel",
    source_ref: "refs/heads/main",
    source_sha: $source_sha,
    workflow_name: "AI OS Kernel image",
    workflow_file: ".github/workflows/release-ai-os-image.yml",
    workflow_ref: "refs/heads/main",
    workflow_sha: $source_sha,
    workflow_identity: "https://github.com/Mindburn-Labs/helm-ai-kernel/.github/workflows/release-ai-os-image.yml@refs/heads/main",
    workflow_run: "https://github.com/Mindburn-Labs/helm-ai-kernel/actions/runs/123",
    image: "ghcr.io/mindburn-labs/helm-ai-kernel",
    staging_tag: "staging-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-123-1",
    final_tag: "sha-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    digest: $index_digest,
    platforms: [
      {platform: "linux/amd64", digest: $amd64_digest, sbom: "sbom-linux-amd64.spdx.json"},
      {platform: "linux/arm64", digest: $arm64_digest, sbom: "sbom-linux-arm64.spdx.json"}
    ],
    oci_labels: {
      "org.opencontainers.image.source": "https://github.com/Mindburn-Labs/helm-ai-kernel",
      "org.opencontainers.image.revision": $source_sha
    },
    entrypoint: "/usr/local/bin/helm-ai-kernel",
    default_command: "serve --policy /etc/helm-ai-kernel/release.high_risk.v3.toml --addr 0.0.0.0 --port 8080 --data-dir /var/lib/helm-ai-kernel",
    healthcheck: "GET /healthz on port 8080",
    persistence: "/var/lib/helm-ai-kernel",
    runtime_verification: {
      oci_config: "linux/amd64-and-linux/arm64-config-exactly-verified",
      exercised_platform: "linux/amd64",
      smoke: "health-denial-receipt-stop-restart-exact-readback-passed"
    },
    cve_gate: {
      tool: "grype",
      scope: "os-and-library",
      fail_on: "high",
      status: "passed",
      database: {status: "grype-db-status.json", status_digest: $db_status_digest},
      platforms: [
        {platform: "linux/amd64", digest: $amd64_digest, report: "grype-linux-amd64.json", report_digest: $amd64_scan_digest},
        {platform: "linux/arm64", digest: $arm64_digest, report: "grype-linux-arm64.json", report_digest: $arm64_scan_digest}
      ]
    },
    slsa: {
      build_type: $build_type,
      index: {predicate: "slsa-provenance.json", attestation: "slsa-provenance.attestation.json"},
      platforms: [
        {platform: "linux/amd64", digest: $amd64_digest, predicate: "slsa-provenance-linux-amd64.json", attestation: "slsa-provenance-linux-amd64.attestation.json"},
        {platform: "linux/arm64", digest: $arm64_digest, predicate: "slsa-provenance-linux-arm64.json", attestation: "slsa-provenance-linux-arm64.attestation.json"}
      ]
    },
    cosign: "keyless-signature-and-platform-attestations-exactly-verified",
    promotion_status: "staging-digest-verified"
  }
')"
if ! assert_release_evidence_shape "$evidence_fixture" staging-digest-verified ''; then
  echo 'provider-shaped release evidence fixture was not accepted' >&2
  exit 1
fi
final_evidence_fixture="$(printf '%s\n' "$evidence_fixture" | jq -c --arg final_digest "$expected_digest" '
  .promotion_status = "final-tag-digest-platforms-signature-and-evidence-verified" |
  .final_tag_digest = $final_digest
')"
if ! assert_release_evidence_shape "$final_evidence_fixture" final-tag-digest-platforms-signature-and-evidence-verified "$expected_digest"; then
  echo 'final provider-shaped release evidence fixture was not accepted' >&2
  exit 1
fi
if assert_release_evidence_shape "$(printf '%s\n' "$evidence_fixture" | jq -c '.actor = "other"')" staging-digest-verified '' ||
  assert_release_evidence_shape "$(printf '%s\n' "$evidence_fixture" | jq -c '.cve_gate.fail_on = "medium"')" staging-digest-verified '' ||
  assert_release_evidence_shape "$(printf '%s\n' "$evidence_fixture" | jq -c 'del(.cve_gate.database)')" staging-digest-verified '' ||
  assert_release_evidence_shape "$(printf '%s\n' "$evidence_fixture" | jq -c '.cve_gate.database.status_digest = "sha256:not-a-digest"')" staging-digest-verified '' ||
  assert_release_evidence_shape "$(printf '%s\n' "$evidence_fixture" | jq -c '.slsa.platforms[0].predicate = "slsa-provenance.json"')" staging-digest-verified '' ||
  assert_release_evidence_shape "$(printf '%s\n' "$evidence_fixture" | jq -c '.extra = true')" staging-digest-verified ''; then
  echo 'release evidence mutation was accepted' >&2
  exit 1
fi
if assert_release_evidence_shape "$(printf '%s\n' "$final_evidence_fixture" | jq -c 'del(.final_tag_digest)')" final-tag-digest-platforms-signature-and-evidence-verified "$expected_digest"; then
  echo 'final release evidence without final_tag_digest was accepted' >&2
  exit 1
fi

reject_provider_authority() {
  mutation=$1
  environment_json=$2
  branch_policy_json=${3:-$provider_branch_policies}
  if assert_provider_authority "$environment_json" "$branch_policy_json"; then
    echo "provider authority mutation was accepted: $mutation" >&2
    exit 1
  fi
}

reject_provider_authority 'missing required reviewer rule' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules = [.protection_rules[0]]')"
reject_provider_authority 'required reviewer outer rule extra field' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].extra = true')"
reject_provider_authority 'required reviewer outer rule missing id' \
  "$(printf '%s\n' "$provider_environment" | jq -c 'del(.protection_rules[0].id)')"
reject_provider_authority 'required reviewer outer rule missing node id' \
  "$(printf '%s\n' "$provider_environment" | jq -c 'del(.protection_rules[0].node_id)')"
reject_provider_authority 'required reviewer outer rule zero id' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].id = 0')"
reject_provider_authority 'required reviewer outer rule string id' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].id = "101"')"
reject_provider_authority 'required reviewer outer rule fractional id' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].id = 101.5')"
reject_provider_authority 'required reviewer outer rule empty node id' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].node_id = ""')"
reject_provider_authority 'required reviewer outer rule missing prevent-self-review' \
  "$(printf '%s\n' "$provider_environment" | jq -c 'del(.protection_rules[0].prevent_self_review)')"
reject_provider_authority 'required reviewer outer rule missing reviewers' \
  "$(printf '%s\n' "$provider_environment" | jq -c 'del(.protection_rules[0].reviewers)')"
reject_provider_authority 'required reviewer outer rule missing type' \
  "$(printf '%s\n' "$provider_environment" | jq -c 'del(.protection_rules[0].type)')"
reject_provider_authority 'extra unknown rule' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules += [{"type":"unknown"}]')"
reject_provider_authority 'unknown rule type' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[1].type = "unknown"')"
reject_provider_authority 'Team reviewer' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].reviewers[0].type = "Team"')"
reject_provider_authority 'reviewer entry extra field' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].reviewers[0].extra = true')"
reject_provider_authority 'reviewer entry missing reviewer' \
  "$(printf '%s\n' "$provider_environment" | jq -c 'del(.protection_rules[0].reviewers[0].reviewer)')"
reject_provider_authority 'reviewer entry missing type' \
  "$(printf '%s\n' "$provider_environment" | jq -c 'del(.protection_rules[0].reviewers[0].type)')"
reject_provider_authority 'multiple reviewers' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].reviewers += [{"type":"User","reviewer":{"login":"peycheff-com","id":654321}}]')"
reject_provider_authority 'reviewer outside owner set' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].reviewers[0].reviewer.login = "other"')"
reject_provider_authority 'reviewer User zero id' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].reviewers[0].reviewer.id = 0')"
reject_provider_authority 'reviewer User string id' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].reviewers[0].reviewer.id = "123456"')"
reject_provider_authority 'reviewer User fractional id' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].reviewers[0].reviewer.id = 123456.5')"
reject_provider_authority 'reviewer User missing id' \
  "$(printf '%s\n' "$provider_environment" | jq -c 'del(.protection_rules[0].reviewers[0].reviewer.id)')"
reject_provider_authority 'reviewer User empty node id' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].reviewers[0].reviewer.node_id = ""')"
reject_provider_authority 'reviewer User missing node id' \
  "$(printf '%s\n' "$provider_environment" | jq -c 'del(.protection_rules[0].reviewers[0].reviewer.node_id)')"
reject_provider_authority 'reviewer User wrong type' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].reviewers[0].reviewer.type = "Bot"')"
reject_provider_authority 'reviewer User missing type' \
  "$(printf '%s\n' "$provider_environment" | jq -c 'del(.protection_rules[0].reviewers[0].reviewer.type)')"
reject_provider_authority 'reviewer User site admin' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].reviewers[0].reviewer.site_admin = true')"
reject_provider_authority 'reviewer User missing site admin' \
  "$(printf '%s\n' "$provider_environment" | jq -c 'del(.protection_rules[0].reviewers[0].reviewer.site_admin)')"
reject_provider_authority 'administrator bypass' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.can_admins_bypass = true')"
reject_provider_authority 'self review enabled' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[0].prevent_self_review = false')"
reject_provider_authority 'protected branch policy' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.deployment_branch_policy.protected_branches = true')"
reject_provider_authority 'custom branch policy disabled' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.deployment_branch_policy.custom_branch_policies = false')"
reject_provider_authority 'extra deployment branch' \
  "$provider_environment" \
  "$(printf '%s\n' "$provider_branch_policies" | jq -c '.total_count = 2 | .branch_policies += [{"id":202,"name":"release","type":"branch"}]')"
reject_provider_authority 'wrong deployment branch name' \
  "$provider_environment" \
  "$(printf '%s\n' "$provider_branch_policies" | jq -c '.branch_policies[0].name = "release"')"
reject_provider_authority 'wrong deployment branch type' \
  "$provider_environment" \
  "$(printf '%s\n' "$provider_branch_policies" | jq -c '.branch_policies[0].type = "tag"')"

reject_provider_authority 'environment branch rule extra field' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[1].extra = true')"
reject_provider_authority 'environment branch rule missing id' \
  "$(printf '%s\n' "$provider_environment" | jq -c 'del(.protection_rules[1].id)')"
reject_provider_authority 'environment branch rule zero id' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[1].id = 0')"
reject_provider_authority 'environment branch rule string id' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[1].id = "102"')"
reject_provider_authority 'environment branch rule fractional id' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[1].id = 102.5')"
reject_provider_authority 'environment branch rule empty node id' \
  "$(printf '%s\n' "$provider_environment" | jq -c '.protection_rules[1].node_id = ""')"
reject_provider_authority 'environment branch rule missing node id' \
  "$(printf '%s\n' "$provider_environment" | jq -c 'del(.protection_rules[1].node_id)')"
reject_provider_authority 'environment branch rule missing type' \
  "$(printf '%s\n' "$provider_environment" | jq -c 'del(.protection_rules[1].type)')"
reject_provider_authority 'deployment branch extra field' \
  "$provider_environment" \
  "$(printf '%s\n' "$provider_branch_policies" | jq -c '.branch_policies[0].extra = true')"
reject_provider_authority 'deployment branch missing id' \
  "$provider_environment" \
  "$(printf '%s\n' "$provider_branch_policies" | jq -c 'del(.branch_policies[0].id)')"
reject_provider_authority 'deployment branch zero id' \
  "$provider_environment" \
  "$(printf '%s\n' "$provider_branch_policies" | jq -c '.branch_policies[0].id = 0')"
reject_provider_authority 'deployment branch string id' \
  "$provider_environment" \
  "$(printf '%s\n' "$provider_branch_policies" | jq -c '.branch_policies[0].id = "201"')"
reject_provider_authority 'deployment branch fractional id' \
  "$provider_environment" \
  "$(printf '%s\n' "$provider_branch_policies" | jq -c '.branch_policies[0].id = 201.5')"
reject_provider_authority 'deployment branch empty node id' \
  "$provider_environment" \
  "$(printf '%s\n' "$provider_branch_policies" | jq -c '.branch_policies[0].node_id = ""')"
reject_provider_authority 'deployment branch missing node id' \
  "$provider_environment" \
  "$(printf '%s\n' "$provider_branch_policies" | jq -c 'del(.branch_policies[0].node_id)')"
reject_provider_authority 'deployment branch missing name' \
  "$provider_environment" \
  "$(printf '%s\n' "$provider_branch_policies" | jq -c 'del(.branch_policies[0].name)')"
reject_provider_authority 'deployment branch missing type' \
  "$provider_environment" \
  "$(printf '%s\n' "$provider_branch_policies" | jq -c 'del(.branch_policies[0].type)')"

for actor_fixture in '["mindburnlabs"]' '["peycheff-com","mindburnlabs"]' '["mindburnlabs","peycheff-com","other"]'; do
  if assert_provider_actors "$actor_fixture"; then
    echo "non-exact release actor fixture was accepted: $actor_fixture" >&2
    exit 1
  fi
done

if assert_provider_approval "$(printf '%s\n' "$provider_approval" | jq -c '.[0].created_at = "2026-08-31T23:59:59Z"')" "$run_started_at" mindburnlabs mindburnlabs ||
  assert_provider_approval "$provider_approval" "$run_started_at" peycheff-com mindburnlabs ||
  assert_provider_approval "$provider_approval" "$run_started_at" mindburnlabs peycheff-com ||
  assert_provider_approval "$(printf '%s\n' "$provider_approval" | jq -c '.[0].environments[0].name = "other"')" "$run_started_at" mindburnlabs mindburnlabs; then
  echo 'stale, self, or wrong-environment approval fixture was accepted' >&2
  exit 1
fi

mutate_and_reject() {
  fixture=$1
  if "$checker" "$fixture" >/dev/null 2>&1; then
    echo "release contract mutation was not rejected: $fixture" >&2
    exit 1
  fi
}

sed 's/\["id", "node_id", "type"\]/["id", "node_id", "type", "extra"]/g' \
  "$workflow" > "$test_dir/loose-environment-branch-rule.yml"
mutate_and_reject "$test_dir/loose-environment-branch-rule.yml"

sed 's/\["id", "name", "node_id", "type"\]/["id", "name", "type"]/g' \
  "$workflow" > "$test_dir/missing-deployment-branch-node-id.yml"
mutate_and_reject "$test_dir/missing-deployment-branch-node-id.yml"

sed 's/\.id | type == "number" and (try (floor == \. and \. > 0) catch false)/.id | type == "number" and (try (floor == \. and \. >= 0) catch false)/g' \
  "$workflow" > "$test_dir/non-positive-branch-rule-id.yml"
mutate_and_reject "$test_dir/non-positive-branch-rule-id.yml"

sed 's/\.node_id | type == "string" and length > 0/.node_id | type == "string" and length >= 0/g' \
  "$workflow" > "$test_dir/empty-branch-rule-node-id.yml"
mutate_and_reject "$test_dir/empty-branch-rule-node-id.yml"

sed 's/\["id", "node_id", "prevent_self_review", "reviewers", "type"\]/["id", "node_id", "prevent_self_review", "reviewers", "type", "extra"]/g' \
  "$workflow" > "$test_dir/loose-required-reviewer-rule.yml"
mutate_and_reject "$test_dir/loose-required-reviewer-rule.yml"

sed 's/\["reviewer", "type"\]/["reviewer"]/g' \
  "$workflow" > "$test_dir/missing-reviewer-entry-type.yml"
mutate_and_reject "$test_dir/missing-reviewer-entry-type.yml"

sed 's/\.reviewers\[0\]\.reviewer\.site_admin == false/.reviewers[0].reviewer.site_admin == true/g' \
  "$workflow" > "$test_dir/allowlisted-site-admin-reviewer.yml"
mutate_and_reject "$test_dir/allowlisted-site-admin-reviewer.yml"

sed '/grype db update/d' \
  "$workflow" > "$test_dir/missing-grype-db-bootstrap.yml"
mutate_and_reject "$test_dir/missing-grype-db-bootstrap.yml"

sed '/grype db status --output json > grype-db-status.json/d' \
  "$workflow" > "$test_dir/missing-grype-db-status.yml"
mutate_and_reject "$test_dir/missing-grype-db-status.yml"

sed 's/(keys | sort) == \["built", "from", "path", "schemaVersion", "valid"\]/(keys | sort) != ["built", "from", "path", "schemaVersion", "valid"]/g' \
  "$workflow" > "$test_dir/open-grype-db-status.yml"
mutate_and_reject "$test_dir/open-grype-db-status.yml"

sed 's/\.valid == true/.valid == false/g' \
  "$workflow" > "$test_dir/invalid-grype-db-status.yml"
mutate_and_reject "$test_dir/invalid-grype-db-status.yml"

sed 's/status_digest=sha256:$(sha256sum grype-db-status.json/status_digest=sha256:$(sha256sum missing-grype-db-status.json/g' \
  "$workflow" > "$test_dir/unbound-grype-db-status-digest.yml"
mutate_and_reject "$test_dir/unbound-grype-db-status-digest.yml"

sed 's/\.name == "main"/.name == "release"/g' \
  "$workflow" > "$test_dir/loose-deployment-branch-name.yml"
mutate_and_reject "$test_dir/loose-deployment-branch-name.yml"

sed 's/\.type == "branch"/.type == "tag"/g' \
  "$workflow" > "$test_dir/loose-deployment-branch-type.yml"
mutate_and_reject "$test_dir/loose-deployment-branch-type.yml"

sed 's/--scope all-layers/--scope squashed/g' \
  "$workflow" > "$test_dir/incomplete-layer-scan.yml"
mutate_and_reject "$test_dir/incomplete-layer-scan.yml"

sed 's/--fail-on high/--fail-on medium/g' \
  "$workflow" > "$test_dir/weakened-cve-threshold.yml"
mutate_and_reject "$test_dir/weakened-cve-threshold.yml"

sed 's/GRYPE_DB_AUTO_UPDATE: "false"/GRYPE_DB_AUTO_UPDATE: "true"/g' \
  "$workflow" > "$test_dir/mutable-grype-db.yml"
mutate_and_reject "$test_dir/mutable-grype-db.yml"

sed 's/GRYPE_CHECK_FOR_APP_UPDATE: "false"/GRYPE_CHECK_FOR_APP_UPDATE: "true"/g' \
  "$workflow" > "$test_dir/mutable-grype-update-check.yml"
mutate_and_reject "$test_dir/mutable-grype-update-check.yml"

sed 's#IMAGE_REF: \${{ env.IMAGE_NAME }}@\${{ steps.platforms.outputs.amd64_digest }}#IMAGE_REF: \${{ env.IMAGE_NAME }}:\${{ env.STAGING_TAG }}#' \
  "$workflow" > "$test_dir/unbound-amd64-cve-digest.yml"
mutate_and_reject "$test_dir/unbound-amd64-cve-digest.yml"

sed 's#IMAGE_REF: \${{ env.IMAGE_NAME }}@\${{ steps.platforms.outputs.arm64_digest }}#IMAGE_REF: \${{ env.IMAGE_NAME }}:\${{ env.STAGING_TAG }}#' \
  "$workflow" > "$test_dir/unbound-arm64-cve-digest.yml"
mutate_and_reject "$test_dir/unbound-arm64-cve-digest.yml"

sed 's#write_slsa_predicate slsa-provenance-linux-amd64.json linux/amd64 "\${{ steps.platforms.outputs.amd64_digest }}"#write_slsa_predicate slsa-provenance-linux-amd64.json linux/amd64 "\${{ steps.build.outputs.digest }}"#' \
  "$workflow" > "$test_dir/unbound-amd64-slsa-digest.yml"
mutate_and_reject "$test_dir/unbound-amd64-slsa-digest.yml"

sed 's#write_slsa_predicate slsa-provenance-linux-arm64.json linux/arm64 "\${{ steps.platforms.outputs.arm64_digest }}"#write_slsa_predicate slsa-provenance-linux-arm64.json linux/arm64 "\${{ steps.build.outputs.digest }}"#' \
  "$workflow" > "$test_dir/unbound-arm64-slsa-digest.yml"
mutate_and_reject "$test_dir/unbound-arm64-slsa-digest.yml"

sed 's/\.actor == \$actor/.actor == "other"/' \
  "$workflow" > "$test_dir/unbound-evidence-actor.yml"
mutate_and_reject "$test_dir/unbound-evidence-actor.yml"

sed 's/\.cve_gate == {/true and/' \
  "$workflow" > "$test_dir/unbound-evidence-cve-gate.yml"
mutate_and_reject "$test_dir/unbound-evidence-cve-gate.yml"

sed 's/\.slsa == {/true and/' \
  "$workflow" > "$test_dir/unbound-evidence-slsa.yml"
mutate_and_reject "$test_dir/unbound-evidence-slsa.yml"

sed 's/\.final_tag_digest == \$final_digest/.final_tag_digest != \$final_digest/' \
  "$workflow" > "$test_dir/unbound-final-evidence-digest.yml"
mutate_and_reject "$test_dir/unbound-final-evidence-digest.yml"

sed '/cp release-evidence\.json release-evidence\.staging\.json/d' \
  "$workflow" > "$test_dir/unbound-final-evidence-fields.yml"
mutate_and_reject "$test_dir/unbound-final-evidence-fields.yml"

sed 's/(keys | sort) == \[/(keys | sort) != [/g' \
  "$workflow" > "$test_dir/open-evidence-shape.yml"
mutate_and_reject "$test_dir/open-evidence-shape.yml"

sed '/^            grype-linux-amd64\.json$/d' \
  "$workflow" > "$test_dir/missing-amd64-grype-upload.yml"
mutate_and_reject "$test_dir/missing-amd64-grype-upload.yml"

sed '/^            slsa-provenance-linux-arm64\.attestation\.json$/d' \
  "$workflow" > "$test_dir/missing-arm64-slsa-upload.yml"
mutate_and_reject "$test_dir/missing-arm64-slsa-upload.yml"

sed '/cosign attest --yes --type slsaprovenance1 --predicate slsa-provenance-linux-amd64\.json/d' \
  "$workflow" > "$test_dir/missing-amd64-slsa-attestation.yml"
mutate_and_reject "$test_dir/missing-amd64-slsa-attestation.yml"

sed 's/persist-credentials: false/persist-credentials: true/' \
  "$workflow" > "$test_dir/persisted-checkout-credentials.yml"
mutate_and_reject "$test_dir/persisted-checkout-credentials.yml"

sed 's/\["mindburnlabs","peycheff-com"\]/["mindburnlabs"]/' \
  "$workflow" > "$test_dir/non-exact-actor-allowlist.yml"
mutate_and_reject "$test_dir/non-exact-actor-allowlist.yml"

sed 's/\["branch_policy", "required_reviewers"\]/["branch_policy", "unknown"]/' \
  "$workflow" > "$test_dir/unknown-protection-rule.yml"
mutate_and_reject "$test_dir/unknown-protection-rule.yml"

sed 's/(\.protection_rules | type == "array" and length == 2)/(\.protection_rules | type == "array" and length == 3)/g' \
  "$workflow" > "$test_dir/extra-protection-rule.yml"
mutate_and_reject "$test_dir/extra-protection-rule.yml"

sed 's/\.type == "User"/.type == "Team"/g' \
  "$workflow" > "$test_dir/team-reviewer.yml"
mutate_and_reject "$test_dir/team-reviewer.yml"

sed 's/(\.reviewers | type == "array" and length == 1)/(\.reviewers | type == "array" and length == 2)/g' \
  "$workflow" > "$test_dir/multiple-reviewers.yml"
mutate_and_reject "$test_dir/multiple-reviewers.yml"

sed 's/\.can_admins_bypass == false/.can_admins_bypass == true/g' \
  "$workflow" > "$test_dir/admin-bypass.yml"
mutate_and_reject "$test_dir/admin-bypass.yml"

sed 's/protected_branches: false/protected_branches: true/g' \
  "$workflow" > "$test_dir/protected-branches.yml"
mutate_and_reject "$test_dir/protected-branches.yml"

sed 's/custom_branch_policies: true/custom_branch_policies: false/g' \
  "$workflow" > "$test_dir/custom-branches-disabled.yml"
mutate_and_reject "$test_dir/custom-branches-disabled.yml"

sed 's/\.prevent_self_review == true/.prevent_self_review == false/g' \
  "$workflow" > "$test_dir/self-review.yml"
mutate_and_reject "$test_dir/self-review.yml"

sed 's/\.created_at > \$run_started_at/.created_at >= \$run_started_at/g' \
  "$workflow" > "$test_dir/stale-approval-timestamp.yml"
mutate_and_reject "$test_dir/stale-approval-timestamp.yml"

sed 's/\.user.login != \$request_actor/.user.login == \$request_actor/g; s/\.user.login != \$triggering_actor/.user.login == \$triggering_actor/g' \
  "$workflow" > "$test_dir/self-approval.yml"
mutate_and_reject "$test_dir/self-approval.yml"

sed 's/any(\.\[\]; \.name == \$release_environment)/any(.[ ]; .name == \$release_environment)/g' \
  "$workflow" > "$test_dir/wrong-approval-environment.yml"
mutate_and_reject "$test_dir/wrong-approval-environment.yml"

sed 's/--jq '\''\.run_started_at'\''/--jq '\''\.missing'\''/g' \
  "$workflow" > "$test_dir/missing-run-start-time.yml"
mutate_and_reject "$test_dir/missing-run-start-time.yml"

sed 's/GH_TOKEN="\${OWNER_READBACK_TOKEN}" gh api/gh api/g' \
  "$workflow" > "$test_dir/unbound-owner-readback.yml"
mutate_and_reject "$test_dir/unbound-owner-readback.yml"

reject_dockerignore_mutation() {
  entry=$1
  fixture="$test_dir/missing-context.dockerignore"
  awk -v entry="$entry" '$0 != entry' .dockerignore > "$fixture"
  if "$checker" "$workflow" .github/workflows/release.yml Dockerfile "$fixture" >/dev/null 2>&1; then
    echo "Docker context mutation was not rejected: $entry" >&2
    exit 1
  fi
}

while IFS= read -r dockerignore_entry; do
  case "$dockerignore_entry" in
    ''|'#'*) continue ;;
  esac
  reject_dockerignore_mutation "$dockerignore_entry"
done < .dockerignore

sed -e 's/^USER /  user /' -e 's/^ENTRYPOINT /  entrypoint /' -e 's/^CMD /  cmd /' \
  Dockerfile > "$test_dir/lowercase-governed.Dockerfile"
"$checker" "$workflow" .github/workflows/release.yml "$test_dir/lowercase-governed.Dockerfile" >/dev/null

awk '{ print } END { print "  from alpine:latest" }' Dockerfile > "$test_dir/indented-unpinned.Dockerfile"
if "$checker" "$workflow" .github/workflows/release.yml "$test_dir/indented-unpinned.Dockerfile" >/dev/null 2>&1; then
  echo 'indented lowercase unpinned Docker base was not rejected' >&2
  exit 1
fi

awk '{ print } END { print "  run set -e; apk add --no-cache curl" }' Dockerfile > "$test_dir/compound-package-install.Dockerfile"
if "$checker" "$workflow" .github/workflows/release.yml "$test_dir/compound-package-install.Dockerfile" >/dev/null 2>&1; then
  echo 'compound mutable package installation was not rejected' >&2
  exit 1
fi

sed 's/cancel-in-progress: false/cancel-in-progress: true/' "$workflow" > "$test_dir/cancelling.yml"
mutate_and_reject "$test_dir/cancelling.yml"

sed 's/group: ai-os-kernel-image-/group: container-sha-/' "$workflow" > "$test_dir/wrong-tag-owner-concurrency.yml"
mutate_and_reject "$test_dir/wrong-tag-owner-concurrency.yml"

sed 's/source_date_epoch="$(git show -s --format=%ct "${SOURCE_SHA}")"/source_date_epoch="$(date +%s)"/' \
  "$workflow" > "$test_dir/wall-clock-metadata.yml"
mutate_and_reject "$test_dir/wall-clock-metadata.yml"

sed 's/SOURCE_DATE_EPOCH=${{ steps.metadata.outputs.source_date_epoch }}/SOURCE_DATE_EPOCH=0/' \
  "$workflow" > "$test_dir/unbound-source-date-epoch.yml"
mutate_and_reject "$test_dir/unbound-source-date-epoch.yml"

sed 's/BUILDX_VERSION: v0.36.1/BUILDX_VERSION: latest/' \
  "$workflow" > "$test_dir/floating-buildx.yml"
mutate_and_reject "$test_dir/floating-buildx.yml"

sed 's/BUILDX_SHA256: 48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778/BUILDX_SHA256: 0000000000000000000000000000000000000000000000000000000000000000/' \
  "$workflow" > "$test_dir/unbound-buildx-artifact.yml"
mutate_and_reject "$test_dir/unbound-buildx-artifact.yml"

sed 's#BUILDKIT_IMAGE: moby/buildkit:v0.32.2@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8#BUILDKIT_IMAGE: moby/buildkit:latest#' \
  "$workflow" > "$test_dir/floating-buildkit.yml"
mutate_and_reject "$test_dir/floating-buildkit.yml"

sed "s/--format '{{json \.Image\.Config}}'/--format '{{json .Image.Config.Labels}}'/" \
  "$workflow" > "$test_dir/missing-platform-config-inspection.yml"
mutate_and_reject "$test_dir/missing-platform-config-inspection.yml"

awk '
  /\.Cmd == \["serve"/ { print "              true and"; next }
  { print }
' "$workflow" > "$test_dir/unbound-platform-command.yml"
mutate_and_reject "$test_dir/unbound-platform-command.yml"

awk '
  /any\(\.Env\[\]\?; \. == "HELM_DATA_DIR=/ { print "              true and"; next }
  { print }
' "$workflow" > "$test_dir/unbound-platform-data-dir.yml"
mutate_and_reject "$test_dir/unbound-platform-data-dir.yml"

sed 's|          bash scripts/ci/docker_smoke.sh|          true # mutation: skip runtime persistence smoke|' \
  "$workflow" > "$test_dir/missing-runtime-smoke.yml"
mutate_and_reject "$test_dir/missing-runtime-smoke.yml"

sed 's/^assert_decision_receipt_binding$/true # mutation: skip decision receipt binding/' \
  scripts/ci/docker_smoke.sh > "$test_dir/missing-decision-receipt-binding.sh"
if python3 - "$test_dir/missing-decision-receipt-binding.sh" >/dev/null 2>&1 <<'PY'
import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location("smoke_hardening", "scripts/ci/check_docker_smoke_hardening.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.check_docker_smoke(pathlib.Path(sys.argv[1]))
PY
then
  echo 'missing decision-to-receipt binding call was not rejected' >&2
  exit 1
fi

sed 's/:dev-sha-${{ inputs.source_sha }}/:sha-${{ inputs.source_sha }}/' \
  .github/workflows/release.yml > "$test_dir/legacy-final-tag-collision.yml"
if "$checker" "$workflow" "$test_dir/legacy-final-tag-collision.yml" >/dev/null 2>&1; then
  echo 'legacy dev publisher was allowed to collide with the governed immutable tag namespace' >&2
  exit 1
fi

sed 's/TRIGGERING_ACTOR: \${{ github.triggering_actor }}/TRIGGERING_ACTOR: \${{ github.actor }}/' \
  "$workflow" > "$test_dir/unbound-triggering-actor.yml"
mutate_and_reject "$test_dir/unbound-triggering-actor.yml"

sed '/OWNER_READBACK_TOKEN: \${{ secrets.HELM_GITHUB_OWNER_READ_TOKEN }}/d' \
  "$workflow" > "$test_dir/missing-owner-readback-token.yml"
mutate_and_reject "$test_dir/missing-owner-readback-token.yml"

sed '/INITIAL_LIVE_RELEASE_AUTHORITY=%s/d; /INITIAL_LIVE_RELEASE_ACTORS_SHA256=%s/d' \
  "$workflow" > "$test_dir/missing-initial-live-authority-persistence.yml"
mutate_and_reject "$test_dir/missing-initial-live-authority-persistence.yml"

sed '/INITIAL_LIVE_RELEASE_AUTHORITY}/d' \
  "$workflow" > "$test_dir/missing-final-live-authority-comparison.yml"
mutate_and_reject "$test_dir/missing-final-live-authority-comparison.yml"

sed '/INITIAL_LIVE_RELEASE_ACTORS_SHA256}/d' \
  "$workflow" > "$test_dir/missing-final-live-actor-digest-comparison.yml"
mutate_and_reject "$test_dir/missing-final-live-actor-digest-comparison.yml"

sed 's/GIT_CONFIG_VALUE_0="AUTHORIZATION: bearer \${OWNER_READBACK_TOKEN}"/GIT_CONFIG_VALUE_0="AUTHORIZATION: bearer \${GH_TOKEN}"/g' \
  "$workflow" > "$test_dir/unbound-current-main-readback.yml"
mutate_and_reject "$test_dir/unbound-current-main-readback.yml"

sed 's/GH_TOKEN="\${OWNER_READBACK_TOKEN}" gh api --paginate/gh api --paginate/g' \
  "$workflow" > "$test_dir/unbound-ci-readback.yml"
mutate_and_reject "$test_dir/unbound-ci-readback.yml"

sed 's#actions/runs/${GITHUB_RUN_ID}/approvals#actions/runs/${GITHUB_RUN_ID}#' \
  "$workflow" > "$test_dir/missing-run-approval-readback.yml"
mutate_and_reject "$test_dir/missing-run-approval-readback.yml"

sed 's/if \[\[ "${GITHUB_RUN_ATTEMPT}" != "1" \]\]; then/if false; then/' \
  "$workflow" > "$test_dir/replayed-owner-approval.yml"
mutate_and_reject "$test_dir/replayed-owner-approval.yml"

awk '
  /if \[\[ "\${RELEASE_AUTHORITY_ARMED:-}" != "release-production" \]\]; then/ {
    seen++
    if (seen == 2) {
      print "          if false; then # mutation: skip final authority recheck"
      next
    }
  }
  { print }
' "$workflow" > "$test_dir/stale-final-authority.yml"
mutate_and_reject "$test_dir/stale-final-authority.yml"

sed 's/if \[\[ "${live_release_authority}" != "release-production" \]\]; then/if false; then/' \
  "$workflow" > "$test_dir/stale-live-authority-readback.yml"
mutate_and_reject "$test_dir/stale-live-authority-readback.yml"

sed 's/if \[\[ "${live_release_authority}" != "${RELEASE_AUTHORITY_ARMED}" \]\]; then/if false; then/' \
  "$workflow" > "$test_dir/unbound-live-authority-snapshot.yml"
mutate_and_reject "$test_dir/unbound-live-authority-snapshot.yml"

sed 's#/actions/variables/HELM_AI_OS_IMAGE_RELEASE_ACTORS#/environments/${RELEASE_ENVIRONMENT}/variables/HELM_AI_OS_IMAGE_RELEASE_ACTORS#' \
  "$workflow" > "$test_dir/wrong-live-actor-variable-scope.yml"
mutate_and_reject "$test_dir/wrong-live-actor-variable-scope.yml"

awk '
  /for candidate in "\$\{REQUEST_ACTOR\}" "\$\{TRIGGERING_ACTOR\}"; do/ {
    seen++
    if (seen == 2) {
      print "          for candidate in; do # mutation: skip final actor allowlist recheck"
      next
    }
  }
  { print }
' "$workflow" > "$test_dir/missing-final-actor-readback.yml"
mutate_and_reject "$test_dir/missing-final-actor-readback.yml"

awk '
  /approval_history="\$\(GH_TOKEN="\$\{OWNER_READBACK_TOKEN\}" gh api .*\/approvals/ {
    seen++
    if (seen == 2) {
      print "          approval_history=\"[]\" # mutation: skip final approval readback"
      next
    }
  }
  { print }
' "$workflow" > "$test_dir/missing-final-approval-readback.yml"
mutate_and_reject "$test_dir/missing-final-approval-readback.yml"

awk '
  /for owner in mindburnlabs peycheff-com; do/ {
    seen++
    if (seen == 2) {
      print "          for owner in mindburnlabs; do # mutation: skip final second-owner readback"
      next
    }
  }
  { print }
' "$workflow" > "$test_dir/missing-final-owner-readback.yml"
mutate_and_reject "$test_dir/missing-final-owner-readback.yml"

awk '
  /^      - name: Reauthorize and promote the verified digest$/ { in_final = 1 }
  in_final && /^          RELEASE_ENVIRONMENT: release-production$/ { next }
  in_final && /^      - name:/ && $0 !~ /Reauthorize and promote the verified digest/ { in_final = 0 }
  { print }
' "$workflow" > "$test_dir/missing-final-release-environment.yml"
mutate_and_reject "$test_dir/missing-final-release-environment.yml"

awk '
  /approval_history="\$\(GH_TOKEN="\$\{OWNER_READBACK_TOKEN\}" gh api .*\/approvals/ {
    seen++
    if (seen == 2) {
      held = $0
      next
    }
  }
  /for owner in mindburnlabs peycheff-com; do/ && held != "" {
    print
    print held " # mutation: approval readback moved after owner loop"
    held = ""
    next
  }
  { print }
' "$workflow" > "$test_dir/reordered-final-authority.yml"
mutate_and_reject "$test_dir/reordered-final-authority.yml"

sed 's/name: release-production/name: unprotected-release/' "$workflow" > "$test_dir/wrong-environment.yml"
mutate_and_reject "$test_dir/wrong-environment.yml"

sed 's/if \[\[ "\${SOURCE_SHA}" != "\${WORKFLOW_SHA}" \]\]; then/if false; then/' \
  "$workflow" > "$test_dir/detached-dispatch-source.yml"
mutate_and_reject "$test_dir/detached-dispatch-source.yml"

sed 's/if \[\[ "\${SOURCE_SHA}" != "\${main_tip}" \]\]; then/if false; then/' \
  "$workflow" > "$test_dir/stale-current-main.yml"
mutate_and_reject "$test_dir/stale-current-main.yml"

awk '
  index($0, "./scripts/release/require_latest_main_ci_success.sh") {
    seen++
    if (seen == 2) {
      print "          true # mutation: skip immediate pre-promotion CI recheck"
      next
    }
  }
  { print }
' "$workflow" > "$test_dir/stale-promotion-ci.yml"
mutate_and_reject "$test_dir/stale-promotion-ci.yml"

sed 's/branch=main&per_page=100/branch=main\&status=completed\&per_page=100/g' \
  "$workflow" > "$test_dir/completed-only-ci-readback.yml"
mutate_and_reject "$test_dir/completed-only-ci-readback.yml"

sed 's/tags: \${{ env.IMAGE_NAME }}:\${{ env.STAGING_TAG }}/tags: \${{ env.IMAGE_NAME }}:sha-\${{ env.SOURCE_SHA }}/' \
  "$workflow" > "$test_dir/premature-final-tag.yml"
mutate_and_reject "$test_dir/premature-final-tag.yml"

awk '
  !changed && /upload-artifact: false/ { sub(/false/, "true"); changed = 1 }
  { print }
' "$workflow" > "$test_dir/duplicate-sbom-artifact.yml"
mutate_and_reject "$test_dir/duplicate-sbom-artifact.yml"

sed 's#actions/checkout@[0-9a-f]*#actions/checkout@v5#' "$workflow" > "$test_dir/unpinned-action.yml"
mutate_and_reject "$test_dir/unpinned-action.yml"

sed 's/\.predicate == \$expected\[0\] and/true and/g' "$workflow" > "$test_dir/unbound-predicate.yml"
mutate_and_reject "$test_dir/unbound-predicate.yml"

sed 's/\.subject\[0\]\.digest\.sha256 == \$expected_digest/true/g' "$workflow" > "$test_dir/unbound-subject.yml"
mutate_and_reject "$test_dir/unbound-subject.yml"

echo 'AI OS Kernel image release contract tests OK'
