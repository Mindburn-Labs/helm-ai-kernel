#!/usr/bin/env sh
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
      missing_404) echo '404 Not Found' >&2; exit 1 ;;
      auth) echo 'unauthorized: authentication required' >&2; exit 1 ;;
      transport) echo 'TLS handshake timeout' >&2; exit 1 ;;
      server) echo '500 Internal Server Error: manifest unknown' >&2; exit 1 ;;
      ambiguous) echo 'unexpected registry response' >&2; exit 1 ;;
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

for mode in missing missing_not_found missing_404; do
  run_promotion "$mode" >/dev/null
  if [ "$(grep -Fc 'buildx imagetools create' "$mock_log")" -ne 1 ]; then
    echo "$mode immutable tag was not created exactly once" >&2
    exit 1
  fi
done

for mode in auth transport server ambiguous; do
  if run_promotion "$mode" >/dev/null 2>"$mock_error"; then
    echo "$mode registry failure was incorrectly treated as a missing tag" >&2
    exit 1
  fi
  grep -Fq "${mode%iguous}" "$mock_error" || {
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

mutate_and_reject() {
  fixture=$1
  if "$checker" "$fixture" >/dev/null 2>&1; then
    echo "release contract mutation was not rejected: $fixture" >&2
    exit 1
  fi
}

sed -e 's/^USER /  user /' -e 's/^ENTRYPOINT /  entrypoint /' -e 's/^CMD /  cmd /' \
  Dockerfile > "$test_dir/lowercase-governed.Dockerfile"
"$checker" "$workflow" .github/workflows/release.yml "$test_dir/lowercase-governed.Dockerfile" >/dev/null

awk '{ print } END { print "  from alpine:latest" }' Dockerfile > "$test_dir/indented-unpinned.Dockerfile"
if "$checker" "$workflow" .github/workflows/release.yml "$test_dir/indented-unpinned.Dockerfile" >/dev/null 2>&1; then
  echo 'indented lowercase unpinned Docker base was not rejected' >&2
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

sed 's#actions/runs/${GITHUB_RUN_ID}/approvals#actions/runs/${GITHUB_RUN_ID}#' \
  "$workflow" > "$test_dir/missing-run-approval-readback.yml"
mutate_and_reject "$test_dir/missing-run-approval-readback.yml"

sed 's/if \[\[ "${GITHUB_RUN_ATTEMPT}" != "1" \]\]; then/if false; then/' \
  "$workflow" > "$test_dir/replayed-owner-approval.yml"
mutate_and_reject "$test_dir/replayed-owner-approval.yml"

sed 's/for owner in mindburnlabs peycheff-com; do/for owner in mindburnlabs; do/' \
  "$workflow" > "$test_dir/missing-second-owner-readback.yml"
mutate_and_reject "$test_dir/missing-second-owner-readback.yml"

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
