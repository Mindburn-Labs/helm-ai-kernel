#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO="${HELM_LAUNCHPAD_GITHUB_REPO:-Mindburn-Labs/helm-ai-kernel}"
RELEASE_TAG="v0.5.12"
ARTIFACT_RUN_ID="26198407296"
HOST_KIND="developer_macos"
OUTPUT="$ROOT/docs/launchpad/clean_install_report.json"
TRANSCRIPT_DIR="${TMPDIR:-/tmp}/helm-launchpad-clean-install"
INCLUDE_CANDIDATES=0
SUPPORTED_APPS=(openclaw hermes)
VERIFY_ONLY_APPS=(opencode kilocode)
CANDIDATE_APPS=()

usage() {
  cat <<'USAGE'
Usage: scripts/launch/clean_install_gate.sh [options]

Options:
  --release-tag <tag>       Release tag to validate (default: v0.5.12)
  --artifact-run-id <id>    Launchpad artifact workflow run (default: 26198407296)
  --host-kind <kind>        developer_macos or github_macos_runner
  --output <path>           Redacted JSON report path
  --transcript-dir <path>   Directory for redacted command output and audit inputs
  --include-candidates      Backward-compatible no-op; verify-only apps are not launched
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-tag) RELEASE_TAG="$2"; shift 2 ;;
    --artifact-run-id) ARTIFACT_RUN_ID="$2"; shift 2 ;;
    --host-kind) HOST_KIND="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --transcript-dir) TRANSCRIPT_DIR="$2"; shift 2 ;;
    --include-candidates) INCLUDE_CANDIDATES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

mkdir -p "$TRANSCRIPT_DIR"/{commands,audit,verify}
COMMANDS_JSONL="$TRANSCRIPT_DIR/commands.jsonl"
EVIDENCE_JSONL="$TRANSCRIPT_DIR/evidence.jsonl"
LAUNCH_IDS_JSONL="$TRANSCRIPT_DIR/launch_ids.jsonl"
GHCR_JSON="$TRANSCRIPT_DIR/ghcr_digest_confirmations.json"
SECRET_AUDIT_JSON="$TRANSCRIPT_DIR/secret_fragment_audit.json"
REMOTE_AUDIT_JSON="$TRANSCRIPT_DIR/remote_audit.json"
: > "$COMMANDS_JSONL"
: > "$EVIDENCE_JSONL"
: > "$LAUNCH_IDS_JSONL"

if [[ -z "${OPENROUTER_API_KEY:-}" && -n "${HELM_LAUNCHPAD_CI_OPENROUTER_API_KEY:-}" ]]; then
  export OPENROUTER_API_KEY="$HELM_LAUNCHPAD_CI_OPENROUTER_API_KEY"
fi
if [[ -z "${GH_TOKEN:-}" && -n "${GITHUB_TOKEN:-}" ]]; then
  export GH_TOKEN="$GITHUB_TOKEN"
fi

export HELM_LAUNCHPAD_HOME="$TRANSCRIPT_DIR/launchpad-home"
export HELM_LAUNCHPAD_EGRESS_RECEIPT_DIR="$TRANSCRIPT_DIR/egress-receipts"
mkdir -p "$HELM_LAUNCHPAD_HOME" "$HELM_LAUNCHPAD_EGRESS_RECEIPT_DIR"

model_provider_secret_envs() {
  jq -r '.providers[].env[]' "$ROOT/core/pkg/launchpad/modelproviders/catalog.json" | sort -u
}

model_provider_required_env_groups() {
  jq -r '
    .providers[]
    | ((.required_env_groups // []) as $groups
       | if ($groups | length) > 0 then $groups[] else (.env[] | [.]) end)
    | @tsv
  ' "$ROOT/core/pkg/launchpad/modelproviders/catalog.json"
}

import_model_provider_secret_json() {
  [[ -n "${HELM_LAUNCHPAD_CI_MODEL_PROVIDER_SECRET_JSON:-}" ]] || return 0
  local allowed
  allowed="$(model_provider_secret_envs | tr '\n' ' ')"
  local key value
  while IFS=$'\t' read -r key value; do
    [[ -n "$key" && -n "$value" ]] || continue
    case " $allowed " in
      *" $key "*) export "$key=$value" ;;
    esac
  done < <(printf '%s' "$HELM_LAUNCHPAD_CI_MODEL_PROVIDER_SECRET_JSON" | jq -r 'to_entries[] | [.key, .value] | @tsv')
}

model_provider_key_present() {
  local group env_name complete
  while IFS=$'\t' read -r -a group; do
    [[ "${#group[@]}" -gt 0 ]] || continue
    complete=1
    for env_name in "${group[@]}"; do
      if [[ -z "${!env_name:-}" ]]; then
        complete=0
        break
      fi
    done
    [[ "$complete" -eq 1 ]] && return 0
  done < <(model_provider_required_env_groups)
  return 1
}

first_model_provider_secret_env() {
  local group env_name complete fallback
  while IFS=$'\t' read -r -a group; do
    [[ "${#group[@]}" -gt 0 ]] || continue
    complete=1
    fallback=""
    for env_name in "${group[@]}"; do
      [[ -z "$fallback" ]] && fallback="$env_name"
      if [[ -z "${!env_name:-}" ]]; then
        complete=0
        break
      fi
    done
    if [[ "$complete" -eq 1 ]]; then
      for env_name in "${group[@]}"; do
        case "$env_name" in
          *_API_KEY|*_ACCESS_TOKEN|*_TOKEN|*_KEY)
            printf '%s\n' "$env_name"
            return 0
            ;;
        esac
      done
      printf '%s\n' "$fallback"
      return 0
    fi
  done < <(model_provider_required_env_groups)
  return 1
}

redact_file() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  local env_name
  while IFS= read -r env_name; do
    [[ -n "$env_name" && -n "${!env_name:-}" ]] || continue
    SECRET_ENV_NAME="$env_name" perl -0pi -e 's/\Q$ENV{$ENV{SECRET_ENV_NAME}}\E/[REDACTED]/g' "$file"
  done < <(model_provider_secret_envs)
  if [[ -n "${HELM_LAUNCHPAD_CI_OPENROUTER_API_KEY:-}" ]]; then
    perl -0pi -e 's/\Q$ENV{HELM_LAUNCHPAD_CI_OPENROUTER_API_KEY}\E/[REDACTED]/g' "$file"
  fi
}

record_command() {
  local name="$1" display="$2" exit_code="$3" stdout_file="$4" stderr_file="$5"
  jq -nc \
    --arg name "$name" \
    --arg command "$display" \
    --arg stdout_file "$(basename "$stdout_file")" \
    --arg stderr_file "$(basename "$stderr_file")" \
    --argjson exit_code "$exit_code" \
    '{name:$name, command:$command, exit_code:$exit_code, stdout_file:$stdout_file, stderr_file:$stderr_file}' >> "$COMMANDS_JSONL"
}

run_step() {
  local name="$1" display="$2" script="$3"
  local stdout_file="$TRANSCRIPT_DIR/commands/${name}.stdout"
  local stderr_file="$TRANSCRIPT_DIR/commands/${name}.stderr"
  set +e
  bash -o pipefail -c "$script" >"$stdout_file" 2>"$stderr_file"
  local status=$?
  set -e
  record_command "$name" "$display" "$status" "$stdout_file" "$stderr_file"
  if [[ "$status" -eq 0 ]]; then
    printf 'clean-install: %s passed\n' "$name"
  else
    printf 'clean-install: %s failed with exit %s\n' "$name" "$status" >&2
  fi
  return "$status"
}

collect_remote_audit_inputs() {
  local status="PASS"
  local detail="remote release assets and workflow logs collected"
  mkdir -p "$TRANSCRIPT_DIR/audit/release-assets" "$TRANSCRIPT_DIR/audit/logs" "$TRANSCRIPT_DIR/audit/artifact-manifest"
  if ! command -v gh >/dev/null 2>&1; then
    status="FAIL"
    detail="gh CLI is required to collect release notes, assets, and workflow logs"
  elif [[ -z "${GH_TOKEN:-}" ]]; then
    status="FAIL"
    detail="GH_TOKEN or GITHUB_TOKEN is required to collect release notes, assets, and workflow logs"
  else
    gh release view "$RELEASE_TAG" --repo "$REPO" --json tagName,name,publishedAt,url,assets,body \
      > "$TRANSCRIPT_DIR/audit/release-view.json" 2> "$TRANSCRIPT_DIR/audit/release-view.stderr" || status="FAIL"
    gh release download "$RELEASE_TAG" --repo "$REPO" --dir "$TRANSCRIPT_DIR/audit/release-assets" \
      --pattern "evidence-pack.tar" \
      --pattern "release-attestation.json" \
      --pattern "${RELEASE_TAG}.json" \
      --pattern "SHA256SUMS.txt" \
      > "$TRANSCRIPT_DIR/audit/release-download.stdout" 2> "$TRANSCRIPT_DIR/audit/release-download.stderr" || status="FAIL"
    gh run view "$ARTIFACT_RUN_ID" --repo "$REPO" --log \
      > "$TRANSCRIPT_DIR/audit/logs/launchpad-artifacts.log" 2> "$TRANSCRIPT_DIR/audit/logs/launchpad-artifacts.stderr" || status="FAIL"
    local release_run_id
    release_run_id="$(gh run list --repo "$REPO" --workflow release.yml --branch "$RELEASE_TAG" --limit 1 --json databaseId --jq '.[0].databaseId // empty' 2>/dev/null || true)"
    if [[ -n "$release_run_id" ]]; then
      gh run view "$release_run_id" --repo "$REPO" --log \
        > "$TRANSCRIPT_DIR/audit/logs/release.log" 2> "$TRANSCRIPT_DIR/audit/logs/release.stderr" || status="FAIL"
    else
      status="FAIL"
      printf 'release workflow run not found for %s\n' "$RELEASE_TAG" > "$TRANSCRIPT_DIR/audit/logs/release.stderr"
    fi
    gh run download "$ARTIFACT_RUN_ID" --repo "$REPO" -n launchpad-artifact-manifest \
      -D "$TRANSCRIPT_DIR/audit/artifact-manifest" \
      > "$TRANSCRIPT_DIR/audit/artifact-manifest.stdout" 2> "$TRANSCRIPT_DIR/audit/artifact-manifest.stderr" || status="FAIL"
  fi
  jq -n --arg status "$status" --arg detail "$detail" '{status:$status, detail:$detail}' > "$REMOTE_AUDIT_JSON"
  [[ "$status" == "PASS" ]]
}

resolve_egress_proxy_image() {
  if [[ -n "${HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE:-}" ]]; then
    return 0
  fi
  local manifest="$TRANSCRIPT_DIR/audit/artifact-manifest/launchpad-artifact-manifest.json"
  if [[ -f "$manifest" ]]; then
    local image
    image="$(jq -r '.egress_proxy.image // empty' "$manifest")"
    if [[ -n "$image" ]]; then
      export HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE="$image"
      printf 'clean-install: resolved egress proxy image from workflow artifact\n'
      return 0
    fi
  fi
  printf 'clean-install: missing HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE and artifact manifest\n' >&2
  return 1
}

collect_evidence_refs() {
  local json_file="$1"
  jq -r '.evidence_pack_refs[]? // empty' "$json_file" | sed '/^$/d' >> "$TRANSCRIPT_DIR/evidence_refs.txt"
}

record_evidence_ref() {
  local ref="$1" verify_status="$2"
  local kind="file"
  local digest=""
  if [[ -d "$ref" ]]; then
    kind="directory"
    if [[ -f "$ref/00_INDEX.json" ]]; then
      digest="$(shasum -a 256 "$ref/00_INDEX.json" | awk '{print $1}')"
    else
      digest="$(find "$ref" -type f -print0 | sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}')"
    fi
  elif [[ -f "$ref" ]]; then
    digest="$(shasum -a 256 "$ref" | awk '{print $1}')"
  else
    kind="missing"
  fi
  local safe_ref="${ref//$TRANSCRIPT_DIR/\$TRANSCRIPT_DIR}"
  safe_ref="${safe_ref//$HOME/\$HOME}"
  jq -nc \
    --arg path "$safe_ref" \
    --arg kind "$kind" \
    --arg sha256 "$digest" \
    --arg status "$verify_status" \
    '{path:$path, kind:$kind, sha256:$sha256, verify_status:$status}' >> "$EVIDENCE_JSONL"
}

verify_evidence_refs() {
  [[ -f "$TRANSCRIPT_DIR/evidence_refs.txt" ]] || return 1
  sort -u "$TRANSCRIPT_DIR/evidence_refs.txt" > "$TRANSCRIPT_DIR/evidence_refs.sorted"
  local status=0
  while IFS= read -r ref; do
    [[ -n "$ref" ]] || continue
    local name
    name="$(basename "$ref" | tr -c 'A-Za-z0-9_.-' '-')"
    if run_step "verify_${name}" "helm-ai-kernel verify --bundle <pack> --json" "helm-ai-kernel verify --bundle '$ref' --json"; then
      record_evidence_ref "$ref" "PASS"
    else
      record_evidence_ref "$ref" "FAIL"
      status=1
    fi
  done < "$TRANSCRIPT_DIR/evidence_refs.sorted"
  return "$status"
}

redact_transcripts() {
  find "$TRANSCRIPT_DIR" -type f -print0 | while IFS= read -r -d '' file; do
    redact_file "$file"
  done
}

write_final_report() {
  local status="$1"
  python3 - "$OUTPUT" "$status" "$COMMANDS_JSONL" "$EVIDENCE_JSONL" "$LAUNCH_IDS_JSONL" "$GHCR_JSON" "$SECRET_AUDIT_JSON" "$REMOTE_AUDIT_JSON" "$RELEASE_TAG" "$HOST_KIND" "$ARTIFACT_RUN_ID" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

output, status, commands_path, evidence_path, launch_ids_path, ghcr_path, secret_path, remote_path, release_tag, host_kind, artifact_run_id = sys.argv[1:]

def read_jsonl(path):
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]

def read_json(path, fallback):
    p = Path(path)
    if not p.exists():
        return fallback
    return json.loads(p.read_text(encoding="utf-8"))

commands = read_jsonl(commands_path)
evidence = read_jsonl(evidence_path)
launch_ids = {item["app_id"]: item["launch_id"] for item in read_jsonl(launch_ids_path)}
failed = [item["name"] for item in commands if item.get("exit_code") != 0]
report = {
    "schema_version": 1,
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "milestone": "Launchpad v0.5.10 Clean Install + Public Docs GA",
    "release_tag": release_tag,
    "artifact_workflow_run_id": artifact_run_id,
    "host_kind": host_kind,
    "status": status,
    "supported_apps": ["openclaw", "hermes"],
    "verify_only_apps": ["opencode", "kilocode"],
    "candidate_promotion_apps": [],
    "candidate_promotion_included": False,
    "deprecated_include_candidates_flag": "accepted_noop_verify_only_apps_are_not_launched",
    "commands": commands,
    "launch_ids": launch_ids,
    "ghcr_digest_confirmations": read_json(ghcr_path, []),
    "evidence_packs": evidence,
    "remote_audit": read_json(remote_path, {"status": "MISSING"}),
    "secret_fragment_audit": read_json(secret_path, {"status": "MISSING"}),
    "failed_steps": failed,
    "redaction": {
        "raw_logs_committed": False,
        "secret_values_committed": False,
        "host_identifiers_committed": False
    }
}
Path(output).parent.mkdir(parents=True, exist_ok=True)
Path(output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

main() {
  local final_status="PASS"

  import_model_provider_secret_json

  if ! model_provider_key_present; then
    printf 'clean-install: one BYO model provider API key from core/pkg/launchpad/modelproviders/catalog.json is required\n' >&2
    final_status="FAIL"
  fi

  collect_remote_audit_inputs || final_status="FAIL"
  resolve_egress_proxy_image || final_status="FAIL"

  run_step brew_update "brew update" "brew update" || final_status="FAIL"
  run_step brew_install "brew install mindburnlabs/tap/helm-ai-kernel" "brew install mindburnlabs/tap/helm-ai-kernel" || final_status="FAIL"
  run_step docker_version "docker version" "docker version" || final_status="FAIL"
  run_step helm_version "helm-ai-kernel --version" "helm-ai-kernel --version" || final_status="FAIL"
  run_step launch_matrix "helm-ai-kernel launch matrix --json" "helm-ai-kernel launch matrix --json" || final_status="FAIL"
  run_step launch_apps "helm-ai-kernel launch apps --json" "helm-ai-kernel launch apps --json" || final_status="FAIL"

  if [[ -s "$TRANSCRIPT_DIR/commands/launch_apps.stdout" ]]; then
    jq '[.[] | select(.id == "openclaw" or .id == "hermes" or .id == "opencode" or .id == "kilocode") | {
      app_id: .id,
      availability: .availability,
      image: .install.image,
      digest: .install.digest,
      signature_ref: .supply_chain_evidence.signature_ref
    }]' "$TRANSCRIPT_DIR/commands/launch_apps.stdout" > "$GHCR_JSON" || final_status="FAIL"
  else
    echo "[]" > "$GHCR_JSON"
    final_status="FAIL"
  fi

  local launch_apps=("${SUPPORTED_APPS[@]}")
  if [[ "$INCLUDE_CANDIDATES" -eq 1 ]]; then
    launch_apps+=("${CANDIDATE_APPS[@]}")
  fi

  for app in "${launch_apps[@]}"; do
    if run_step "launch_${app}" "helm-ai-kernel launch ${app} local-container --headless --output json" "helm-ai-kernel launch ${app} local-container --headless --output json"; then
      local launch_json="$TRANSCRIPT_DIR/commands/launch_${app}.stdout"
      collect_evidence_refs "$launch_json"
      local launch_id
      launch_id="$(jq -r '.launch_id // empty' "$launch_json")"
      if [[ -n "$launch_id" ]]; then
        jq -nc --arg app_id "$app" --arg launch_id "$launch_id" '{app_id:$app_id, launch_id:$launch_id}' >> "$LAUNCH_IDS_JSONL"
        if run_step "delete_${app}" "helm-ai-kernel launch delete <launch_id> --cascade" "helm-ai-kernel launch delete '$launch_id' --cascade"; then
          collect_evidence_refs "$TRANSCRIPT_DIR/commands/delete_${app}.stdout"
        else
          final_status="FAIL"
        fi
      else
        final_status="FAIL"
      fi
    else
      final_status="FAIL"
    fi
  done

  verify_evidence_refs || final_status="FAIL"

  local audit_secret_env
  audit_secret_env="$(first_model_provider_secret_env || true)"
  if [[ -n "$audit_secret_env" ]]; then
    python3 "$ROOT/scripts/launch/secret_fragment_audit.py" \
      --secret-env "$audit_secret_env" \
      --root "$TRANSCRIPT_DIR/commands" \
      --root "$TRANSCRIPT_DIR/audit" \
      --root "$HELM_LAUNCHPAD_HOME" \
      --json-out "$SECRET_AUDIT_JSON" || final_status="FAIL"
  fi

  redact_transcripts

  write_final_report "$final_status"
  printf 'clean-install: wrote redacted report to %s\n' "$OUTPUT"
  [[ "$final_status" == "PASS" ]]
}

main "$@"
