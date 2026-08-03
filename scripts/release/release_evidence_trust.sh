#!/usr/bin/env bash

# Shared helpers for explicit release EvidencePack trust preparation.

HELM_RELEASE_EVIDENCE_PREPARED_PROFILE=""
HELM_RELEASE_EVIDENCE_PREPARED_DATA_DIR=""
HELM_RELEASE_EVIDENCE_PREPARED_CONFIG_PATH=""
HELM_RELEASE_EVIDENCE_PREPARED_STORAGE_RECEIPT_PATH=""

helm_release_evidence_contract_complete() {
  local receipt_path="${HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_PATH:-}"
  local receipt_json="${HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_JSON:-}"
  [[ -n "${HELM_RELEASE_EVIDENCE_PROFILE:-}" ]] &&
    [[ -n "${HELM_RELEASE_EVIDENCE_ANCHOR_TYPE:-}" ]] &&
    [[ -n "${HELM_RELEASE_EVIDENCE_ANCHOR_URI:-}" ]] &&
    [[ -n "${HELM_RELEASE_EVIDENCE_STORAGE_URI:-}" ]] &&
    [[ -n "${HELM_EVIDENCE_KMS_KEY_ID:-${HELM_EVIDENCE_SIGNER_KEY_ID:-}}" ]] &&
    [[ -n "${HELM_EVIDENCE_KMS_PUBLIC_KEY_HEX:-}" ]] &&
    [[ -n "${HELM_EVIDENCE_KMS_SIGN_COMMAND:-}" ]] &&
    {
      [[ -n "$receipt_path" && -z "$receipt_json" ]] ||
        [[ -z "$receipt_path" && -n "$receipt_json" ]]
    }
}

helm_release_evidence_error() {
  local caller="$1"
  local detail="$2"
  echo "::error file=$caller::explicit release EvidencePack trust is required: $detail" >&2
}

helm_release_evidence_prepare() {
  local kernel_bin="$1"
  local tmp_root="$2"
  local caller="$3"

  local profile="${HELM_RELEASE_EVIDENCE_PROFILE:-}"
  local anchor_type="${HELM_RELEASE_EVIDENCE_ANCHOR_TYPE:-}"
  local anchor_uri="${HELM_RELEASE_EVIDENCE_ANCHOR_URI:-}"
  local storage_uri="${HELM_RELEASE_EVIDENCE_STORAGE_URI:-}"
  local kms_key_id="${HELM_EVIDENCE_KMS_KEY_ID:-${HELM_EVIDENCE_SIGNER_KEY_ID:-}}"
  local kms_public_key="${HELM_EVIDENCE_KMS_PUBLIC_KEY_HEX:-}"
  local kms_sign_command="${HELM_EVIDENCE_KMS_SIGN_COMMAND:-}"
  local receipt_path="${HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_PATH:-}"
  local receipt_json="${HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_JSON:-}"
  local trust_json="$tmp_root/trust-init.json"
  local data_dir="$tmp_root/data"
  local storage_receipt_path="$tmp_root/storage-receipt.json"
  local -a trust_args

  HELM_RELEASE_EVIDENCE_PREPARED_PROFILE=""
  HELM_RELEASE_EVIDENCE_PREPARED_DATA_DIR=""
  HELM_RELEASE_EVIDENCE_PREPARED_CONFIG_PATH=""
  HELM_RELEASE_EVIDENCE_PREPARED_STORAGE_RECEIPT_PATH=""

  case "$profile" in
    customer|high-assurance) ;;
    *)
      helm_release_evidence_error "$caller" "HELM_RELEASE_EVIDENCE_PROFILE must be set to customer or high-assurance"
      return 1
      ;;
  esac
  case "$anchor_type" in
    rekor|rekor-v2|rfc3161) ;;
    *)
      helm_release_evidence_error "$caller" "HELM_RELEASE_EVIDENCE_ANCHOR_TYPE must be set to rekor, rekor-v2, or rfc3161"
      return 1
      ;;
  esac
  if [[ -z "$anchor_uri" ]]; then
    helm_release_evidence_error "$caller" "HELM_RELEASE_EVIDENCE_ANCHOR_URI must point at the external anchor endpoint"
    return 1
  fi
  if [[ -z "$storage_uri" ]]; then
    helm_release_evidence_error "$caller" "HELM_RELEASE_EVIDENCE_STORAGE_URI must describe the off-host release archive location"
    return 1
  fi
  if [[ -z "$kms_key_id" || -z "$kms_public_key" || -z "$kms_sign_command" ]]; then
    helm_release_evidence_error "$caller" "HELM_EVIDENCE_KMS_KEY_ID, HELM_EVIDENCE_KMS_PUBLIC_KEY_HEX, and HELM_EVIDENCE_KMS_SIGN_COMMAND must be configured"
    return 1
  fi
  if [[ -n "$receipt_path" && -n "$receipt_json" ]]; then
    helm_release_evidence_error "$caller" "set exactly one of HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_PATH or HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_JSON"
    return 1
  fi
  if [[ -z "$receipt_path" && -z "$receipt_json" ]]; then
    helm_release_evidence_error "$caller" "a release storage receipt source is required via HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_PATH or HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_JSON"
    return 1
  fi
  if [[ ! -x "$kernel_bin" ]]; then
    helm_release_evidence_error "$caller" "release trust preparation requires an executable kernel binary at $kernel_bin"
    return 1
  fi

  mkdir -p "$data_dir"
  chmod 700 "$data_dir"
  trust_args=(
    "$kernel_bin" evidence trust init
    --profile "$profile"
    --signer kms
    --anchor "$anchor_type"
    --anchor-uri "$anchor_uri"
    --store s3
    --store-uri "$storage_uri"
    --data-dir "$data_dir"
    --json
  )
  if [[ "$profile" == "high-assurance" ]]; then
    trust_args+=(--object-lock)
  fi
  "${trust_args[@]}" >"$trust_json"

  HELM_RELEASE_EVIDENCE_PREPARED_CONFIG_PATH="$(
    python3 - "$trust_json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    payload = json.load(fh)
path = payload.get("path", "")
if not isinstance(path, str) or not path:
    raise SystemExit("trust init JSON did not return a config path")
print(path)
PY
  )"

  if [[ -n "$receipt_path" ]]; then
    if [[ ! -f "$receipt_path" ]]; then
      helm_release_evidence_error "$caller" "storage receipt path does not exist: $receipt_path"
      return 1
    fi
    cp "$receipt_path" "$storage_receipt_path"
  else
    printf '%s' "$receipt_json" >"$storage_receipt_path"
  fi
  chmod 600 "$storage_receipt_path"

  HELM_RELEASE_EVIDENCE_PREPARED_PROFILE="$profile"
  HELM_RELEASE_EVIDENCE_PREPARED_DATA_DIR="$data_dir"
  HELM_RELEASE_EVIDENCE_PREPARED_STORAGE_RECEIPT_PATH="$storage_receipt_path"
}
