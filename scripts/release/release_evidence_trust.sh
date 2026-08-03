#!/usr/bin/env bash

# Shared helpers for explicit release EvidencePack trust preparation.

HELM_RELEASE_EVIDENCE_PREPARED_PROFILE=""
HELM_RELEASE_EVIDENCE_PREPARED_DATA_DIR=""
HELM_RELEASE_EVIDENCE_PREPARED_CONFIG_PATH=""
HELM_RELEASE_EVIDENCE_PREPARED_STORAGE_RECEIPT_PATH=""

helm_release_evidence_contract_complete() {
  local receipt_path="${HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_PATH:-}"
  local receipt_json="${HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_JSON:-}"
  local receipt_command="${HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_COMMAND:-}"
  [[ -n "${HELM_RELEASE_EVIDENCE_PROFILE:-}" ]] &&
    [[ -n "${HELM_RELEASE_EVIDENCE_ANCHOR_TYPE:-}" ]] &&
    [[ -n "${HELM_RELEASE_EVIDENCE_ANCHOR_URI:-}" ]] &&
    [[ -n "${HELM_RELEASE_EVIDENCE_STORAGE_URI:-}" ]] &&
    [[ -n "${HELM_EVIDENCE_KMS_KEY_ID:-${HELM_EVIDENCE_SIGNER_KEY_ID:-}}" ]] &&
    [[ -n "${HELM_EVIDENCE_KMS_PUBLIC_KEY_HEX:-}" ]] &&
    [[ -n "${HELM_EVIDENCE_KMS_SIGN_COMMAND:-}" ]] &&
    {
      [[ -n "$receipt_path" && -z "$receipt_json" && -z "$receipt_command" ]] ||
        [[ -z "$receipt_path" && -n "$receipt_json" && -z "$receipt_command" ]] ||
        [[ -z "$receipt_path" && -z "$receipt_json" && -n "$receipt_command" ]]
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
  local trust_json="$tmp_root/trust-init.json"
  local data_dir="$tmp_root/data"
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
  if ! helm_release_evidence_contract_complete; then
    helm_release_evidence_error "$caller" "exactly one storage receipt source is required via HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_COMMAND, HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_PATH, or HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_JSON"
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

  HELM_RELEASE_EVIDENCE_PREPARED_PROFILE="$profile"
  HELM_RELEASE_EVIDENCE_PREPARED_DATA_DIR="$data_dir"
}

helm_release_evidence_subject_root() {
  local bundle="$1"
  python3 - "$bundle" <<'PY'
import json
import pathlib
import sys
import tarfile

bundle = pathlib.Path(sys.argv[1])
if bundle.is_dir():
    data = (bundle / "07_ATTESTATIONS" / "evidence_pack.sig").read_text(encoding="utf-8")
else:
    with tarfile.open(bundle, "r:*") as tar:
        member = tar.extractfile("07_ATTESTATIONS/evidence_pack.sig")
        if member is None:
            raise SystemExit("missing 07_ATTESTATIONS/evidence_pack.sig")
        with member:
            data = member.read().decode("utf-8")
payload = json.loads(data)
root = payload.get("merkle_root", "")
if not isinstance(root, str) or not root:
    raise SystemExit("evidence pack seal is missing merkle_root")
print(root)
PY
}

helm_release_evidence_write_storage_receipt() {
  local archive_path="$1"
  local subject_root="$2"
  local out_path="$3"
  local caller="$4"
  local receipt_path="${HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_PATH:-}"
  local receipt_json="${HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_JSON:-}"
  local receipt_command="${HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_COMMAND:-}"

  if [[ ! -f "$archive_path" ]]; then
    helm_release_evidence_error "$caller" "release archive does not exist: $archive_path"
    return 1
  fi
  if [[ -z "$subject_root" ]]; then
    helm_release_evidence_error "$caller" "subject root is required before materializing a storage receipt"
    return 1
  fi
  if ! helm_release_evidence_contract_complete; then
    helm_release_evidence_error "$caller" "storage receipt source contract is incomplete"
    return 1
  fi
  mkdir -p "$(dirname "$out_path")"
  if [[ -n "$receipt_command" ]]; then
    HELM_RELEASE_EVIDENCE_ARCHIVE_PATH="$archive_path" \
      HELM_RELEASE_EVIDENCE_SUBJECT_ROOT="$subject_root" \
      sh -c "$receipt_command" >"$out_path"
  elif [[ -n "$receipt_path" ]]; then
    if [[ ! -f "$receipt_path" ]]; then
      helm_release_evidence_error "$caller" "storage receipt path does not exist: $receipt_path"
      return 1
    fi
    cp "$receipt_path" "$out_path"
  else
    printf '%s' "$receipt_json" >"$out_path"
  fi
  chmod 600 "$out_path"
  HELM_RELEASE_EVIDENCE_PREPARED_STORAGE_RECEIPT_PATH="$out_path"
}
