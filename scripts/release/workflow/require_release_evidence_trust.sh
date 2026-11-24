#!/usr/bin/env bash
set -e

if [ "$HOMEBREW_TAP_TOKEN_PRESENT" != "true" ]; then
  echo "::error::HOMEBREW_TAP_TOKEN must be configured before publishing a release"
  exit 1
fi
for name in \
  HELM_RELEASE_EVIDENCE_PROFILE \
  HELM_RELEASE_EVIDENCE_ANCHOR_TYPE \
  HELM_RELEASE_EVIDENCE_ANCHOR_URI \
  HELM_RELEASE_EVIDENCE_STORAGE_URI \
  HELM_RELEASE_EVIDENCE_STORAGE_RECEIPT_COMMAND \
  HELM_EVIDENCE_KMS_KEY_ID \
  HELM_EVIDENCE_KMS_PUBLIC_KEY_HEX \
  HELM_EVIDENCE_KMS_SIGN_COMMAND; do
  if [ -z "${!name:-}" ]; then
    echo "::error::$name must be configured for release EvidencePack trust"
    exit 1
  fi
done
