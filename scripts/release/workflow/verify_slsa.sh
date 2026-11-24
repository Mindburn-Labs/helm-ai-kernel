#!/usr/bin/env bash
# quantum_posture: runs the SLSA and Sigstore verification tools.
set -euo pipefail

(cd dist && sha256sum --check SHA256SUMS.txt)
slsa-verifier verify-artifact dist/SHA256SUMS.txt \
  --provenance-path slsa-provenance/multiple.intoto.jsonl \
  --source-uri github.com/Mindburn-Labs/helm-ai-kernel \
  --source-tag "$GITHUB_REF_NAME" \
  --builder-id 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0'
cosign verify-blob-attestation dist/SHA256SUMS.txt \
  --bundle slsa-provenance/multiple.intoto.jsonl \
  --type slsaprovenance02 \
  --certificate-identity 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository "$GITHUB_REPOSITORY" \
  --certificate-github-workflow-ref "$GITHUB_REF" \
  --certificate-github-workflow-sha "$GITHUB_SHA"
