#!/usr/bin/env bash
# quantum_posture: invokes Sigstore keyless signing for the image digest.
set -euo pipefail

cosign sign --yes "${REGISTRY}/${IMAGE_NAME}@${IMAGE_DIGEST:?container image digest is required}"
