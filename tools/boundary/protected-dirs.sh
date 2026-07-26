#!/bin/bash
# protected-dirs.sh — the single definition of the protected surface.
#
# Sourced by tools/boundary/generate-manifest.sh and tools/verify-boundary.sh.
# It previously lived twice, and the two copies drifted: the verifier still
# listed core/pkg/incubator/audit (moved to core/pkg/audit) and never learned
# about core/pkg/packs, so its extraneous-file scan covered neither.
#
# Adding a directory here widens the boundary. That is a governance change:
# it must be reviewed as one.

# shellcheck disable=SC2034  # consumed by the scripts that source this file
PROTECTED_DIRS=(
  core/pkg/kernel
  core/pkg/contracts
  core/pkg/crypto
  core/pkg/evidencepack
  core/pkg/proofgraph
  core/pkg/receipts
  core/pkg/verifier
  core/pkg/connectors/sandbox
  core/pkg/conformance
  core/pkg/safedep
  core/pkg/audit
  core/pkg/integrations/receipts
  core/pkg/integrations/capgraph
  core/pkg/integrations/manifest
  core/pkg/api
  core/pkg/trust/registry
  core/pkg/guardian
  core/pkg/packs
  protocols
  schemas
)
