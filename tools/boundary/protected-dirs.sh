#!/bin/bash
# protected-dirs.sh — the single definition of the protected surface.
#
# Sourced by tools/boundary/generate-manifest.sh and tools/verify-boundary.sh.
# It previously lived twice, and the two copies drifted: the verifier still
# listed core/pkg/incubator/audit (moved to core/pkg/audit) and never learned
# about core/pkg/packs, so its extraneous-file scan covered neither.
#
# Adding a directory here widens the boundary. Removing one narrows it. Both are
# governance changes and must be reviewed as such — which is why tools/boundary
# and the verifier are themselves in the protected surface below. Dropping an
# entry from this list would otherwise un-protect a whole package silently: the
# manifest would regenerate smaller and the gate would still report success.
#
# This makes boundary tampering VISIBLE, not impossible. A commit that edits this
# list and regenerates the manifest together still passes CI — but it cannot do so
# without a manifest diff that says exactly which files stopped being protected.

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
  # The boundary's own configuration and generator. tools/boundary/protected.manifest
  # is excluded where the manifest is built — a file cannot contain its own hash.
  tools/boundary
)

# Individually protected files that do not live under a protected directory.
# shellcheck disable=SC2034  # consumed by the scripts that source this file
PROTECTED_FILES=(
  tools/verify-boundary.sh
)
