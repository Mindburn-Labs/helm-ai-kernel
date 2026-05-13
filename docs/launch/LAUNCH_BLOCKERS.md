# HELM AI Kernel Launch Blockers

This document provides a formalized ledger of known execution, governance, and infrastructure blockers for the HELM AI Kernel public technical launch.

As per the launch governance policy, **we do not downgrade strategic HELM claims** to bypass blockers. If a claim is unsupported, it must be implemented. If a blocker is external or hardware-constrained, it must be explicitly recorded here with its precise remediation path.

## External & Hardware Exceptions

These items are accepted as blockers that cannot be resolved within the local launch execution window, but do not prevent the repository from being structurally launch-ready.

### 1. GitHub Actions Billing Lock

*   **Status**: `ACCEPTED EXCEPTION`
*   **Description**: All CI workflows are failing due to a Mindburn Labs organization-level GitHub billing lock. Remote CI is completely blocked.
*   **Impact**: Prevents automated PR gating, remote test execution, and the automated release pipeline (binaries, SBOM, provenance).
*   **Remediation**: 
    1. Organization billing administrator must unfreeze the account.
    2. Alternatively, release artifacts for `v0.5.0` must be cut locally via the `make release-assets` and `make release-binaries-reproducible` commands if a manual launch path is required.
*   **Owner**: Mindburn Infrastructure / Billing Admin

### 2. TEE Hardware Validation Environment

*   **Status**: `ACCEPTED EXCEPTION`
*   **Description**: The TEE (Trusted Execution Environment) subsystem at `core/pkg/crypto/tee` correctly parses and verifies the shape of SEV-SNP/TDX quotes. However, the production hardware signature chain validation returns `ErrChainUntrusted` because the CI/local environment lacks physical AMD/Intel attestation hardware.
*   **Impact**: Hardware-backed proofs cannot be integration-tested on standard runners.
*   **Remediation**:
    1. Acknowledge this limitation in the documentation: "Full hardware-chain validation requires deployment to a supported Confidential VM (CVM) provider."
    2. Ensure unit tests cover the parser, verifier boundary, and failure determinism.
*   **Owner**: Platform Engineering

## Launch Execution Blockers

These items *must* be resolved by the Launch Execution Agent prior to the completion of Phase 0.

### 3. Commercial Leakage: PR #112

*   **Status**: `RESOLVED` (Phase 0)
*   **Description**: PR #112 (`fix(console): pass credentials to commercial DO proxy`) contained a title, branch name, and scope that leaked the existence of commercial infrastructure onto the OSS launch surface.
*   **Resolution**: Closed PR #112. Cherry-picked OSS-safe changes into a clean branch `fix/oss-console-local-auth`. Removed all references to commercial proxies.

### 4. Canonical Domain Leakage: `wrangler.toml`

*   **Status**: `RESOLVED` (Phase 0)
*   **Description**: The HELM AI Kernel Console deployment config hardcoded `oss.mindburn.org` as the production domain, breaking the requirement that HELM AI Kernel must be self-hostable without hosted infrastructure assumptions.
*   **Resolution**: Removed the hardcoded domain. Added documentation comments guiding self-hosters to use localhost (`127.0.0.1:7714`) or custom environment variables.

### 5. Verdict Drift (DEFER / REQUIRE_APPROVAL)

*   **Status**: `RESOLVED` (Phase 0/1)
*   **Description**: The repository contains legacy terminology (`DEFER`, `REQUIRE_APPROVAL`) that violates the canonical HELM UCS v1.3 verdict model (`ALLOW`, `DENY`, `ESCALATE`).
*   **Resolution**: `docs/VERDICT_CANONICALIZATION.md` is the canonical public compatibility note. New launch, SDK, and MCP docs use only `ALLOW`, `DENY`, and `ESCALATE`; legacy terms are confined to compatibility/generated-code contexts.

### 6. Launch Checklist Automation

*   **Status**: `RESOLVED` (Phase 0/1/2)
*   **Description**: `docs/launch/LAUNCH_READINESS.md` named `scripts/launch/launch-ready.sh`, but the script did not exist and several checks were manual.
*   **Resolution**: Added `make launch-ready`, `scripts/launch/launch-ready.sh`, `make launch-security`, and `make launch-release-dry-run`. The readiness document is generated from executable checks covering boundaries, build/test, demos, console, MCP, proxy, proof, issue templates, docs sync, security, and release artifact dry-run.

## Governance & Ecosystem Blockers

### 7. Maintainer Diversity

*   **Status**: `RECORDED`
*   **Description**: The repository is currently single-vendor governed by Mindburn Labs. While this is expected at launch, long-term CNCF/Linux Foundation readiness requires a diversified maintainer base.
*   **Remediation**: Launch the repo with strong "Good First Issue" labeling and clear contribution guides to bootstrap a non-vendor maintainer pool.
