# HELM AI Kernel Threat Model

Version: 2026-06-08-security-evidence-loop-v1
Version Hash: sha256:77210a48f9f402bd0c28c1c93bc5d422a08f80003fa850e819cedff116697bc8
Owner: HELM Kernel Security
Review Date: 2026-06-08

## Assets

- EvidencePack contracts, seals, signatures, receipt hashes, replay manifests, and trust profiles.
- Boundary verdicts, policy evaluation inputs, sandbox specifications, and proof graph records.
- Kernel package APIs consumed by Enterprise, services, SDKs, and public examples.

## Entry Points

- Go package APIs under `core/pkg/contracts`, `core/pkg/evidence`, `core/pkg/sandbox`, `core/pkg/proofgraph`, and boundary packages.
- Test/conformance fixtures that are promoted into public proof or release evidence.
- Serialized EvidencePack, receipt, replay, sandbox, and policy documents.

## Trusted Inputs

- Source-owned contracts and fixtures committed in this repo.
- Signed EvidencePack material and configured external signer anchors.
- Repo-local tests and conformance cases that run from a pinned commit.

## Untrusted Inputs

- Scanner output, vulnerability candidates, PoC transcripts, model-generated verifier text, and imported report attachments.
- Sandbox command args, environment, mounts, network configuration, and repo checkout content.
- Downstream Enterprise or service claims that are not backed by Kernel receipts.

## Tenant Boundaries

- Kernel packages must not treat tenant/workspace identity as global process state.
- Receipts and EvidencePacks must bind subject, actor, workspace or tenant context where applicable.
- Cross-tenant evidence reuse is invalid unless the EvidencePack explicitly records redaction and delegation scope.

## Credential Surfaces

- Signing keys, KMS references, local development signing keys, secret refs, sandbox mounts, environment variables, and external anchor credentials.
- Credential material must never be stored in receipts, EvidencePacks, fixtures, transcripts, or test golden files.

## Effect Classes

- ALLOW/DENY/ESCALATE boundary decisions, signature/seal creation, proof export, replay, sandbox execution, and connector-facing contract publication.
- High-risk effects require receipts, verifier evidence, and fail-closed behavior.

## Out-of-Scope Bug Classes

- Cosmetic documentation wording that does not affect proof, receipt, contract, or public claim semantics.
- Test-only helper behavior when it cannot mint production evidence or affect release artifacts.

## Past Bug Shapes

- Hash-only evidence accepted where signed or anchored proof was required.
- Sandbox execution evidence without pinned images, credential checks, or network constraints.
- Public or Enterprise claims drifting from Kernel source-owned receipt semantics.

## Severity Calibration

- Critical: forged or self-supplied EvidencePack/seal/verdict accepted as production proof.
- High: verifier, sandbox, replay, or boundary receipt can be bypassed or confused across trust boundaries.
- Medium: contract drift that weakens downstream evidence checks but remains blocked by another fail-closed gate.
- Low: incomplete evidence metadata that does not alter enforcement, sealing, or release decisions.
