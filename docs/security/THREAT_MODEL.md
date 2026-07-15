# HELM AI Kernel Threat Model

Version: 2026-07-14-native-client-lifecycle-v1
Version Hash: no signed release artifact has been created for this source revision
Owner: HELM Kernel Security
Review Date: 2026-07-14

## Assets

- EvidencePack contracts, seals, signatures, receipt hashes, replay manifests, and trust profiles.
- Boundary verdicts, policy evaluation inputs, sandbox specifications, and proof graph records.
- Kernel package APIs consumed by Enterprise, services, SDKs, and public examples.
- Local setup authority, project-scoped Codex bindings, recovery
  journals, canonical lifecycle receipt envelopes, and lifecycle evidence.

## Entry Points

- Go package APIs under `core/pkg/contracts`, `core/pkg/evidence`, `core/pkg/sandbox`, `core/pkg/proofgraph`, and boundary packages.
- Test/conformance fixtures that are promoted into public proof or release evidence.
- Serialized EvidencePack, receipt, replay, sandbox, and policy documents.
- Local client configuration, legacy unscoped setup state, lifecycle databases,
  and recovery directories supplied by the workstation filesystem.

## Trusted Inputs

- Source-owned contracts and fixtures committed in this repo.
- Signed EvidencePack material and configured external signer anchors.
- Repo-local tests and conformance cases that run from a pinned commit.
- Existing native lifecycle state only after private-directory, ownership,
  canonical-envelope, and workspace-binding checks pass.

## Untrusted Inputs

- Scanner output, vulnerability candidates, PoC transcripts, model-generated verifier text, and imported report attachments.
- Sandbox command args, environment, mounts, network configuration, and repo checkout content.
- Downstream Enterprise or service claims that are not backed by Kernel receipts.
- A local config file, synthetic denial, client log, or claimed client load that
  is not bound to the reviewed lifecycle receipt and sterile-session evidence.

## Tenant Boundaries

- Kernel packages must not treat tenant/workspace identity as global process state.
- Receipts and EvidencePacks must bind subject, actor, workspace or tenant context where applicable.
- Cross-tenant evidence reuse is invalid unless the EvidencePack explicitly records redaction and delegation scope.

## Credential Surfaces

- Signing keys, KMS references, local development signing keys, secret refs, sandbox mounts, environment variables, and external anchor credentials.
- Credential material must never be stored in receipts, EvidencePacks, fixtures, transcripts, or test golden files.

## Effect Classes

- ALLOW/DENY/ESCALATE boundary decisions, signature/seal creation, proof export, replay, sandbox execution, and connector-facing contract publication.
- Codex project setup, recovery, migration, and removal of HELM-owned local
  configuration entries.
- High-risk effects require receipts, verifier evidence, and fail-closed behavior.

## Out-of-Scope Bug Classes

- Cosmetic documentation wording that does not affect proof, receipt, contract, or public claim semantics.
- Test-only helper behavior when it cannot mint production evidence or affect release artifacts.

## Past Bug Shapes

- Hash-only evidence accepted where signed or anchored proof was required.
- Sandbox execution evidence without pinned images, credential checks, or network constraints.
- Public or Enterprise claims drifting from Kernel source-owned receipt semantics.
- One project accepting another project's binding, recovery journal, generated
  artifact, or unscoped legacy state.
- Lifecycle recovery accepting an index-only, malformed, or non-canonical
  durable receipt instead of the signed envelope.

## Severity Calibration

- Critical: forged or self-supplied EvidencePack/seal/verdict accepted as production proof.
- High: verifier, sandbox, replay, or boundary receipt can be bypassed or confused across trust boundaries.
- High: unsafe local authority state, cross-project native lifecycle state, or
  a forged lifecycle receipt lets setup/recovery alter client configuration.
- Medium: contract drift that weakens downstream evidence checks but remains blocked by another fail-closed gate.
- Low: incomplete evidence metadata that does not alter enforcement, sealing, or release decisions.
