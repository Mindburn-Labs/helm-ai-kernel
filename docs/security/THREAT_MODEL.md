# HELM AI Kernel Threat Model

Version: 2026-07-15-security-evidence-loop-v2
Owner: HELM Kernel Security
Review Date: 2026-07-15

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

### Desktop local sidecar transport (`transport-v1`, proposed — not implemented)

The current local Desktop composition starts the Kernel at fixed
`127.0.0.1:8420` and supplies the Console sidecar with `HELM_KERNEL_ORIGIN`
plus a Kernel bearer capability in `HELM_KERNEL_TOKEN`. Its availability
preflight binds and releases a fixed port before the child starts. A local
process that wins that bind, or replaces the listener after startup, can receive a
credential-bearing Console request. Loopback addressing and the Console
readiness HMAC do not bind the receiving endpoint to the spawned Kernel
process.

`transport-v1` must defend against an untrusted local process that can
bind/rebind loopback endpoints but cannot read inherited private handles or
tamper with the Desktop, Kernel, or Console processes. It does not claim to
defend a compromised user account or a compromised sidecar process. A port,
URL, readiness response, or bearer alone is not a process-identity boundary.

Before any Desktop use of this path can claim a governed local boundary,
`transport-v1` must fail closed:

- Desktop creates and retains the private listener, then transfers its owned
  handle to the Kernel; there is no bind-then-close preflight or fixed-TCP
  fallback.
- Kernel serves only on that inherited listener or a platform-private
  socket/pipe and rejects peers without a per-launch, endpoint-bound
  capability.
- Console uses that private channel only. It must not receive a reusable
  Kernel bearer plus an arbitrary local origin, and it must not expose the
  channel or capability to browser code.
- A sidecar exit, restart, revocation, or failed peer check invalidates the
  launch capability and blocks the Console rather than reconnecting to a
  replacement endpoint.
- Tests cover malicious pre-bind, post-ready listener replacement, stale or
  replayed launch capabilities, wrong peer, and cleanup after crash/restart.

Cross-repository ownership is explicit: `helm-desktop` owns endpoint creation,
handle transfer, and sidecar lifecycle; `helm-ai-kernel` owns private-listener
serving and peer/capability verification; `app-helm-console` owns the BFF
client boundary and browser non-exposure. No runtime code or public API in
this repository implements `transport-v1` yet.

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
