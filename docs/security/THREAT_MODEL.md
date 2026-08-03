# HELM AI Kernel Threat Model

Version: 2026-08-03-security-evidence-loop-v4
Version Hash: no signed release artifact has been created for this source revision
Owner: HELM Kernel Security
Review Date: 2026-08-03

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

### Desktop local sidecar transport (`transport-v1`, source support)

`transport-v1` defends the local Desktop composition against a distinct local
process squatting a known port and receiving a credential-bearing Console
request. A port, URL, readiness response, or bearer alone is not a
process-identity boundary. It does not claim hostile same-UID or
replaced-process protection.

Status, read back from source on 2026-08-03:

- **`helm-desktop` — implemented.** It sets `HELM_DESKTOP_TRANSPORT_V1` on the
  child, reads a bounded handoff record off the direct child, binds it with an
  HMAC over the per-launch nonce, origin, and challenge, and proves it at
  `/api/v1/desktop/transport/proof` before starting Console. On a handoff
  timeout it fails closed (`transport_timeout`); there is no fixed Kernel-port
  fallback in that handoff path.
- **`helm-ai-kernel` — source support.** An explicit
  `server --desktop-transport-v1` requires the three transport environment
  values, atomically binds `127.0.0.1:0`, writes one bounded authenticated
  direct-child record, and exposes the no-bearer loopback proof route. Ordinary
  fixed-port CLI behavior remains unchanged when the flag is absent.

This source change is not package, native-runtime, release, or security-
certification proof. Those remain separate evidence gates for the full Desktop
composition.

Before any Desktop use of this path can claim a governed local boundary,
`transport-v1` must fail closed:

- Kernel atomically binds `127.0.0.1:0`; there is no Desktop availability
  preflight and no fixed-port fallback.
- Kernel emits one bounded, HMAC-authenticated transport record on its direct
  child stdout. The record binds the per-launch nonce to the dynamic loopback
  origin and port.
- Desktop validates the record's size, encoding, nonce, MAC, loopback origin,
  and port, then verifies `/healthz` before starting Console with the attested
  dynamic origin.
- Console rejects malformed or non-loopback origins before it forwards a
  bearer credential. It does not expose the origin or capability to browser
  code.
- Exit, restart, revocation, a bad transport record, or failed health check
  invalidates the launch and blocks Console; relaunch requires a fresh record.
- Tests cover a pre-bound fixed port, malformed or replayed records, nonce or
  MAC mismatch, non-loopback origins, failed health checks, and absence of a
  fixed-port fallback.

Inherited listeners, Unix-domain sockets, mTLS, or socket activation are the
stronger follow-on requirement for a hostile same-UID or replaced-process
threat. `transport-v1` does not claim that stronger protection.

For a complete transport-v1 design, `helm-desktop` owns the per-launch
nonce/HMAC, direct-child record validation, health check, and sidecar
lifecycle; `helm-ai-kernel` owns the atomic dynamic bind and bounded transport
record; `app-helm-console` owns origin rejection before bearer forwarding and
browser non-exposure. The Kernel proof route is internal and opt-in; it creates
no public API, runtime, or release claim by itself.

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
