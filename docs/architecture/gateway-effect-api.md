# Gateway effect API (contract 1)

<!-- quantum_posture: this note describes a wire contract that carries SHA-256
digests as opaque values and no signatures or keys. It adds no cryptographic
control and makes no post-quantum claim; token verification is ADR-0005's. -->

Status: draft wire contract, HELM-751 slice 1, 2026-09-25. This revision
includes WS-B's review of 2026-09-25 (PR #1015), which the coordinator
accepted; the coordinator's resolutions of 2026-09-26 (see "Resolved"); and
slice 1b (the delegated requester, whole-second approval digests). Under target architecture rev 3.4 §1 the contract is *Specified*: it
is versioned. Slice 2 adds a server, `helm-gateway`, for `Propose`,
`Approve`, `Reject`, `Cancel`, `GetAttempt` and `GetAttemptContent` (see "The
server (slice 2)"). Slice 3 adds `Dispatch` and `Observe` through the
GitHub adapter (see "Dispatch and Observe (slice 3)"). Slice 3b adds `Stop`
and `Lift`, and the River jobs that expire escalations and reconcile
`UNKNOWN` (see "Stop, Lift and jobs (slice 3b)").

- IDL: [`protocols/proto/helm/gateway/v1/gateway.proto`](../../protocols/proto/helm/gateway/v1/gateway.proto),
  package `helm.gateway.v1`, service `EffectGatewayService`.
- Go bindings: `sdk/go/gen/helm/gateway/v1`. `gateway.pb.go` holds the
  messages; `gateway.connect.go`, from `protoc-gen-connect-go`, sits in the
  same package.
- Contract tests: `sdk/go/gen/helm/gateway/v1/gateway_contract_test.go`.
- The authority rows admission reads are written through a second service in the
  same package, `AuthorityAdminService`: see
  [Gateway provisioning API](gateway-provisioning-api.md).
- Binding references: rev 3.4 §4.1–§4.6, §8, §10.1, §11 and the §12.3
  contract list; ADR-0001 (admission), ADR-0003 (settlement) and ADR-0005
  (tenant from the token). All of them live under
  `output/helm-rebuild-strategy-2026-09-23/` in the workspace.

## Operations

Rev 3.4 §4.2 names six operations. Two of them are pairs, so the service has
eight RPCs for them. WS-B's review adds two more, `Cancel` and
`GetAttemptContent`.

| Operation | RPC | Idempotency | ADR-0001 reference |
|---|---|---|---|
| §4.2 `Propose` | `Propose` | `(tenant, idempotency_key)` plus request digest | `admission.Propose` |
| §4.2 `Approve` / `Reject` | `Approve`, `Reject` | on the attempt; one approval per attempt | `admission.Approve`, invariant I6 |
| added: cancel | `Cancel` | on the attempt | the `ADMITTED → CANCELLED` narrowing (ADR-0003 `ReleaseBeforeDispatch`) |
| §4.2 `Dispatch` | `Dispatch` | on the attempt; the permit is consumed once | `admission.ClaimDispatch` |
| §4.2 `Observe` | `Observe` | on the attempt; no transition outside `DISPATCHED`/`UNKNOWN` | §4.1 item 4 (no reference code) |
| §4.2 `Get` | `GetAttempt` (`NO_SIDE_EFFECTS`, so Connect allows GET) | read | — |
| added: content read | `GetAttemptContent` (`NO_SIDE_EFFECTS`) | read | §5.6 content blobs |
| §4.2 `Stop` / `Lift` | `Stop`, `Lift` | `(tenant, idempotency_key)` | `admission.Stop`, `admission.Lift` |

`Lift` widens authority, so it does not lift anything by itself. It creates a
`helm.authority.lift` effect attempt, which is approved with `Approve` (with
step-up) and applied by `Dispatch` like any other attempt (§4.1 item 7,
ADR-0001 §1). Its payload belongs to contract 5.

`Cancel` handles two states:

- On an `ADMITTED` attempt it is ADR-0001's narrowing: the permit is voided
  and the reservation released in one transaction.
- On an `ESCALATED` attempt it withdraws the approval request. Nothing is
  reserved, so nothing is released.

Rev 3.4 §4.3 has no `ESCALATED → CANCELLED` edge, and §4.2 does not list
`Cancel` among the mutating entry points. Both are a recorded amendment to
rev 3.4 (see "Resolved"). `Cancel` fails once dispatch has started, because a
dispatched call cannot be retracted.

Two rules apply everywhere:

- **Decisions are states, not errors.** `DENIED`, `ESCALATED`, `CANCELLED` and
  `UNKNOWN` come back as the attempt's state in a successful response. A Connect
  error means the gateway could not evaluate the request. Each error carries one
  `helm.errors.v1.ErrorDetail` (#992). The service comment lists the codes.
  The exceptions are refused decisions (self-approval, digest mismatch, missing
  step-up), which are errors that leave the attempt `ESCALATED`.
- **A duplicate never dispatches twice (R6).** A repeated `Propose` with the
  same key and content returns the stored attempt in whatever state it is in,
  pending or `UNKNOWN` included, with `existing = true`. The same key with
  different content is `already_exists`. `Dispatch` on an attempt that is
  `CANCELLED`, `DISPATCHING` or later returns it unchanged.

## Messages and where they come from

| Message / field | Source |
|---|---|
| `ProposeRequest.idempotency_key`, request digest | R6, ADR-0001 §1 step 1. The digest covers every field except the key, plus the authenticated principal. |
| `ProposeRequest.mandate_id` | ADR-0001 `Request.Mandate`. Optional since s1b: the gateway resolves the mandate from `sub` and the effect type, and this selects among several. It must be held by `sub`; never a grant (R3). |
| `ProposeRequest.work_ref` (`commitment_id` or `case_id`) | Rev 3.4 §3, schema `work_ref`. Optional for `helm.authority.*` until contract 5. |
| `EffectDescriptor` (`effect_type`, `target`, `arguments`) | §4.1 item 1 effect descriptor. The log carries digests only (R13). |
| `ResourceAmount` (`quote`) | ADR-0001 `Request.Amounts`. Integer; money is minor units of an ISO 4217 currency (§3). Ignored for model calls, which the gateway prices itself. |
| `DistinctValue` | ADR-0001 `Request.Distinct`, rule class U. |
| `ProposeRequest.approval_expires_at` | WS-B review item 4. Optional, clamped to the mandate's approval window; when it is unset, the mandate's approval window applies. |
| `EffectAttempt.state` (`EffectAttemptState`) | §4.3, schema `effect_attempts.state`. See below. |
| `EffectAttempt.risk_class` | Effect-type control row. Never read from the request. |
| `EffectAttempt.reason_code` | ADR-0001 §6, registry strings. |
| `EffectAttempt.workspace_id` | The proposer's token (R9, ADR-0005). Output only. |
| `EffectAttempt.episode` (`EpisodeRef`), `ListAttemptsRequest.episode_id` | The token's `helm_episode` claim (HELM-752 K7): the worker run an attempt was proposed in. Output only, except the list filter; a request cannot name an episode. See "Episode attempts". |
| `EffectAttempt.requester_actor_id`, `Approval.approver_actor_id` | The token's `act.sub` (RFC 8693, ADR-0005 §2). Output only; empty for a direct call. See "The delegated requester". |
| `PendingApproval.approval_digest`, `ApproveRequest.approval_digest` | §10.1 approval digest, v1 below. An approval binds to the digest the approver saw. |
| `ApproveRequest.reason`, `RejectRequest.reason`, `Approval.reason` | WS-B review item 2. At most 2000 bytes; required on `Reject`. The log carries the digest (R13). |
| `Approval` | Schema `authority.approvals`, unique per attempt (I6). |
| `Permit`, `AuthorityVersion` | Schema `authority.permits` (`authority_versions`, `consumed_at`, `claim_id`, `void_reason`). These are the fields the dispatch claim compares. |
| `Exposure`, `ExposureKind` | ADR-0003, `authority.exposures`: one per attempt and counter bucket. |
| `ModelCallSettlement`, `SettlementState` | ADR-0003, `authority.model_calls`; §8's four quantities in integer micro-units. |
| `Observation` | §3 (source, freshness, trust class) and §4.1 item 4. `result_ref` is a content-addressed §5.6 blob readable with `helm.gateway.read`. |
| `Stop`, `StopScopeKind` | Schema `authority.stops` (`scope_kind`, `scope_key`, `expires_at`, `lifted_at`). |

### Held field numbers

Some fields wait on another slice's design. Their numbers are kept free, and
`TestHeldFieldNumbersStayFree` fails if anything takes them:

- `Observation` fields 10–15: typed, bounded result payloads for later effect
  types (fields 7–9 carry the GitHub results).

`ApproveRequest` field 4 was held for the §10.1 step-up assertion until the
step-up proof took it (see "Step-up proof").

They are not declared `reserved`. Under the `FILE` category, buf breaking would
reject the later change that uses such a number, because it deletes a reserved
range. The slice that adds a field updates the test list.

### State machine

The enum follows §4.3 literally. `OBSERVED` and `RECONCILED` carry the outcome
in a separate `outcome` field (`SUCCEEDED` or `FAILED`), and `outcome_basis`
keeps how it was established after the attempt moves on to `SETTLED`. The
reference schema folds these into `SUCCEEDED`/`FAILED` states; the implementing
slice stores the basis instead of losing it.

- `PROPOSED` exists only inside the admission transaction.
- `APPROVED` is transient: `Approve` re-runs admission in the same transaction
  (ADR-0001 §5.5), so a committed attempt is `ADMITTED` or `DENIED`.
- `UNKNOWN` is the domain state, not an unrecognised enum value. It keeps its
  reservation and is never re-dispatched by `Dispatch`.
- `CANCELLED` comes from three places:
  - a refused dispatch claim (a stop, any authority version change, or an
    expired permit), which sets a reason code;
  - `Cancel`, which sets none;
  - a release before dispatch.

  Any reservation is released in the same transaction.

### Self-approval is a refused call, not a denial

ADR-0001 §1 says `Approve` "requires state `ESCALATED` and an active approver
who is not the requester". The contract makes that a precondition. A
self-approval is `permission_denied` with `APPROVER_NOT_DISTINCT`, nothing is
written, and the attempt stays `ESCALATED`, so the distinct human who should
decide still sees it.

The reference `Decide` also denies `ApproverID == PrincipalID`, which in the
reference makes the attempt terminally `DENIED`. Under this contract that
branch is only a backstop that the precondition makes unreachable. The
Control Plane behaves the same way today: a 403 with nothing written, and the
Console's refusal UI (#230) relies on it.

### Approval digest v1

The Console recomputes the digest from what it displays and refuses to submit
on a mismatch. The construction is SHA-256 over the concatenation of:

1. `field("helm.gateway.v1.approval-digest.v1")`: the domain tag;
2. `field(attempt_id)`: the UTF-8 bytes of the lowercase, hyphenated UUID
   string;
3. `field(target_digest)`: SHA-256 of the target's UTF-8 bytes;
4. `field(argument_digest)`: SHA-256 of the argument bytes;
5. the quote, which is the exposure the approver accepts: `u64(entry count)`,
   then for each entry sorted by unit bytes, `field(unit) || u64(amount)`;
6. `field(expires_at)`: the RFC 3339 text of `expires_at` in UTC, whole
   seconds, with a `Z` suffix and no fractional part, for example
   `2026-09-26T12:00:00Z`.

`u64(n)` is an 8-byte big-endian unsigned integer, and `field(b)` is
`u64(len(b)) || b`. The attempt ID binds the effect type, mandate and
requester on the server, so the digest follows §10.1's list of fields and
adds nothing.

**Timestamps are whole seconds (s1b).** Every timestamp in the digest is
encoded as RFC 3339 UTC text with `Z` and whole seconds. The gateway
truncates `expires_at` to the second when it writes it, and truncates
`ProposeRequest.approval_expires_at` the same way. A PostgreSQL `timestamptz`
round-trip keeps microseconds, so without truncation a stored
`12:00:00.987654Z` could come back in a different form than the client
hashed. With truncation, any fractional input produces the same digest as the
whole second. No server emits digests yet, so s1b changes the v1 encoding in
place rather than minting v2. The first revision encoded seconds and nanos as
binary integers.

Test vector:

| Input | Value |
|---|---|
| `attempt_id` | `0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d` |
| target | `github.com/Mindburn-Labs/example/pull/42` |
| `target_digest` | `88075297ac48e169fc8304871a612a786d58f461cbd377e2a074c6a2b9070f64` |
| arguments | `{"merge_method":"squash"}` |
| `argument_digest` | `a251ae0221cb7e5b1c1fb10c05a07c4c17b6f776d117cb73ba78d200afd3ac0f` |
| quote | `count` = 1, `USD` = 2500 (sorted: `USD`, `count`) |
| `expires_at` | `2026-09-26T12:00:00Z`, encoded as that 20-byte text |
| **approval digest** | `7efd7515c4c739e32f6c61ef3214bff08013771f5fdc02da1dd2b1e3806edf31` |

Truncation case: the same inputs with `expires_at` =
`2026-09-26T12:00:00.987654Z` encode as `2026-09-26T12:00:00Z` and give the
same digest, `7efd7515…6edf31`.

`TestApprovalDigestVector` checks both cases against the Go reference and
against an independent Python implementation,
`sdk/go/gen/helm/gateway/v1/testdata/approval_digest.py`, which it runs. The
test also checks that a different second changes the digest, and it fails if
this note stops carrying the values.

For attempts the Control Plane proposed, it already holds the argument bytes.
For attempts proposed by others, the Console reads them with
`GetAttemptContent`. In both cases the client checks
`sha256(arguments) == argument_digest` before it renders them.

### The delegated requester (s1b)

The Control Plane proposes from its background runner on behalf of a human.
This uses RFC 8693 delegation, which ADR-0005 tokens already carry: the
Propose token's `sub` is the requesting human, and its `act.sub` is the
runner's workload identity.

- The gateway records `requester_principal_id = sub` and
  `requester_actor_id = act.sub`. `requester_actor_id` is empty when the
  principal proposed directly.
- Approver ≠ requester (ADR-0001 I6) is therefore checked against the human.
  The runner workload can neither approve nor count as a second person.
- A Propose token whose `sub` is a human principal is accepted only when its
  `act.sub` is a configured workload actor. Today that is
  `HELM_CP_IDENTITY_ACTOR`; later it is the gateway's own actor list. Any
  other actor is `permission_denied`.
- No request message carries `on_behalf_of` or an actor field (R9). The
  identity contract test rejects `actor`, `*_actor_id` and `on_behalf_of*`
  fields in every request.
- `Approval.approver_actor_id` is the same record for decisions: the
  `act.sub` of the decide token when a workload (the Control Plane) carries
  a human's decision, and empty when the approver's session calls the
  gateway directly. The coordinator asked for the requester's actor "on the
  Approval record if one exists". On a decision the relevant actor is the one
  that carried the approver's token, so the field is named for the approver.
  The requester's actor is already on the attempt.

### Mandate selection (s1b)

There is no mandate lookup RPC. At admission the gateway resolves the mandate
from the token's `sub` and the effect type, using the mandate rows of
HELM-750 s2b.

- `ProposeRequest.mandate_id` is an optional selector, for when more than one
  mandate applies.
- The selector is valid only if the mandate is held by `sub`. Otherwise the
  attempt is denied.
- The Control Plane's activation-ref stand-in works only against the fake
  gateway. The real gateway never takes an activation reference in place of
  a mandate.

### Typed observation results and the GitHub effects (HELM-753)

`Observation.result` is a oneof with one member per effect type that defines a
typed result. Fields 10–15 stay held for later result types
(`TestHeldFieldNumbersStayFree`). Clients read these fields, never the
provider's raw bytes.

The HELM-789 walking skeleton needs three GitHub effects. Their argument schemas
are closed JSON Schemas with known-good and known-bad fixtures, checked by the
`json-schemas` gate:

| Effect type | Arguments | Risk | Result |
|---|---|---|---|
| `github.repository.get` | `protocols/json-schemas/effects/github/repository_get.v1.json` | low (admitted) | `github_repository` (field 9) |
| `github.branch.create_from_changes` | `protocols/json-schemas/effects/github/branch_create_from_changes.v1.json` | medium (admitted under a mandate) | `github_branch` (field 8) |
| `github.pull_request.create_draft` | `protocols/json-schemas/effects/github/pull_request_create_draft.v1.json` | medium (escalated by mandate policy) | `github_pull_request` (field 7) |

Rules for both:

- **Target.** The target is `github.com/{owner}/{repo}`, with owner matching
  `^[A-Za-z0-9-]{1,39}$` and repo matching `^[A-Za-z0-9._-]{1,100}$`. It has
  no `#`, `?`, extra or trailing `/`. The repository comes only from the
  target; the arguments never name one (audit 09-02).
- **Bytes.** The arguments are exact UTF-8 bytes, at most 64 KiB. The gateway
  refuses duplicate keys, unknown fields and a missing required field before
  admission, and digests the bytes as sent. The Console shows the same bytes
  through `GetAttemptContent`.

**Risk and approval.** The draft pull request is medium risk: closing it
reverses it, it is not a production change, and it leaves the default branch
alone. It escalates because the mandate requires approval for
`github.pull_request.create_draft` (`approval_required`, an ADR-0001 rule
class), not because of its risk class. Step-up (§10.1) stays with high or
irreversible effects, such as merges to the default branch, releases and
publishes.

**Repository read.** `github.repository.get` reads the default branch and its
head commit, and the head of a named branch when one is requested. The Control
Plane proposes it first and copies `default_branch` and `default_branch_sha`
into the branch attempt's `base` and `base_sha`, so the base comes from a
gateway read, not from Zone B. It is the skeleton's allowed read.

**Branch.** The adapter creates the blobs, the tree, a commit whose only
parent is `base_sha`, and then `refs/heads/{head}` if it does not exist. Rules
the gateway enforces beyond the schema:

- `head` starts with the mandate's branch prefix, `helm/` for the skeleton, and
  is not the repository's default branch, read at Prepare and again at
  Dispatch.
- `.github/workflows/` is refused. A workflow file is code execution and gets
  its own effect type.

The read-back is SUCCEEDED only if all of these hold:

- the ref points at `commit_sha`;
- that commit's parents are exactly `[base_sha]`;
- `compare/{base_sha}...{commit_sha}` lists exactly the proposed paths;
- each blob's git SHA-1 equals the one computed from the proposed content,
  `sha1("blob <len>\0" + bytes)`.

Anything else is FAILED with `READBACK_MISMATCH`. If the ref already exists,
the same commit reconciles to SUCCEEDED and a different one is
`READBACK_MISMATCH`. Nothing is ever overwritten.

`files_digest` is SHA-256 over the files sorted by path, each encoded as
`path 0x00 mode 0x00 blob-sha1-hex 0x0A`. Vector, checked by
`TestGitHubBranchFilesDigestVector`:

| Path | Mode | Content | Blob SHA-1 |
|---|---|---|---|
| `docs/skeleton.md` | `100644` | `# Skeleton\n` | `41b86bfc1930f3be282f9d5dcb8b3816deda7b8c` |
| `scripts/ok.sh` | `100755` | `#!/bin/sh\necho ok\n` | `e37f89b3b76e73e0d000552c897006f0b8ba1b76` |

`files_digest` = `c361fc7cce27fa9aa3f9e7ef1b275961a2418fff20e16fa1846e5bc50b43ec54`

**Draft pull request.** `branch_attempt_id` names the branch attempt. At
Propose the gateway requires that attempt to meet all of these, or it refuses
with `PRECONDITION_FAILED` and creates no attempt:

- it is in the same tenant and has the same target;
- it is `github.branch.create_from_changes` in OBSERVED(SUCCEEDED) or
  RECONCILED(SUCCEEDED). Reconciliation runs the same ref, parent, compare
  and blob checks as Observe, so both prove the same commit;
- its `head` and `base` equal these;
- its `commit_sha` equals `head_sha`.

The approver's diff is therefore the branch attempt's files, and the gateway
has checked that they are what `head_sha` contains. At Dispatch the adapter
re-reads `refs/heads/{head}` and refuses unless it still equals `head_sha`, so
a push after approval is caught.

Idempotency is conditional: one open pull request per (head, base). On a lost
response, Observe finds the pull request by head and base. If the provider's
answer was not definitive, the attempt stays UNKNOWN and is never
re-dispatched blindly.

The read-back is SUCCEEDED only if `draft` is true, `head_sha` equals the
proposed value, `base_ref` equals `base`, and the title matches. Otherwise it
is FAILED with `READBACK_MISMATCH`, and the result still records the URL.

**Dispatch-time refusal is a state, not an error.** When the Dispatch-time
`head` re-read refuses the write, `Dispatch` returns a successful
`DispatchResponse` whose attempt is OBSERVED(FAILED) with `reason_code`
`PRECONDITION_FAILED`. It does not return a Connect `failed_precondition`
error; per the wire rules, a Connect error means the gateway could not
evaluate the call.

A FAILED outcome carries its reason in `EffectAttempt.reason_code`:
`READBACK_MISMATCH`, or `PRECONDITION_FAILED` when the Dispatch-time `head`
re-read refused the write. No provider write happened then, so the outcome is
a certain FAILED and the reservation is released. The Propose-time
`branch_attempt_id` check creates no attempt; it answers a Connect
`failed_precondition` error whose `ErrorDetail.reason_code` is
`PRECONDITION_FAILED`.

The adapter is `core/pkg/gateway/adapters/github` (HELM-753). Since HELM-751
s3, `helm-gateway`'s `Dispatch` and `Observe` call it. It performs all three effects above. It registers and emits `READBACK_MISMATCH` and `PRECONDITION_FAILED`, plus
`PERMIT_ARGUMENT_MISMATCH` (the permit's argument digest is not SHA-256 of the
bytes it is about to send, audit 09-01), `PROVIDER_CREDENTIAL_REJECTED`,
`PROVIDER_RESPONSE_TOO_LARGE` (audit 09-04) and `PROVIDER_ERROR`. Its dispatch
answers one of three statuses:

- `SENT`: the provider accepted the write, or already holds the ref or open
  pull request the write would create. The adapter never overwrites it, and
  `Observe` decides the outcome: SUCCEEDED if it is this effect, otherwise
  FAILED with `READBACK_MISMATCH`.
- `NOT_SENT`: nothing visible was written, so the outcome is certainly FAILED
  with the reason, and the gateway records OBSERVED(FAILED) and releases the
  reservation. Before the ref exists, the branch's new objects are
  unreachable. A `PRECONDITION_FAILED` at Dispatch (for example, the head
  moved) is always `NOT_SENT`, never UNKNOWN.
- `INDEFINITE`: the write may have happened, for example after a lost answer,
  a 5xx or a 422 to the write itself. The attempt is UNKNOWN, and `Observe`
  reconciles it; it is never dispatched again.

The read-back does not check file modes, because the comparison does not
report them. `files_digest` is computed from the proposal, and the read-back
has confirmed each blob ID in it but not the modes. `CheckBranchAttempt` in
the same package is the pure form of the Propose precondition above. The
gateway calls it for the head, base and `head_sha` checks, after its own
tenant, workspace, type and state checks.

### Reason codes

Reason codes are strings from `reason-codes-v1.json`. The proto marks each one
it names:

- `[reason_code: X]`: registered today. Used: `EMERGENCY_STOP_FENCED`,
  `BUDGET_EXCEEDED`, `APPROVAL_REQUIRED`, `APPROVAL_TIMEOUT`, `SCHEMA_VIOLATION`,
  and, registered by slice 2 because its admission emits them,
  `PRINCIPAL_INACTIVE`, `MANDATE_INACTIVE`, `MANDATE_OUTSIDE_VALIDITY`,
  `EFFECT_OUT_OF_SCOPE`, `PER_CALL_LIMIT`, `ARITHMETIC_OVERFLOW` and
  `IDEMPOTENCY_CONFLICT`; and, registered by slice 3 because its dispatch
  claim emits them, `AUTHORITY_CHANGED` and `PERMIT_EXPIRED`.
- `[reason_code_pending: X]`: registered by the slice that first emits it,
  because the registry gate rejects codes that nothing emits (ADR-0001 §6).
  These are the rest of ADR-0001 §6's list, plus `STEP_UP_REQUIRED`, which
  this contract adds for approvals that fail closed without step-up.

The contract test fails if a `reason_code` is not registered, and if a
`reason_code_pending` has been registered, so the markers stay true as codes
land.

## Token scopes

Tenant, workspace and principal come only from the token (R9, ADR-0005). No
request message has a tenant, workspace or caller-principal field, and the
contract test enforces that. ADR-0005 allows one scope per token. An RPC may
accept tokens of more than one scope; `Cancel` does.

WS-B (Control Plane) proposed the scopes on 2026-09-25: one per authority
class, not one per RPC and not one blanket scope. The coordinator resolved the
open points on 2026-09-26 (see "Resolved" below). Mapped onto the real RPC
names:

| Scope | RPCs | Minted for | Token rules |
|---|---|---|---|
| `helm.gateway.propose` | `Propose`; `Cancel` of one's own attempt | any principal, humans included | — |
| `helm.gateway.decide` | `Approve`, `Reject` | a human principal only, from an interactive session, never a worker | single-use; bound by `authorization_details` |
| `helm.gateway.read` | `GetAttempt` (§4.2's `Get`), `GetAttemptContent`, `ListAttempts`, `result_ref` blobs, and `GetProvisioning` and `ListEffectTypes` of `AuthorityAdminService` | any principal with workspace read | — |
| `helm.gateway.stop` | `Stop`, `Lift`; `Cancel` of another principal's attempt | human operators and admins only | single-use; a `Lift` token is bound by `authorization_details` |
| `helm.gateway.execute` | `Dispatch`, `Observe`, and the model gateway's inference endpoint (§8) | workload principals only: the Control Plane backend and SDK agent runtimes. Never a human session, and never a worker's propose token | — |

Two scopes serve one RPC each. `helm.gateway.provision` belongs to
`AuthorityAdminService.EnsurePrincipals` alone: the Control Plane's service
principal holds it, and none of the RPCs above takes it (see
[Gateway authority provisioning](gateway-provisioning-api.md)).
`helm.gateway.stepup` is the scope of the step-up proof that `Approve` may
carry (see "Step-up proof"); no RPC takes it as its own credential.

WS-B's table lists "Get, GetAttempt" for `helm.gateway.read`. They are one RPC:
§4.2's `Get` is `GetAttempt`.

### Binding decide and lift tokens (RFC 9396)

A decide token and a `Lift` token each name their one target in the RFC 9396
`authorization_details` claim. `txn` keeps its ADR-0005 meaning, a unique
transaction ID that is logged.

For `Approve` and `Reject`, the claim is:

```json
"authorization_details": [
  {"type": "helm_effect_decision", "attempt_id": "<attempt_id>", "action": "approve"}
]
```

`action` is `approve` or `reject`. The gateway requires exactly one entry of
this type. Its `attempt_id` must equal the request's, and its `action` must
match the RPC; otherwise the call is `permission_denied`.

For `Lift`, the claim is:

```json
"authorization_details": [
  {"type": "helm_stop_lift", "stop_id": "<stop_id>"}
]
```

`stop_id` must equal the request's. The lift attempt that `Lift` creates is
then approved with a decide token bound to that attempt, like any other.

A `Stop` token names the stop request it was minted for (L1 of the slice 3b
review), so a token issued to cancel or lift cannot be spent on a tenant-wide
stop:

```json
"authorization_details": [
  {"type": "helm_stop", "idempotency_key": "<key>", "scope_kind": "tenant", "scope_key": ""}
]
```

An operator's stop token on `Cancel` names the attempt it withdraws (slice
3b; L4 of the slice 2 review):

```json
"authorization_details": [
  {"type": "helm_effect_cancel", "attempt_id": "<attempt_id>"}
]
```

A requester cancelling its own attempt with a propose token needs no binding.

### Model calls

A model call is admitted like any other effect, then dispatched differently
(§8, HELM-752):

1. `Propose` admits it. The gateway prices the quote from the route and the
   clamped `max_tokens`, and ignores the caller's `quote`.
2. The caller presents `permit_id` to the model gateway's inference endpoint
   with a `helm.gateway.execute` token.
3. The gateway injects the provider key (R8), claims the permit, streams the
   response and settles it (ADR-0003).

Model calls keep this inference-endpoint path. Other effects are dispatched
through the `Dispatch` RPC. HELM-752 names the model-call effect type and the
endpoint.

## Resolved (coordinator, 2026-09-26)

The first revision of this note listed six points where WS-B's scope proposal
conflicted with rev 3.4 or the ADRs. They are resolved as follows.

1. **`Dispatch` and `Observe` are external RPCs**, as rev 3.4 §4.2 has them.
   Their scope is `helm.gateway.execute`, minted only for workload principals
   (the Control Plane backend and SDK agent runtimes), never from a human
   session or a worker's propose token. The product therefore still decides
   when an admitted effect is dispatched. Model calls keep the
   inference-endpoint path described above.
2. **Single-use decide and stop tokens: accepted.** This needs an ADR-0005
   amendment, proposed below for §9. It covers the `decide` and `stop` scopes
   only; every other scope keeps "no replay cache".
3. **`txn` is not overloaded.** Decide and lift tokens bind their target
   through RFC 9396 `authorization_details`, with the claim shapes above.
4. **`helm.gateway.propose` may be minted for any principal**, humans
   included: effects started from the Console, and authority changes proposed
   from the organization module (§12.4). Separation of duties comes from two
   things: propose and decide are different scopes, and the approver must
   differ from the requester (ADR-0001 I6). Limiting who can propose is not
   the mechanism.
5. **Approvers are humans only.** This narrows ADR-0001 I6, which requires a
   verified principal distinct from the requester. The narrowing is
   compatible. The gateway checks the approver's `kind` in its own principals
   table, not a claim from whoever minted the token.
6. **`Cancel` and the `ESCALATED → CANCELLED` edge** are a recorded amendment
   to rev 3.4 §4.2 (a new mutating entry point, narrowing, no approval) and
   §4.3 (a new edge). The coordinator reports it to Ivan.

### Proposed ADR-0005 amendment (for §9)

> **Single-use tokens for the gateway's `decide` and `stop` scopes.** A token
> with scope `helm.gateway.decide` or `helm.gateway.stop` is single-use. The
> gateway records each accepted token's `jti` in a Postgres table
> (`authority.token_replay`, keyed by issuer and `jti`) in the same
> transaction as the operation the token authorizes (R5). A second use of the
> same `jti` is refused with 403.
>
> - Rows carry the token's `exp` and are deleted once `exp` plus the 30 s skew
>   allowance has passed. At that point the token is invalid anyway, so no
>   replay window opens.
> - Process memory is never the replay store.
> - Every other scope, including the four Control Plane routes of §2, keeps
>   "no replay cache": replay there is bounded by the TTL and by the R6
>   idempotency keys.
>
> **Binding.** Decide tokens carry `authorization_details` (RFC 9396)
> `[{"type": "helm_effect_decision", "attempt_id", "action": "approve" | "reject"}]`.
> Lift tokens carry `[{"type": "helm_stop_lift", "stop_id"}]`. The gateway
> refuses a token whose binding does not match the call. `txn` keeps its §2
> meaning. Because a bound token names one target, the phase-2 cache (§5)
> does not apply to these two scopes: they are minted per decision, which
> costs one issuer signing hop at human approval rates.
>
> **Audience.** The gateway has its own audience, `helm-gateway:<env>`. A
> token for the kernel audience is refused by the gateway, and the reverse.

## WS-B's answers to the open questions (2026-09-25)

1. **Listing: `ListAttempts` in slice 2.** It is needed in R1 because SDK
   agents propose directly to the gateway, and the Console must find
   `ESCALATED` attempts the Control Plane never created. The name is recorded
   in the service comment. Shape:
   - scope `helm.gateway.read`;
   - filters: `repeated state`, `commitment_id`, `requester_principal_id`,
     `effect_type`, and an `updated_after` cursor;
   - `page_size` of at most 200, with a `page_token`;
   - ordered by (`updated_at`, `attempt_id`).

   The cursor also lets the Control Plane sync its projection incrementally.
2. **Cancel: yes, added in s1.** It is narrowing and needs no approval. It
   applies to `ESCALATED` and `ADMITTED` attempts, releasing any reservation
   (ADR-0003). It is idempotent on the attempt. The requester cancels with
   `helm.gateway.propose`; an operator cancels with `helm.gateway.stop`. The
   Control Plane calls it when a run is cancelled or its commitment is
   rejected.
3. **Workspace: attempts are workspace-scoped.** `workspace_id` is recorded
   from the token at `Propose`. Reads, lists and decisions require the token's
   workspace to match, and a mismatch is `not_found`, as a cross-tenant request
   is. Mandates stay tenant-wide, and so do stops.
4. **Audience and transport.** The gateway takes its own audience,
   `helm-gateway:<env>`, so kernel and gateway tokens cannot be replayed at each
   other. Once mTLS exists, `cnf` is required on every scope. The Control Plane
   presents human decide tokens too, so the binding is to its certificate
   either way.
5. **What the approver sees.** The digest construction and its test vector are
   above, and `GetAttemptContent` returns the argument bytes. The Console
   verifies both before it submits a decision.
6. **Step-up fails closed.** Approvals that need it (high or irreversible risk,
   authority widening, stop lifts) are `permission_denied` with
   `STEP_UP_REQUIRED` unless `ApproveRequest.step_up_proof`, field 4, carries a
   valid proof (see "Step-up proof").
   - Consequence: the proof must be served before R1's first high-risk
     approval (a GitHub merge) and before any authority widening.
   - The Control Plane already has WebAuthn, so WS-B builds its side in
     parallel: it verifies the assertion and signs the proof.
7. **Correlation for authority changes.** `work_ref` is optional for
   `helm.authority.*` types until contract 5 settles it.
8. **Units.** `ResourceAmount.unit` names a unit declared by the tenant's
   limits. The unit vocabulary belongs to the limit templates, which §17.3
   still lists as open. Model calls are priced by the gateway.
9. **Outcomes to Zone B.** Until contract 6 (effect and observation events)
   exists, the product reads attempts, incrementally through `ListAttempts`'
   `updated_after` cursor once s2 lands.

## The server (slice 2)

`core/cmd/helm-gateway` serves the contract; the server lives in
`core/pkg/gateway/...` and imports nothing from the legacy Guardian, proxy,
MCP or executor packages (`TestGatewayDoesNotImportTheLegacyRuntime`), so it
can move to its own repository.

| Command | What it does |
|---|---|
| `helm-gateway migrate` | Applies the gateway schema to `HELM_GATEWAY_DATABASE_URL`: the authority rows (`docs/architecture/authority-rows.md`) and the admission tables, each under forced tenant row security, recorded in the `gateway_schema_migrations` journal. It refuses a database newer than the binary. |
| `helm-gateway serve` | Serves Connect, gRPC and gRPC-Web on `:8443` over TLS (`HELM_TLS_CERT_FILE`, `HELM_TLS_KEY_FILE`; `HELM_TLS_CLIENT_AUTH=require` with `HELM_TLS_CLIENT_CA_FILE` for mutual TLS), and `/healthz` and `/readyz` on `:8081`. `/readyz` answers 200 only when the database is reachable and its schema is at the binary's head. |
| `helm-gateway serve --dev-insecure-listen 127.0.0.1:PORT` | Plain HTTP (h2c) on a loopback IP, for local development. Any other address is refused; token checks are unchanged. |

Tokens are ADR-0005 tokens, verified by the kernel's one verifier
(`core/pkg/auth/jwks`) from `HELM_CP_IDENTITY_JWKS_URL`, `_ISSUER`,
`_AUDIENCE` (the gateway's own, `helm-gateway:<env>`), `_ACTOR`,
`_MAX_TTL`, `_REQUIRE_CNF` and `_OUTBOUND_CA_BUNDLE_FILE`. A token must carry
exactly one audience and one scope, `sub`, `tenant_id` and `workspace_id`.
`act.sub`, when present, must be the configured actor. A human's Propose must
come through that actor (see "The delegated requester").
`HELM_GATEWAY_PERMIT_TTL` (default 10m) and `HELM_GATEWAY_APPROVAL_WINDOW`
(default 24h) tune admission.

**Propose** is ADR-0001's admission transaction, one READ COMMITTED
transaction bound to the token's tenant:

1. The request is validated first; a malformed request, including arguments
   that break their effect type's closed schema, is `invalid_argument` and
   creates no attempt. Every effect's arguments are one JSON object of at most
   64 KiB of UTF-8 with no duplicate key. Field names match exactly and
   case-sensitively: `Head` or `ſchema` is an unknown field, never a spelling
   of `head` or `schema`. The walking-skeleton effect types
   are checked against their HELM-753 schemas and the rules those schemas
   state in prose (`core/pkg/gateway/effectargs`).
2. The attempt is inserted with `ON CONFLICT (tenant_id, idempotency_key) DO
   NOTHING`. The request digest covers every request field but the key, the
   token's principal and its workspace. The same key and digest return the
   stored attempt; another digest is `already_exists` with
   `IDEMPOTENCY_CONFLICT`.
3. For `github.pull_request.create_draft`, `branch_attempt_id` must name a
   branch attempt of the same tenant and target in `OBSERVED(SUCCEEDED)` or
   `RECONCILED(SUCCEEDED)`, with the same head and base, and a read-back
   commit equal to `head_sha`; otherwise
   `failed_precondition` with `PRECONDITION_FAILED`, and no attempt. The
   branch attempt must be in the caller's workspace; a missing one, another
   workspace's, another type or an unobserved one get the same refusal text,
   and the detail goes to the server log.
4. The mandate is resolved from `sub` and the effect type (the selector, when
   set, must be held by `sub`). Then the tenant row, every principal of the
   chain (the requester, and each holder and delegator), the mandates root to
   leaf, the effect-type row and the limits are locked `FOR SHARE`; stops are
   read after the locks; counters are locked `FOR UPDATE` in
   `(limit_id, bucket_start)` order.
5. `Decide` (`core/pkg/gateway/admission/decide.go`) is pure. It denies, in
   order, on a stop, an inactive principal, a missing or revoked mandate, a
   link wider than its parent (`DELEGATION_SCOPE_VIOLATION`), a validity
   window, an effect type or target outside a link, a per-call limit, a
   link's condition (`MISSING_REQUIREMENT`, or `PRG_EVALUATION_ERROR` when it
   cannot be evaluated), a missing effect-type row, and a counter. It
   escalates on a high or irreversible risk class (the effect-type row's,
   raised by any link's `risk_classes`), on a link whose `approval_required`
   names the effect type (how the skeleton's medium draft pull request
   escalates), or on an amount at an approval threshold.
6. ALLOW writes a conditional hold on each counter, the exposure and its
   posting, and a permit that records every locked row's version; DENY and
   ESCALATE set the state. ESCALATED carries `approval_expires_at`, the
   request's value or the approval window, whichever is sooner, truncated to
   the second, and approval digest v1 over the stored attempt.

**GetAttempt** and **GetAttemptContent** read in the token's tenant and
workspace; anything else is `not_found`.

**Approve** and **Reject** take a `helm.gateway.decide` token whose
`authorization_details` holds exactly one `helm_effect_decision` entry for
this attempt and action; anything else is `permission_denied`. The token is
single-use: its `jti` is recorded in `authority_token_replay`, keyed by
tenant, issuer and `jti`, in the decision's own transaction, and a second use
is refused. A token whose `exp` plus 30 s has passed by the database clock
is refused too, and rows are purged only after that point, so clock skew
between the gateway and the database never lets a purge make a token
replayable. Process
memory is never the replay store. A refused call rolls the record back, so
only an accepted operation uses up its token. In the transaction the attempt
is locked `FOR UPDATE`; an attempt no longer `ESCALATED` returns unchanged
with `existing` true. The preconditions, each an error that leaves the
attempt `ESCALATED`:

- the approver is not the requester (`APPROVER_NOT_DISTINCT`), and is an
  active human principal of the tenant in the gateway's own rows
  (`INSUFFICIENT_PRIVILEGE`);
- `approval_digest` equals the attempt's (`failed_precondition`);
- the escalation has not expired (`failed_precondition`,
  `APPROVAL_TIMEOUT`);
- Approve only: a high, irreversible or `helm.authority.*` effect needs
  step-up: a valid `step_up_proof` (see "Step-up proof"), and without one the
  approval fails closed (`STEP_UP_REQUIRED`). The risk is the one
  re-admission computes, so a class raised since the escalation counts. A
  medium effect that a
  mandate escalates through `approval_required`, such as the skeleton's draft
  pull request, is approved without it.

Approve then records the approval and re-runs admission on the stored
request, re-reading stops, the mandate chain and counters: the attempt
becomes `ADMITTED` with a hold and a permit, or `DENIED`. Reject records the
rejection and the attempt becomes `REJECTED` (`APPROVAL_REJECTED`). There is
one decision per attempt.

**Cancel** takes the requester's `helm.gateway.propose` token, or an active
human operator's single-use `helm.gateway.stop` token.

- `ESCALATED` becomes `CANCELLED`.
- `ADMITTED` becomes `CANCELLED`, with the permit voided (`voided_at`) and
  every held exposure released in the same transaction.
- `DENIED`, `REJECTED`, `EXPIRED` and `CANCELLED` return unchanged.
- `DISPATCHING` and later are `failed_precondition`.

A request message is capped at 128 KiB after decompression, and a request
body at 132 KiB as sent, before authentication or any handler runs. Propose
alone has a larger cap, because it alone carries an authority plan (at most
524288 bytes, which a JSON client sends base64-encoded): 764588 bytes of message
and 768684 bytes of body.

Errors carry one `helm.errors.v1.ErrorDetail`. `invalid_argument` carries
`SCHEMA_VIOLATION`; `permission_denied` for a scope, an actor or a human's
direct Propose carries `INSUFFICIENT_PRIVILEGE`, and for a tenant with no
authority rows `TENANT_ISOLATION`; `unauthenticated` and `not_found` carry no
code; a gateway failure is `unavailable` with `retryable` set.

### Slice 2 decisions and open points

- **`ListAttempts` is served.** The proto carries the RPC and its messages (see
  "ListAttempts"); `helm-gateway` answers it under a `helm.gateway.read` token.
- **The approval window is gateway configuration.** The proto clamps
  `approval_expires_at` to "the mandate's approval window", but mandates have
  no such term yet; `HELM_GATEWAY_APPROVAL_WINDOW` stands in for it.
- **A mandate may raise a risk class.** `EffectAttempt.risk_class` is the
  effect-type row's class raised by the chain's `risk_classes`, never lowered
  and never taken from the request.
- **The draft pull request's branch attempt** is accepted in
  `OBSERVED(SUCCEEDED)` or `RECONCILED(SUCCEEDED)`. Slice 3's Observe writes
  those observations.
- **Conditions are compiled at activation** (`authorityrows` refuses one that
  does not compile) and once per condition text per gateway process, never per
  request.
- **A condition that reads an absent field denies.** A mandate covering
  several effect types must guard fields only some of them carry, for example
  `input.effect_type == "github.repository.get" ||
  input.args.head.startsWith("helm/")`, or the read is denied with
  `PRG_EVALUATION_ERROR`.
- **`github.repository.get`** (HELM-753, PR #1058) is validated like the other
  two skeleton types: its closed schema, a 4 KiB cap and a git branch name.

## Dispatch and Observe (slice 3)

`Dispatch` and `Observe` take a `helm.gateway.execute` token. The token's
principal must be an active `agent` or `service` principal of the tenant, per
the gateway's own principal rows; a human is `permission_denied`
(`INSUFFICIENT_PRIVILEGE`). Attempts are read in the token's tenant and
workspace, as for every other RPC.

Only the workload the attempt was proposed through may dispatch or observe
it (coordinator decision, 2026-09-27). That is its requester actor
(`requester_actor_id`, the `act.sub` that carried the Propose, such as the
Control Plane runner), or its requester principal when that principal is
itself the workload. Any other workload in the workspace is
`permission_denied` (`INSUFFICIENT_PRIVILEGE`), and the attempt is unchanged.
The claim records the dispatcher in the permit row
(`claimed_by_principal_id`, `claimed_by_actor_id`). `EffectAttempt` has no
field for it.

**The dispatch claim** (ADR-0001 §1, TA §4.1 item 3) is one transaction,
committed before any provider I/O:

1. The attempt is locked. Only `ADMITTED` is claimed. `CANCELLED`,
   `DISPATCHING` and every later state return unchanged with `existing` true.
   `PROPOSED`, `DENIED`, `ESCALATED`, `APPROVED`, `REJECTED` and `EXPIRED`
   are `failed_precondition`, and so is an effect type no adapter of this
   gateway performs.
2. The attempt's unused permit is locked. No unused permit (consumed or
   voided) is `failed_precondition`: a permit is consumed once.
3. The authority rows are locked `FOR SHARE` again in the global order, and
   the stops are read after the locks.
4. `claimRefusal`, a pure function, decides in this order: an active stop
   (`EMERGENCY_STOP_FENCED`); an expired permit (`PERMIT_EXPIRED`); any
   difference between the permit's `authority_versions` and the rows just
   locked (`AUTHORITY_CHANGED`, ADR-0001 §5.4, even for an unrelated
   widening); a chain link outside its validity window
   (`MANDATE_OUTSIDE_VALIDITY`, because a window ends without a version
   change).
5. A refusal voids the permit (`void_reason_code`), releases every held
   exposure, and moves the attempt to `CANCELLED` with the reason. This is a
   successful response, not an error.
6. Otherwise the permit is consumed (`consumed_at`, `claim_id`) and the
   attempt becomes `DISPATCHING`, with its fence `dispatch_deadline` set to
   the claim time plus `HELM_GATEWAY_DISPATCH_TIMEOUT` (default 2m) plus one
   minute.

**The adapter call** runs after the commit, bounded by the dispatch timeout
and detached from the caller's request, so a client that hangs up does not
interrupt it. The adapter gets its credential from the connection custody for
each call. Its answer is recorded only if the attempt is still `DISPATCHING`
under the same `claim_id`:

| Adapter status | Attempt | Reservation |
|---|---|---|
| `SENT` | `DISPATCHED`, then read back at once: `OBSERVED` with the outcome, or `UNKNOWN` if inconclusive | settled with the outcome |
| `NOT_SENT` | `OBSERVED(FAILED)` with the adapter's `reason_code` (for example `PRECONDITION_FAILED`, `PROVIDER_CREDENTIAL_REJECTED`) and a `gateway.dispatch` observation | released |
| `INDEFINITE` (lost answer, 5xx, 422 to the write) | `UNKNOWN` with the adapter's reason. It is not read back at once, because the provider may still be applying the write | held |

An already existing ref or open pull request is `SENT` without a write. The
adapter never overwrites it, and the read-back decides: `SUCCEEDED` if it is
this effect, `FAILED` with `READBACK_MISMATCH` if not.

**Observe** reads back through the adapter and never dispatches.

- `DISPATCHED` becomes `OBSERVED`; `UNKNOWN` becomes `RECONCILED`.
- An inconclusive read-back leaves `UNKNOWN` (or makes a `DISPATCHED` attempt
  `UNKNOWN`) and records no observation.
- A `FAILED` that rests only on the object's absence (no ref, no pull
  request; the adapter sets `ObserveResult.Absent`) is inconclusive until the
  attempt's `dispatch_deadline` has passed. A write still in flight can make
  the object appear. The attempt stays `DISPATCHED` or `UNKNOWN`, with its
  reservation held. Only an object that contradicts the effect fails it
  early.
- A `DISPATCHING` attempt inside its fence may still be in flight and returns
  unchanged. Past its fence, which means the gateway died between the claim
  and recording the answer, it becomes `UNKNOWN` and is read back. It is never
  sent again. Worker death is not proof of failure (TA §4.3).
- Every other state returns unchanged with `existing` true and no provider
  I/O.

An established read-back records one observation row with the adapter's
`source`, `trust_class`, `evidence_digest` and `observed_at`. The typed result
must be exactly the member the effect type defines, or none for a type that
defines none. Any other shape breaks the contract and counts as inconclusive.
`result_ref` is `sha256:<hex>` over the result's RFC 8785 (JCS) form
(`core/pkg/canonicalize`). The row keeps the result as JSONB, which may
reorder keys, so anyone can recompute the reference from the stored or
returned JSON. `GetAttempt` returns it as `latest_observation.result`, converted from
the adapter's plain Go mirrors to the generated messages in the server.

**Settlement (ADR-0003, count units).** The observed outcome settles the held
exposure in the observing transaction. `SUCCEEDED` moves it to `confirmed`:
the counter moves the amount from `reserved` to `used`, with a reversing held
posting and a confirmed posting. A `FAILED` read-back is settled in one of
two ways:

- When an object contradicts the effect (`READBACK_MISMATCH` without
  `Absent`), the reservation is consumed the same way, because a write of
  ours may have made that object.
- When the object is absent after the fence, the reservation is released,
  because the effect did not happen. `UNKNOWN` and a
`DISPATCHING` attempt keep their hold. The attempt stays `OBSERVED` or
`RECONCILED`: this slice does not write the `SETTLED` state (see the open
points below).

**Connection custody (R8).** `core/pkg/gateway/custody` mints GitHub App
installation tokens, and the adapters never see anything else. The chart
(#1065) mounts the files into the gateway Pod only:

| Variable | Chart path | Content |
|---|---|---|
| `HELM_GATEWAY_GITHUB_APP_ID_FILE` | `/var/run/secrets/helm-gateway-github/app-id` | the numeric App ID |
| `HELM_GATEWAY_GITHUB_APP_PRIVATE_KEY_FILE` | `/var/run/secrets/helm-gateway-github/private-key.pem` | the App's RSA key, PKCS#1 or PKCS#8 PEM |
| `HELM_GATEWAY_GITHUB_INSTALLATIONS_FILE` | `/etc/helm-gateway/github/installations.json` | the installations file below |
| `HELM_GATEWAY_GITHUB_API_URL` | — | optional; default `https://api.github.com`. Plain http only on loopback |

The three files are set together or not at all. `serve` refuses a partial
set. With none set, every GitHub dispatch is `NOT_SENT`
(`PROVIDER_CREDENTIAL_REJECTED`).

The installations file maps a tenant to its installation and the
repositories it may act on. Decoding refuses unknown fields:

```json
{"installations": [
  {"tenant_id": "tenant-a", "owner": "Mindburn-Labs", "installation_id": 12345,
   "repositories": ["Mindburn-Labs/example"]}
]}
```

- `tenant_id`, `owner` and a positive `installation_id` are required.
- A (tenant, owner) pair appears once.
- Each repository is `owner/name` under that owner.

For each call, the custody takes the owner and repository from the effect's
target and looks up the tenant's entry for that owner. It refuses a repository
missing from the entry. Otherwise it signs an RS256 App JWT (`iss` is the App
ID, 9 minutes of lifetime) and posts
`/app/installations/{id}/access_tokens` with `repositories: [name]` and the
least `permissions` the effect type needs:

| Effect type | Permissions |
|---|---|
| `github.repository.get` | `contents: read`, `metadata: read` |
| `github.branch.create_from_changes` | `contents: write`, `metadata: read` |
| `github.pull_request.create_draft` | `pull_requests: write`, `contents: read`, `metadata: read` |

A token therefore reaches one repository with one operation's permissions.
Tokens are cached per (installation, repository, effect type) until 5 minutes
before GitHub's expiry. Each key mints under its own lock, so a slow mint
never blocks another key, and a waiter gives up when its context ends. Tokens
are never logged.

The mandate's `helm/` branch prefix is still the mandate's CEL condition, and
the adapter re-checks the default branch at `Dispatch`.

### Slice 3 decisions and open points

- **`Observe` on `DISPATCHING`.** The proto lists `DISPATCHED` and `UNKNOWN`
  as `Observe`'s inputs. Slice 3 adds `DISPATCHING` past its fence, which is
  the rev 3.4 §4.3 edge `DISPATCHING → UNKNOWN`. Without it, nothing could
  reconcile a gateway that died between the claim and the answer.
- **`SETTLED` is not written.** For count units, the observed outcome is the
  usage confirmation, so the exposure settles in the observing transaction,
  and the state stays `OBSERVED` or `RECONCILED`. The draft pull request's
  precondition needs those states. Whether effect attempts move on to
  `SETTLED` is left to settlement's owner (HELM-752), together with model
  calls.
- **`ESCALATED_TO_HUMAN`** and the polling of `UNKNOWN` are slice 3b's
  River jobs (below). A workload may still call `Observe` at any time.
- **The `Observe` scope** is `helm.gateway.execute`, as the proto says. The
  read scope does not reach it.

## Stop, Lift and jobs (slice 3b)

**Stop.** `Stop` takes a single-use `helm.gateway.stop` token from an active
human operator of the tenant. In one transaction it bumps the version of the
scope's control row (the tenant, a principal, a mandate or an effect type;
`mandates.BumpControlRow`, the same code the authority-row store uses) and
writes the stop row with its issuer.

- **Idempotency.** It is idempotent on `(tenant, idempotency_key)`, with a
  request digest over the principal, scope, reason and expiry (schema v4).
  The same key and request return the stored stop with `existing` true
  without using up the token, so a retry after a lost answer is safe.
  Another request under the key is `already_exists`
  (`IDEMPOTENCY_CONFLICT`).
- **Validation.** A tenant stop names no `scope_key`, because it is always
  the token's tenant. A scope the tenant does not have is `not_found`.
- **Effect.** Admissions after the commit are `DENIED` and admitted attempts
  are `CANCELLED` at their dispatch claim, both `EMERGENCY_STOP_FENCED`. A
  call already dispatched is not retracted: it is read back and recorded as
  usual.
- **Who a principal stop covers** (H1 of the slice 3b review):
  - the requester;
  - the workload that carries its call (the Propose token's `act.sub`, locked
    and versioned with the requester);
  - the principal that dispatches and its `act.sub`;
  - the approver and the workload carrying the decision: `Approve` is
    `permission_denied` (`EMERGENCY_STOP_FENCED`), and the attempt stays
    `ESCALATED` for another approver.
- **Concurrent Stops under one key** make one stop. The request that loses
  the race, or its token's, answers with the winner's stop.
- **The Console's emergency stop (HELM-799)** is a tenant `Stop`.

**Lift.** `Lift` takes a single-use `helm.gateway.stop` token bound to the
stop (`helm_stop_lift`). It proposes a `helm.authority.lift` attempt with the
target `stop:<stop_id>` and the arguments
`{"schema":"helm.authority.lift.v1","stop_id":"<stop_id>"}`, under the
operator's mandate for that effect type.

- **Approval.** Every `helm.authority.*` effect escalates, whatever its risk
  row says. It needs a distinct human approver with a step-up proof (see
  "Step-up proof"), and without one the approval fails closed
  (`STEP_UP_REQUIRED`).
- **Stops.** A lift is not blocked by the one stop it lifts. Every other
  stop, the operator's own and the tenant's included, still applies, at
  admission and at the claim.
- **Only through Lift.** A `Propose` of `helm.authority.lift` is
  `invalid_argument` (`SCHEMA_VIOLATION`): the lift must come with a stop
  token bound to its stop.
- **No limits.** Authority changes spend no resource, so no limit counts a
  `helm.authority.*` effect. `LiftRequest` carries no quote.
- **Idempotency.** A replayed key returns the stored attempt without using
  up the token.

**Sum limits fail closed** (L5 of the slice 2 review; the prerequisite for
HELM-797). Admission refuses a quote that carries no amount for a unit that
a `sum` limit counts: `invalid_argument` (`SCHEMA_VIOLATION`), and no attempt
is created. It does not read the missing unit as zero. A zero amount is
allowed. Distinct-value limits already worked this way.

This applies to reads too: a `github.repository.get` under a mandate with a
summed unit quotes that unit at 0. Limits belong to the mandate, not to an
effect type, so the quote names every unit the mandate's limits sum. The
Control Plane sends the tenant's unit set. An explicit 0 costs nothing, and
the gateway never has to guess that a unit was meant to be free.
`helm.authority.*` effects are the one exception above, because no limit
counts them.

**Jobs (TA §6.1-§6.3).** `core/pkg/gateway/jobs` runs River v0.44.1, the
newest release on Go 1.25, in the gateway's own Postgres.

- **Driver.** It uses River's `database/sql` driver over the same `lib/pq`
  pool, so a job is inserted in the admission transaction itself
  (transactional enqueueing). That driver has no LISTEN, so jobs are worked
  in poll-only mode.
- **Where it runs.** `helm-gateway serve` runs the worker in-process. It is
  leader-elected, and replicas share the queue. `helm-gateway migrate`
  applies River's migrations after the gateway schema, and `/readyz` requires
  both to be current.
- **Expiry job.** The transaction that escalates an attempt enqueues
  `expire_escalation`, due at `approval_expires_at`. The job locks the
  attempt `FOR UPDATE`, as `Approve` does, and writes `EXPIRED`
  (`APPROVAL_TIMEOUT`) if the attempt is still `ESCALATED` past its window.
  Of an approval and the expiry, exactly one makes a transition.
- **Reconcile job.** The dispatch claim's transaction enqueues `reconcile`,
  30 s out. The job runs `Observe`'s read-back without a caller:
  - inside a dispatch fence it snoozes to the fence, spending no attempt;
  - an unresolved read-back retries with backoff: 30 s, doubling, capped at
    30 min;
  - on the last of 12 attempts, an attempt still `UNKNOWN` becomes
    `ESCALATED_TO_HUMAN` with its reservation held;
  - it never dispatches.
- **Tenancy.** River's tables have no row security and hold only tenant,
  workspace and attempt IDs in job arguments. Each job binds its own
  transaction to the tenant it names. Row security on River's tables is
  follow-up L3.
- **Shutdown.** A graceful stop gives running jobs 15 s (River's soft stop)
  before their contexts are cancelled.
- **The last try.** On the last reconciliation try, the hand-off to
  `ESCALATED_TO_HUMAN` runs in its own transaction, whatever made the
  read-back fail (a missing adapter, lost content, a cancelled context).
- **Shared pool.** Every job kind shares one worker pool, so a flood of
  reconciliations can delay expiries. Follow-up L4.

The runtime role needs these grants on River's tables. The chart's
`002_grants.sql` extension point (#1065) must list them; the job proofs'
fixture grants exactly these:

| Table | Privileges |
|---|---|
| `river_job`, `river_leader`, `river_queue`, `river_notification` | `SELECT, INSERT, UPDATE, DELETE` |
| `river_migration` | `SELECT` |
| sequences `river_*` (the `bigserial` ids) | `USAGE` |

### Slice 3b decisions and open points

- **Every `helm.authority.*` type is a widening, except the one that says it
  narrows.** Admission escalates every `helm.authority.*` effect, whatever its
  risk row or the mandate's `approval_required`, and `Approve` requires step-up
  for it. A narrowing type must be listed as one explicitly: contract 5 lists
  `helm.authority.narrow.v1`, which is `ADMITTED` without approval (see
  [Gateway authority provisioning](gateway-provisioning-api.md)). The
  conformance table's GW-020 asserts the rule for the widening types.
- **Lift is bound to the stop.** The proto binds a lift token to the stop,
  not to the attempt. The lift attempt is approved with a decide token bound
  to it, like any other attempt.
- **No lift can be applied yet.** A `helm.authority.lift` attempt reaches
  `ADMITTED` when a distinct approver approves it with a step-up proof, but
  there is no dispatch-time applier for it (`Dispatch` answers
  `failed_precondition`: no adapter). A gateway stop lasts until it expires,
  or until the authority-row store lifts it with a distinct approver. The
  applier is a separate change.
- **A last try whose own hand-off transaction fails** (the database is
  unreachable) is discarded by River. The attempt stays `UNKNOWN`, with its
  hold, for `Observe`.

## ListAttempts

`ListAttempts` (token scope `helm.gateway.read`) lists the attempts of the
token's tenant and workspace, ordered by (`updated_at`, `attempt_id`), oldest
change first. It exists because SDK agents propose directly, so the Console
must find `ESCALATED` attempts the Control Plane never created, and because
the Control Plane syncs its projection incrementally.

- **Filters**, all optional, all narrowing: `states` (any of), `commitment_id`
  or `case_id`, `requester_principal_id`, `effect_type`, `episode_id` (the
  episode an attempt was proposed in; see "Episode attempts"), and
  `updated_after` (exclusive). A filter cannot reach another tenant's or
  workspace's attempts.
- **Paging.** `page_size` is 1 to 200 (0 means 50); a response with a
  `next_page_token` has more, and the same request with that token continues
  after the last attempt returned. A token belongs to one set of filters; one
  from another set, or a malformed one, is `invalid_argument`.
- **Cursor.** `updated_at` is the database time at which the transaction that
  last changed the attempt began. Transactions commit out of that order, so an
  attempt can first appear with an `updated_at` earlier than one already
  listed, and the last `updated_at` a reader saw is not a safe place to resume.
  The first page captures `settled_before`: a time later than the longest a gateway
  transaction may run (every one is bounded), before the moment the page was
  read. Its continuation tokens preserve that same watermark on every later
  page, even when traversal spans the safety margin. An attempt whose
  `updated_at` is before `settled_before` is final in
  the listing: none appears later with an earlier position. A reader that has
  read to the end asks again with `updated_after` set to the `settled_before`
  of its last page, never misses a change, and sees the changes after that
  instant again, so it applies an attempt idempotently. An attempt that changes
  again is listed again at its new position.
- **Content.** Each entry is the attempt `GetAttempt` returns. The arguments
  stay behind `GetAttemptContent`.
- **Status.** Served: `helm-gateway` answers `ListAttempts` under a
  `helm.gateway.read` token.

## Episode attempts

A worker runs in one bounded episode (HELM-752 K7), and its token carries the
episode as a `helm_episode` claim: `episode_id`, `work_item_id` and
`organization_version_id`. An attempt proposed with such a token records them:

- **`EffectAttempt.episode`** (`EpisodeRef`: `episode_id`, `work_item_id`,
  `organization_version_id`) is set for an attempt proposed with an episode
  token and unset for every other attempt. The gateway copies it from the
  verified claim alone. No request message carries an episode, except the list
  filter, which says which attempts to list and never what an attempt records.
- **`work_item_id` is the attempt's `case_id`.** For a token with an episode
  claim the work reference is the claim's work item: a request that names a
  commitment, or a different case, is refused, and a request that names none
  takes the claim's.
- **`ListAttemptsRequest.episode_id`** keeps the attempts of one episode. Like
  every filter it only narrows.
- **Read isolation.** A token with the Control Plane's service principal and
  `helm.gateway.read` reads every attempt of its own tenant and workspace. A
  token that carries an episode claim reads only the attempts of its own
  episode that its own principal proposed, through `GetAttempt`,
  `GetAttemptContent`, `ListAttempts` and the stored response of a model call:
  any other attempt of the same tenant, another episode's, another seat's under
  the same episode id and the Control Plane's, is `not_found` for it, the same
  answer as an attempt that does not exist. `Dispatch`, `Observe` and `Cancel`
  find only those attempts too.
- **Request digest.** The episode claim is part of the idempotency digest of a
  request proposed under one, so the same key and request from another episode
  is an `IDEMPOTENCY_CONFLICT`. A request with no claim digests as it always
  did.
- **Status.** Served: `helm-gateway` records the episode (schema version 8:
  `episode_id` and `organization_version_id` on the attempt row, with the work
  item as `case_id`), holds episode tokens to it, and honors the `episode_id`
  filter. The worker's MCP endpoint ([gateway-mcp.md](gateway-mcp.md)) and the
  model endpoints both propose under it.

## Step-up proof

An approval of an effect that needs step-up (risk class high or irreversible,
and every `helm.authority.*` widening) carries `ApproveRequest.step_up_proof`.
The proof is the Control Plane issuer's attestation that it verified the
approver's WebAuthn assertion, whose challenge is the approval digest. The
gateway does not hold the approver's credential and does not verify WebAuthn
itself: it verifies the issuer's signature, as it does for every token, and the
binding below. That is a trust choice, recorded here: a compromised issuer can
mint a proof, as it can mint a decide token. Independent verification needs a
credential registry in the gateway and is not part of this contract.

The proof is a compact token verified like any other gateway token (one
audience, the issuer's keys, the configured actor, the certificate binding when
required), with these rules:

| Claim | Rule |
|---|---|
| `scope` | `helm.gateway.stepup`, and only that. |
| `sub`, `tenant_id` | the decide token's own: the same approver, the same tenant. |
| `authorization_details` | exactly one entry `{"type": "helm_step_up", "attempt_id": "<attempt_id>", "approval_digest": "<lower-case hex>", "method": "webauthn", "user_verified": true}`, naming the attempt approved and the digest the approver was shown, and stating that the issuer saw the authenticator's user-verification flag set. |
| `iat`, `exp` | fresh: `exp` is at most 300 seconds after `iat`, and the call is between them (within the usual clock skew). |
| `jti` | single-use: recorded in `authority_token_replay` in the approval's own transaction, like the decide token's. |

`Approve` without a proof for an effect that needs one, with an invalid one, or
with one bound to another attempt or digest, is `permission_denied`
(`STEP_UP_REQUIRED`), the attempt stays `ESCALATED`, and no token is used up.
The approval record keeps the proof exactly as received, with its `jti` and
method, so that it can be verified again against the issuer's keys. A `Reject`
needs no proof. Status: served. The server verifies the proof before the
approval's transaction and treats one that does not verify, or is longer than
8192 bytes, as none; admission uses its `jti` up in that transaction, after the
decide token's, when the effect needs step-up, keeps the proof on the approval
record, and ignores a proof for an effect that needs none.

## Conformance table

[`protocols/conformance/gateway/v1`](../../protocols/conformance/gateway/v1/README.md)
turns this note's rules into machine-readable scenarios. The real
`helm-gateway` must pass them, and so must every fake gateway, such as the
Control Plane's. Each scenario has:

- fixtures: principals, mandates as data, and the fake adapter's behaviour;
- steps: RPCs with abstract token claims;
- the attempt state or Connect error each step must produce.

`core/pkg/gateway/conformance` runs the table against the real gateway on
PostgreSQL. `TestPostgresGatewayConformanceTable` is a Postgres proof, so the
table cannot drift from the gateway. Fakes pin the table by commit and by the
SHA-256 of its `conformance-pack.json`.

New scenarios are additive. A change to an expectation changes a rule, so
it changes the section of this note that the scenario cites, in the same pull
request.

## Generated code

- **Go only.** `make codegen-go` generates `helm.gateway.v1` with
  `protoc-gen-go` and `protoc-gen-connect-go` (v1.21.0, pinned in CI). The
  `package_suffix` option is empty, so the Connect stubs sit in `gatewayv1`
  beside the messages. The other packages keep `protoc-gen-go-grpc`. `sdk/go`
  gains `connectrpc.com/connect`.
- **No Python, TypeScript, Java or Rust binding.** §11.3 generates the TS and
  Python clients in their own slice, and Java and Rust are being retired
  (HELM-756). A `grpc-js` TypeScript binding published now would freeze a
  client shape that slice has not chosen. The `Makefile` names the split:
  `CONNECT_PROTO_FILES` and `GRPC_PROTO_FILES`.
- **The server imports the bindings.** `core` requires `sdk/go` at a pinned
  version and `connectrpc.com/connect`. `core/cmd/helm-gateway` is a deadcode
  root (`scripts/ci/deadcode-roots.txt`).

## What slice 1 does not do

- No server, handler registration or route. The route registry tests (#1009)
  therefore see nothing new.
- No reason-code registration. Pending codes are registered by the slices that
  emit them.
- No `controls.yaml` entry. The contract makes no enforcement claim (R1).
- No River jobs, no expiry of escalations, no settlement code.
