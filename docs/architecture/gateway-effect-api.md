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
server (slice 2)"); `Dispatch`, `Observe`, `Stop` and `Lift` answer
`unimplemented`.

- IDL: [`protocols/proto/helm/gateway/v1/gateway.proto`](../../protocols/proto/helm/gateway/v1/gateway.proto),
  package `helm.gateway.v1`, service `EffectGatewayService`.
- Go bindings: `sdk/go/gen/helm/gateway/v1`. `gateway.pb.go` holds the
  messages; `gateway.connect.go`, from `protoc-gen-connect-go`, sits in the
  same package.
- Contract tests: `sdk/go/gen/helm/gateway/v1/gateway_contract_test.go`.
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

- `ApproveRequest` field 4: the §10.1 step-up assertion.
- `Observation` fields 7–15: typed, bounded result payloads, such as a pull
  request URL and merge commit for R1's outcome check.

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
typed result. Fields 9–15 stay held for later result types
(`TestHeldFieldNumbersStayFree`). Clients read these fields, never the
provider's raw bytes.

The HELM-789 walking skeleton needs two GitHub effects. Their argument schemas
are closed JSON Schemas with known-good and known-bad fixtures, checked by the
`json-schemas` gate:

| Effect type | Arguments | Risk | Result |
|---|---|---|---|
| `github.branch.create_from_changes` | `protocols/json-schemas/effects/github/branch_create_from_changes.v1.json` | medium (admitted under a mandate) | `github_branch` (field 8) |
| `github.pull_request.create_draft` | `protocols/json-schemas/effects/github/pull_request_create_draft.v1.json` | high (escalated) | `github_pull_request` (field 7) |

Rules for both:

- **Target.** The target is `github.com/{owner}/{repo}`, with owner matching
  `^[A-Za-z0-9-]{1,39}$` and repo matching `^[A-Za-z0-9._-]{1,100}$`. It has
  no `#`, `?`, extra or trailing `/`. The repository comes only from the
  target; the arguments never name one (audit 09-02).
- **Bytes.** The arguments are exact UTF-8 bytes, at most 64 KiB. The gateway
  refuses duplicate keys, unknown fields and a missing required field before
  admission, and digests the bytes as sent. The Console shows the same bytes
  through `GetAttemptContent`.

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
- it is `github.branch.create_from_changes` in OBSERVED(SUCCEEDED);
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

`READBACK_MISMATCH` and `PRECONDITION_FAILED` are registered by the slice that
first emits them (HELM-751 s3 / HELM-753 adapter).

### Reason codes

Reason codes are strings from `reason-codes-v1.json`. The proto marks each one
it names:

- `[reason_code: X]`: registered today. Used: `EMERGENCY_STOP_FENCED`,
  `BUDGET_EXCEEDED`, `APPROVAL_REQUIRED`, `APPROVAL_TIMEOUT`, `SCHEMA_VIOLATION`,
  and, registered by slice 2 because its admission emits them,
  `PRINCIPAL_INACTIVE`, `MANDATE_INACTIVE`, `MANDATE_OUTSIDE_VALIDITY`,
  `EFFECT_OUT_OF_SCOPE`, `PER_CALL_LIMIT`, `ARITHMETIC_OVERFLOW` and
  `IDEMPOTENCY_CONFLICT`.
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
| `helm.gateway.read` | `GetAttempt` (§4.2's `Get`), `GetAttemptContent`, `ListAttempts` in s2, `result_ref` blobs | any principal with workspace read | — |
| `helm.gateway.stop` | `Stop`, `Lift`; `Cancel` of another principal's attempt | human operators and admins only | single-use; a `Lift` token is bound by `authorization_details` |
| `helm.gateway.execute` | `Dispatch`, `Observe`, and the model gateway's inference endpoint (§8) | workload principals only: the Control Plane backend and SDK agent runtimes. Never a human session, and never a worker's propose token | — |

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

`Stop` tokens need no binding. A stop narrows authority, and a stop token is
single-use anyway.

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
   `STEP_UP_REQUIRED` until the assertion field, held at `ApproveRequest`
   field 4, exists.
   - Consequence: the passkey slice must land before R1's first high-risk
     approval (a GitHub merge).
   - The Control Plane already has WebAuthn, so WS-B can build its side in
     parallel once the field shape is fixed.
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
   64 KiB of UTF-8 with no duplicate key. The walking-skeleton effect types
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
   `failed_precondition` with `PRECONDITION_FAILED`, and no attempt.
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
is refused. Rows are purged once `exp` plus 30 s has passed, and process
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
  step-up, which fails closed (`STEP_UP_REQUIRED`). A medium effect that a
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

Errors carry one `helm.errors.v1.ErrorDetail`. `invalid_argument` carries
`SCHEMA_VIOLATION`; `permission_denied` for a scope, an actor or a human's
direct Propose carries `INSUFFICIENT_PRIVILEGE`, and for a tenant with no
authority rows `TENANT_ISOLATION`; `unauthenticated` and `not_found` carry no
code; a gateway failure is `unavailable` with `retryable` set.

### Slice 2 decisions and open points

- **`ListAttempts` is not served.** The service comment reserves the name and
  this note gives its shape, but the proto defines no RPC or messages for it.
  Adding it is a contract change for a later slice.
- **The approval window is gateway configuration.** The proto clamps
  `approval_expires_at` to "the mandate's approval window", but mandates have
  no such term yet; `HELM_GATEWAY_APPROVAL_WINDOW` stands in for it.
- **A mandate may raise a risk class.** `EffectAttempt.risk_class` is the
  effect-type row's class raised by the chain's `risk_classes`, never lowered
  and never taken from the request.
- **The draft pull request's branch attempt** is accepted in
  `OBSERVED(SUCCEEDED)` or `RECONCILED(SUCCEEDED)`. Until slice 3 writes
  observations, only a fixture row can satisfy it.
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
