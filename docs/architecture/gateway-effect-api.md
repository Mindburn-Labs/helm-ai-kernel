# Gateway effect API (contract 1)

<!-- quantum_posture: this note describes a wire contract that carries SHA-256
digests as opaque values and no signatures or keys. It adds no cryptographic
control and makes no post-quantum claim; token verification is ADR-0005's. -->

Status: draft wire contract, HELM-751 slice 1, 2026-09-25. This revision
includes WS-B's review of 2026-09-25 (PR #1015), which the coordinator
accepted. Under target architecture rev 3.4 §1 the contract is *Specified*: it
is versioned, and no server stands behind it. Nothing in this repository
serves these RPCs yet.

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
`Cancel` among the mutating entry points. This contract adds both at WS-B's
request, and rev 3.4 should record them. `Cancel` fails once dispatch has
started, because a dispatched call cannot be retracted.

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
| `ProposeRequest.mandate_id` | ADR-0001 `Request.Mandate`. A selector the gateway checks against the token's principal and the delegation chain; never a grant (R3). |
| `ProposeRequest.work_ref` (`commitment_id` or `case_id`) | Rev 3.4 §3, schema `work_ref`. Optional for `helm.authority.*` until contract 5. |
| `EffectDescriptor` (`effect_type`, `target`, `arguments`) | §4.1 item 1 effect descriptor. The log carries digests only (R13). |
| `ResourceAmount` (`quote`) | ADR-0001 `Request.Amounts`. Integer; money is minor units of an ISO 4217 currency (§3). Ignored for model calls, which the gateway prices itself. |
| `DistinctValue` | ADR-0001 `Request.Distinct`, rule class U. |
| `ProposeRequest.approval_expires_at` | WS-B review item 4. Optional, clamped to the mandate's approval window; when it is unset, the mandate's approval window applies. |
| `EffectAttempt.state` (`EffectAttemptState`) | §4.3, schema `effect_attempts.state`. See below. |
| `EffectAttempt.risk_class` | Effect-type control row. Never read from the request. |
| `EffectAttempt.reason_code` | ADR-0001 §6, registry strings. |
| `EffectAttempt.workspace_id` | The proposer's token (R9, ADR-0005). Output only. |
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
6. `expires_at`: its seconds as a big-endian int64, then its nanos as a
   big-endian int32.

`u64(n)` is an 8-byte big-endian unsigned integer, and `field(b)` is
`u64(len(b)) || b`. The attempt ID binds the effect type, mandate and
requester on the server, so the digest follows §10.1's list of fields and
adds nothing.

Test vector:

| Input | Value |
|---|---|
| `attempt_id` | `0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d` |
| target | `github.com/Mindburn-Labs/example/pull/42` |
| `target_digest` | `88075297ac48e169fc8304871a612a786d58f461cbd377e2a074c6a2b9070f64` |
| arguments | `{"merge_method":"squash"}` |
| `argument_digest` | `a251ae0221cb7e5b1c1fb10c05a07c4c17b6f776d117cb73ba78d200afd3ac0f` |
| quote | `count` = 1, `USD` = 2500 (sorted: `USD`, `count`) |
| `expires_at` | `2026-09-26T12:00:00Z` (seconds 1790424000, nanos 0) |
| **approval digest** | `cb2cd8caa08ee2544750dd59644a0d2f3bb16a729be108520055c2f72c5f53d7` |

The vector was computed by a Python implementation and matches the Go
reference in `TestApprovalDigestVector`. That test also fails if this note
stops carrying the value.

For attempts the Control Plane proposed, it already holds the argument bytes.
For attempts proposed by others, the Console reads them with
`GetAttemptContent`. In both cases the client checks
`sha256(arguments) == argument_digest` before it renders them.

### Reason codes

Reason codes are strings from `reason-codes-v1.json`. The proto marks each one
it names:

- `[reason_code: X]`: registered today. Used: `EMERGENCY_STOP_FENCED`,
  `BUDGET_EXCEEDED`, `APPROVAL_REQUIRED`, `APPROVAL_TIMEOUT`, `SCHEMA_VIOLATION`.
- `[reason_code_pending: X]`: registered by the slice that first emits it,
  because the registry gate rejects codes that nothing emits (ADR-0001 §6).
  These are ADR-0001 §6's list, plus two that this contract adds:
  `IDEMPOTENCY_CONFLICT` for the `already_exists` error, and
  `STEP_UP_REQUIRED` for approvals that fail closed without step-up.

The contract test fails if a `reason_code` is not registered, and if a
`reason_code_pending` has been registered, so the markers stay true as codes
land.

## Token scopes

Tenant, workspace and principal come only from the token (R9, ADR-0005). No
request message has a tenant, workspace or caller-principal field, and the
contract test enforces that. ADR-0005 allows one scope per token. An RPC may
accept tokens of more than one scope; `Cancel` does.

WS-B (Control Plane) proposed the scopes on 2026-09-25: one per authority
class, not one per RPC and not one blanket scope. Mapped onto the real RPC
names:

| Scope | RPCs | Minted for |
|---|---|---|
| `helm.gateway.propose` | `Propose`; `Cancel` of one's own attempt | the run or agent principal on the worker path |
| `helm.gateway.decide` | `Approve`, `Reject` | a human principal only, from an interactive session, never a worker |
| `helm.gateway.read` | `GetAttempt` (§4.2's `Get`), `GetAttemptContent`, `ListAttempts` in s2, `result_ref` blobs | any principal with workspace read |
| `helm.gateway.stop` | `Stop`, `Lift`; `Cancel` of another principal's attempt | human operators and admins only |
| `helm.gateway.execute` | the model gateway's inference endpoint (§8). `Dispatch` and `Observe` have no external caller and would take it if they ever get one | a workload principal, never a human |

WS-B's table lists "Get, GetAttempt" for `helm.gateway.read`. They are one RPC:
§4.2's `Get` is `GetAttempt`.

WS-B also proposed that a `helm.gateway.decide` token be single-use per
attempt: the kernel requires the `txn` claim to equal the attempt ID being
decided and rejects a reused `jti`. The same rule applies to `Lift`. This is
recorded as a proposal for the implementing slice (HELM-755 S4 / HELM-751),
not as a wire change; the proto comments document the `txn` binding. For
`Lift` this note maps `txn` to `stop_id`, since no attempt exists yet when
`Lift` is called.

### Model calls

A model call is admitted like any other effect, then dispatched differently
(§8, HELM-752):

1. `Propose` admits it. The gateway prices the quote from the route and the
   clamped `max_tokens`, and ignores the caller's `quote`.
2. The caller presents `permit_id` to the model gateway's inference endpoint
   with a `helm.gateway.execute` token.
3. The gateway injects the provider key (R8), claims the permit, streams the
   response and settles it (ADR-0003).

The dispatch of a model call is therefore caller-initiated through that
endpoint, not through the `Dispatch` RPC. HELM-752 names the model-call effect
type and the endpoint.

### Where the proposal conflicts with rev 3.4 or the ADRs

These need a decision before the implementing slice, not a silent choice:

1. **`Dispatch` and `Observe` with no external caller.** Rev 3.4 §4.2 says
   "The product backend, MCP exposure and SDKs all call them", and §2 has the
   product backend call the gateway's operations over mTLS.
   - Keeping them internal means the gateway dispatches non-model effects on
     its own once an attempt is `ADMITTED`. The product no longer chooses when
     an admitted effect happens; it can only `Cancel` before dispatch.
   - Model calls are the exception: they are dispatched by the caller through
     the inference endpoint.

   This is a §4.2 change. The wire keeps both RPCs, since they are §4.2
   operations.
2. **Rejecting a reused `jti`.** ADR-0005 §2 and §6 say the kernel keeps no
   replay cache and that individual revocation relies on the short TTL.
   - A single-use rule needs an ADR-0005 amendment, and under R5 the used-`jti`
     set must be a Postgres row, not process memory.
   - For `Approve` and `Reject` it adds little: the `txn` binding limits the
     token to one attempt, and a repeated decision on that attempt is already a
     no-op (approvals are unique per attempt and return `existing = true`).
   - For `Lift` it does add something: without it, a replayed token with a new
     idempotency key creates a second lift attempt, which still needs its own
     approval.
3. **`txn` equal to the attempt ID.** ADR-0005 §2 defines `txn` as a unique
   transaction ID that is logged, not an idempotency key. Phase 2 caches tokens
   per (principal, tenant, workspace, scope) for up to 300 s. A decide token
   bound to one attempt cannot be cached, so each decision costs one signing
   hop at the issuer. That is acceptable at human approval rates, but it is a
   new token profile that ADR-0005 has to describe.
4. **`helm.gateway.propose` only for run or agent principals.** Rev 3.4 does
   not restrict who proposes. Authority changes are proposed from the
   organization module (§12.4, `helm.authority.change`), and humans start
   effects from the Console. If those go through `Propose`, the scope must also
   be minted for human sessions.
5. **Human-only approvers.** This narrows rev 3.4 §4.2 and ADR-0001 I6, which
   require a verified principal distinct from the requester. It is compatible.
   The gateway must still check the approver's `kind` in its own principals
   table rather than trust whoever minted the token.
6. **`Cancel` and the `ESCALATED → CANCELLED` edge** extend §4.2 and §4.3 (see
   Operations).

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
- **Unused handlers are expected.** Nothing in this repository calls the
  generated handler constructors, which is normal for a public API surface.
  The deadcode gate reaches only the `core` module from
  `core/cmd/helm-ai-kernel`, and `sdk/go` is a separate module, so neither
  `deadcode-roots.txt` nor the allowlist changes.

## What slice 1 does not do

- No server, handler registration or route. The route registry tests (#1009)
  therefore see nothing new.
- No reason-code registration. Pending codes are registered by the slices that
  emit them.
- No `controls.yaml` entry. The contract makes no enforcement claim (R1).
- No River jobs, no expiry of escalations, no settlement code.
