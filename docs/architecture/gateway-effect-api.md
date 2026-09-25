# Gateway effect API (contract 1)

<!-- quantum_posture: this note describes a wire contract that carries SHA-256
digests as opaque values and no signatures or keys. It adds no cryptographic
control and makes no post-quantum claim; token verification is ADR-0005's. -->

Status: draft wire contract, HELM-751 slice 1, 2026-09-25. It is *Specified*
in the sense of target architecture rev 3.4 §1: a versioned contract, with no
server behind it. Nothing in this repository serves these RPCs yet.

- IDL: [`protocols/proto/helm/gateway/v1/gateway.proto`](../../protocols/proto/helm/gateway/v1/gateway.proto),
  package `helm.gateway.v1`, service `EffectGatewayService`.
- Go bindings: `sdk/go/gen/helm/gateway/v1` (`gateway.pb.go`, and
  `gateway.connect.go` from `protoc-gen-connect-go`, in the same package).
- Contract tests: `sdk/go/gen/helm/gateway/v1/gateway_contract_test.go`.
- Binding references: rev 3.4 §4.1–§4.6, §8, §10.1, §11 and the §12.3
  contract list; ADR-0001 (admission), ADR-0003 (settlement), ADR-0005 (tenant
  from the token), all under
  `output/helm-rebuild-strategy-2026-09-23/` in the workspace.

## Operations

Rev 3.4 §4.2 names six operations. The service has eight RPCs because two of
the six are pairs.

| §4.2 operation | RPC | Idempotency | ADR-0001 reference |
|---|---|---|---|
| `Propose` | `Propose` | `(tenant, idempotency_key)` plus request digest | `admission.Propose` |
| `Approve` / `Reject` | `Approve`, `Reject` | on the attempt; one approval per attempt | `admission.Approve` |
| `Dispatch` | `Dispatch` | on the attempt; the permit is consumed once | `admission.ClaimDispatch` |
| `Observe` | `Observe` | on the attempt; no transition outside `DISPATCHED`/`UNKNOWN` | §4.1 item 4 (no reference code) |
| `Get` | `GetAttempt` (`NO_SIDE_EFFECTS`, so Connect allows GET) | read | — |
| `Stop` / `Lift` | `Stop`, `Lift` | `(tenant, idempotency_key)` | `admission.Stop`, `admission.Lift` |

`Lift` widens authority, so it does not lift anything by itself. It creates a
`helm.authority.lift` effect attempt, which is approved with `Approve` and
applied by `Dispatch` like any other attempt (§4.1 item 7, ADR-0001 §1). Its
payload belongs to contract 5.

Two rules apply everywhere:

- **Decisions are states, not errors.** `DENIED`, `ESCALATED`, `CANCELLED` and
  `UNKNOWN` come back as the attempt's state in a successful response. A Connect
  error means the gateway could not evaluate the request. Each error carries one
  `helm.errors.v1.ErrorDetail` (#992). The service comment lists the codes.
- **A duplicate never dispatches twice (R6).** A repeated `Propose` with the
  same key and content returns the stored attempt in whatever state it is in,
  pending or `UNKNOWN` included, with `existing = true`. The same key with
  different content is `already_exists`. `Dispatch` on an attempt past
  `ADMITTED` returns it unchanged.

## Messages and where they come from

| Message / field | Source |
|---|---|
| `ProposeRequest.idempotency_key`, request digest | R6, ADR-0001 §1 step 1. The digest covers every field except the key, plus the authenticated principal. |
| `ProposeRequest.mandate_id` | ADR-0001 `Request.Mandate`. A selector the gateway checks against the token's principal and the delegation chain; never a grant (R3). |
| `ProposeRequest.work_ref` (`commitment_id` or `case_id`) | Rev 3.4 §3, schema `work_ref`. |
| `EffectDescriptor` (`effect_type`, `target`, `arguments`) | §4.1 item 1 effect descriptor. The log carries digests only (R13). |
| `ResourceAmount` (`quote`) | ADR-0001 `Request.Amounts`. Integer; money is minor units of an ISO 4217 currency (§3). |
| `DistinctValue` | ADR-0001 `Request.Distinct`, rule class U. |
| `EffectAttempt.state` (`EffectAttemptState`) | §4.3, schema `effect_attempts.state`. See below. |
| `EffectAttempt.risk_class` | Effect-type control row. Never read from the request. |
| `EffectAttempt.reason_code` | ADR-0001 §6, registry strings. |
| `PendingApproval.approval_digest`, `ApproveRequest.approval_digest` | §10.1 approval digest. An approval binds to the digest the approver saw. |
| `Approval` | Schema `authority.approvals`, unique per attempt (I6). |
| `Permit`, `AuthorityVersion` | Schema `authority.permits` (`authority_versions`, `consumed_at`, `claim_id`, `void_reason`). These are the fields the dispatch claim compares. |
| `Exposure`, `ExposureKind` | ADR-0003, `authority.exposures`: one per attempt and counter bucket. |
| `ModelCallSettlement`, `SettlementState` | ADR-0003, `authority.model_calls`; §8's four quantities in integer micro-units. |
| `Observation` | §3 (source, freshness, trust class) and §4.1 item 4. |
| `Stop`, `StopScopeKind` | Schema `authority.stops` (`scope_kind`, `scope_key`, `expires_at`, `lifted_at`). |

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
- `CANCELLED` comes from a refused dispatch claim (stop, any authority version
  change, expired permit). Its reservation is released in the same transaction.

### Reason codes

Reason codes are strings from `reason-codes-v1.json`. The proto marks each one
it names:

- `[reason_code: X]`: registered today. Used: `EMERGENCY_STOP_FENCED`,
  `BUDGET_EXCEEDED`, `APPROVAL_REQUIRED`, `APPROVAL_TIMEOUT`, `SCHEMA_VIOLATION`.
- `[reason_code_pending: X]`: registered by the slice that first emits it,
  because the registry gate rejects codes that nothing emits (ADR-0001 §6).
  These are ADR-0001 §6's list, plus `IDEMPOTENCY_CONFLICT`, which this
  contract adds for the `already_exists` error.

The contract test fails if a `reason_code` is not registered, and if a
`reason_code_pending` has been registered, so the markers stay true as codes
land.

## Token scopes

Tenant and principal come only from the token (R9, ADR-0005). No request
message has a tenant, caller-principal or workspace field, and the contract
test enforces that. ADR-0005 allows one scope per token.

WS-B (Control Plane) proposed the scopes on 2026-09-25: one per authority
class, not one per RPC and not one blanket scope. Mapped onto the real RPC
names:

| Scope | RPCs | Minted for |
|---|---|---|
| `helm.gateway.propose` | `Propose` | the run or agent principal on the worker path |
| `helm.gateway.decide` | `Approve`, `Reject` | a human principal only, from an interactive session, never a worker |
| `helm.gateway.read` | `GetAttempt` (§4.2's `Get`; a list RPC too, when one exists) | any principal with workspace read |
| `helm.gateway.stop` | `Stop`, `Lift` | human operators and admins only |
| none externally | `Dispatch`, `Observe` | internal to the gateway. `helm.gateway.execute` is reserved for a workload principal, never a human, if an external caller is ever needed |

WS-B's table lists "Get, GetAttempt" for `helm.gateway.read`. They are one RPC:
§4.2's `Get` is `GetAttempt`.

WS-B also proposed that a `helm.gateway.decide` token be single-use per
attempt: the kernel requires the `txn` claim to equal the attempt ID being
decided and rejects a reused `jti`, and the same rule applies to `Lift`. This is
recorded as a proposal for the implementing slice (HELM-755 S4 / HELM-751). It
is not wire-level; the proto comments document the `txn` binding. For `Lift`
this note maps `txn` to `stop_id`, since no attempt exists yet when `Lift` is
called.

### Where the proposal conflicts with rev 3.4 or the ADRs

These need a decision before the implementing slice, not a silent choice:

1. **`Dispatch` and `Observe` with no external caller.** Rev 3.4 §4.2 says
   "The product backend, MCP exposure and SDKs all call them", and §2 has the
   product backend call the gateway's six operations over mTLS. Keeping them
   internal means the gateway dispatches on its own once an attempt is
   `ADMITTED`, so the product no longer chooses when an admitted effect
   happens. That is a §4.2 change. The wire keeps both RPCs, since they are
   §4.2 operations, and reserves `helm.gateway.execute`.
2. **Rejecting a reused `jti`.** ADR-0005 §2 and §6 say the kernel keeps no
   replay cache and that individual revocation relies on the short TTL. A
   single-use rule needs an ADR-0005 amendment, and under R5 the used-`jti` set
   must be a Postgres row, not process memory. For `Approve` and `Reject` it
   adds little: the `txn` binding limits the token to one attempt, and a
   repeated decision on that attempt is already a no-op (approvals are unique
   per attempt and return `existing = true`). For `Lift` it does add
   something: without it, a replayed token with a new idempotency key creates
   a second lift attempt, which still needs its own approval.
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

## Open questions for WS-B

1. **Listing.** §11.2 has "Effects: list" and "Decisions: list". s1 has only
   `GetAttempt`. A list RPC (for example `ESCALATED` attempts for the
   Decisions inbox) is a follow-up. Filters and pagination are open.
2. **Caller-initiated cancel.** §4.2 has no operation that cancels an
   `ADMITTED` attempt, for example when its commitment is cancelled. ADR-0003's
   reference has `ReleaseBeforeDispatch`. The choices are a `Cancel` RPC, which
   is narrowing and needs no approval, or permit expiry alone.
3. **Workspace.** ADR-0005 tokens carry `workspace_id`, but ADR-0001 attempts
   are tenant-scoped. Should attempts and reads be workspace-scoped?
4. **Audience and transport.** The gateway is a separate process (§2). Does it
   take its own `aud` (for example `helm-gateway:<deployment id>`), and is
   `cnf` required once mTLS exists?
5. **What the approver sees.** The approval digest binds the approval to the
   target and argument digests, but a human needs the arguments themselves.
   How the approval page reads authenticated argument content (§5.6 content
   blobs, §10.1 minimal approval page) is open.
6. **Step-up.** §10.1 requires a passkey assertion for high-risk approvals,
   authority widening and stop lifts. The assertion field arrives with that
   slice as an additive field on `ApproveRequest` and `LiftRequest`. Until then
   the implementing slice must decide whether those approvals fail closed.
7. **Correlation for authority changes.** A `helm.authority.lift` attempt has
   no commitment or case, while the reference schema requires `work_ref`.
   Contract 5 decides.
8. **Units.** `ResourceAmount.unit` names a unit declared by the tenant's
   limits. The unit vocabulary belongs to the limit templates, which §17.3
   still lists as open.
9. **Outcomes to Zone B.** Until contract 6 (effect and observation events)
   exists, the product learns outcomes by reading the attempt.

## Generated code

- Go only. `make codegen-go` runs `protoc-gen-go` plus `protoc-gen-connect-go`
  (v1.21.0, pinned in CI) for `helm.gateway.v1`, with `package_suffix` empty
  so the Connect stubs sit in `gatewayv1` beside the messages. The other
  packages keep `protoc-gen-go-grpc`. `sdk/go` gains `connectrpc.com/connect`.
- No Python, TypeScript, Java or Rust binding. §11.3 generates the TS and
  Python clients in their own slice, and Java and Rust are being retired
  (HELM-756). A `grpc-js` TypeScript binding published now would freeze a
  client shape that slice has not chosen. The `Makefile` names the split
  (`CONNECT_PROTO_FILES`, `GRPC_PROTO_FILES`).
- The generated handler constructors are unused in this repository, which is
  expected for a public API surface. The deadcode gate reaches only the `core`
  module from `core/cmd/helm-ai-kernel`, and `sdk/go` is a separate module, so
  neither `deadcode-roots.txt` nor the allowlist changes.

## What slice 1 does not do

- No server, handler registration or route. The route registry tests (#1009)
  therefore see nothing new.
- No reason-code registration. Pending codes are registered by the slices that
  emit them.
- No `controls.yaml` entry. The contract makes no enforcement claim (R1).
- No River jobs, no expiry of escalations, no settlement code.
