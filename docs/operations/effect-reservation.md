# Durable connector effect reservation

Status: source-owned implementation and real-PostgreSQL proof; internal,
pre-production, and not yet enabled by a deployed Data Plane configuration.

This boundary joins one immutable Kernel-signed
`approval-dispatch-admission.v1` to the current signed connector release head
and persists connector-start truth before a governed write can reach an
external network sink. It orders new work against tenant/workspace FENCE and
exact-release revocation. It is not a claim that HELM Cloud or Emergency Stop
is generally available.

## Authority chain

The approval-owned `connector_authority` now binds all of the following before
the approval hold starts:

- tenant, workspace, pack, effect, policy, and lifecycle action;
- exact `connector_action`, such as `github.create_issue`;
- connector ID/version, binary hash, signature reference and hash, signer,
  sandbox profile, drift policy, and certification evidence;
- exact release scope, source authority ID, JCS-safe registry revision, and
  source authority hash.

The same self-hashed object is carried unchanged through challenge, verified
quorum, grant, consumption, and dispatch admission. A local agent cannot
select the connector, connector action, release scope, or release revision at
dispatch time.

## Transaction order

`EffectReservationAdmitter.Admit` owns the effect-admission transaction. The
order is fixed:

1. set tenant/workspace RLS context from the verified workload identity;
2. acquire the same tenant/workspace advisory transaction lock as FENCE;
3. return an exact committed replay if this admission already has a reservation;
4. reject an active FENCE;
5. reload and verify the exact persisted Kernel-signed dispatch admission;
6. acquire the shared exact-release lock used by the connector authority
   registry, load its current head, and evaluate certification against the
   PostgreSQL clock;
7. compare the current head to every release field signed into the approval
   chain;
8. append `ADMITTED` sequence 1 and commit;
9. only after commit may a lifecycle-aware connector run local prechecks and
   approach its network sink.

The source-authority writer takes the exclusive form of the same exact-release
lock. FENCE uses the same scope lock. `ADMITTED` records remain visible for
recovery, but admission alone is not a durable right to cross the network seam:
`MarkStarted` reacquires the scope lock, rejects the current FENCE, acquires the
shared exact-release lock, reloads the current certified head using the
PostgreSQL clock, and requires an exact match to the release signed into the
approval chain before appending `STARTED`. Therefore the two legal orderings
are explicit: `STARTED` commits first and the effect is active work requiring
reconciliation, or FENCE/revocation commits first and start is denied with no
network request. No connector callback or network request runs under a
database lock.

## Append-only lifecycle

`approval_effect_reservation_events` is a forced-RLS, append-only event stream
keyed by tenant, workspace, signed admission ID, and sequence. Runtime roles
need only `SELECT, INSERT`; they need no `UPDATE`, `DELETE`, DDL, superuser, or
`BYPASSRLS`. Database triggers pin `search_path` to `pg_catalog`, dynamically
schema-qualify the trigger relation, verify JSON/shadow parity, acquire the
scope lock, enforce exact succession, preserve structural JSON equality plus the
exact signed authority identities and signatures, and reject mutation or invalid
transitions. PostgreSQL `jsonb` storage does not claim byte-preserving JSON
serialization.

Once a reservation is `STARTED`, `connector_execution_ref`,
`proof_session_ref`, and `intent_ref` remain exact across an `UNCERTAIN`
transition. `effect_ref` may be added only when the started event did not
already contain one; an existing effect reference cannot be replaced. These
rules are enforced both by the service and by the database trigger so a caller
cannot detach reconciliation from the execution that crossed the network seam.

The current states mean:

- `ADMITTED`: FENCE and the current certified release were transactionally
  checked and committed; no connector start has been reported. A later FENCE
  or revocation is rechecked at `MarkStarted` and can still deny the network
  seam. The record remains active until it is closed as `NOT_STARTED` or moves
  to `STARTED`/`UNCERTAIN`.
- `STARTED`: the connector completed all local prechecks and durably marked the
  last pre-network seam before issuing the external request. The source-side
  effect may exist; never retry under a new idempotency key. The PostgreSQL
  transition is a single-winner start claim: an exact second `MarkStarted`
  receives `ErrEffectReservationAlreadyStarted` and cannot dispatch.
- `NOT_STARTED`: a bounded local failure proves the connector did not cross its
  start seam. This is terminal for the admission.
- `UNCERTAIN`: the process cannot prove non-start or lacks a reliable connector
  acknowledgement/evidence result. It must never be retried optimistically. A
  later verified signed close may reconcile it to `COMPLETED`.
- `COMPLETED`: the Kernel atomically persisted a verified connector
  acknowledgement, verified EvidencePack identity, Kernel-signed close receipt,
  and matching terminal event. Its explicit outcome is `APPLIED` or
  `NOT_APPLIED`; completion alone must not be interpreted as a successful
  external mutation.

`ListActive` returns the latest `ADMITTED`, `STARTED`, and `UNCERTAIN` events in
the authenticated scope. Reservation and signed-close recovery remain available
after later FENCE or revocation and create no authority. See
`docs/operations/effect-close.md` for the separate connector acknowledgement,
Kernel receipt, EvidencePack, and recovery contract. No deployed adapter invokes
that close boundary yet, so the current GitHub integration still leaves a
successful request at `STARTED`.

## MCP and GitHub enforcement

When `runtimeadapters/mcp.BridgeConfig.EffectReservations` is configured, every
connector call must expose its exact permit scope through
`effects.PermitScopeProvider`; unclassified calls fail closed. A bounded write
must also provide approval evidence containing the exact signed dispatch
admission and implement `effects.LifecycleConnector`. The bridge verifies the
admission hash, effect hash, connector ID, granted tool scope, and signed
`connector_action`, then persists `ADMITTED`. The connector-owned permit scope
supplies the exact effect class, parameter values, and resource reference used
to mint the permit. It is resolved before MCP firewall authorization, so the
same exact effect class is checked against the server quarantine approval and
then used for approval classification; the legacy tool-name verb heuristic
cannot downgrade a connector-declared mutation to a read.

The GitHub connector implements that interface. It emits:

- `NOT_STARTED` for unknown tools, permit/scope failures, gate denial, canonical
  input failure, invalid connector/base-URL configuration, nonce replay, or
  pre-network ProofGraph intent failure;
- `STARTED` after those checks and immediately before its REST dispatch;
- `UNCERTAIN` for ambiguous REST failure, missing effect evidence, or an
  ambiguous start transition.

A typed start-interlock denial is not ambiguous: the GitHub connector appends
`NOT_STARTED` with `GITHUB_START_INTERLOCK_DENIED` and returns without issuing
HTTP. Any other `MarkStarted` failure remains `UNCERTAIN`, because the caller
cannot prove whether the durable start claim committed before response loss.

GitHub parameter decoding is strict at that seam: fractional/overflowing issue
numbers and mixed-type label/assignee arrays become `NOT_STARTED` instead of
being truncated or filtered. Mutating GitHub HTTP methods are attempted once;
HTTP redirects are not followed, and transport, redirect, rate-limit,
response-read, or 5xx ambiguity becomes `UNCERTAIN` without automatic replay.
Safe GET/HEAD reads retain bounded retry and normal redirect handling.

If a proven pre-dispatch failure cannot durably append `NOT_STARTED`, the
bridge attempts a direct `UNCERTAIN` transition and then read-only recovery. It
reports the recovered durable state and emits `EFFECT_LIFECYCLE_UNCERTAIN` if
no terminal state can be persisted or recovered; it never claims a successful
`NOT_STARTED` transition from an in-memory assumption.

Other connectors retain their legacy path only when the durable boundary is
not configured. With the boundary configured, every connector call requires
`PermitScopeProvider`; provider-classified reads remain read-only while all
calls through an unadapted connector fail closed. Writes additionally require
the lifecycle start seam.

The source-owned MCP test drives the real GitHub connector through a local HTTP
server and asserts that the request is observed only after durable `STARTED`.
It is integration evidence for the code path, not a controlled live GitHub or
deployed Data Plane proof.

## Recovery and operator response

| Observation | Meaning | Required response |
| --- | --- | --- |
| No reservation exists | Admission did not commit, or the caller used the wrong authenticated scope. | Recover the signed dispatch admission first; do not call the connector. |
| `ADMITTED` | Reserved work with no reported start. Current stop/release authority must still pass at the start seam. | Recover the worker. If the start interlock denied it, close `NOT_STARTED`; never dispatch from the old admission. |
| `STARTED` | The outbound seam was crossed. | Query the source system by the original idempotency key/execution reference; do not replay. |
| `NOT_STARTED` | Proven local pre-dispatch stop. | Close the attempt; a new attempt requires new approval authority. |
| `UNCERTAIN` | Start or outcome cannot be disproved. | Quarantine automatic retry and obtain connector/source acknowledgement evidence. |
| `COMPLETED` | A verified connector acknowledgement and EvidencePack were atomically bound to a Kernel-signed close receipt. | Verify the signed closure through `EffectCloser`; inspect its explicit `APPLIED` or `NOT_APPLIED` outcome. |

## Verification

Run unit and real database proofs:

```bash
(cd core && GOWORK=off go test ./pkg/boundary/approvalceremony ./pkg/runtimeadapters/mcp ./pkg/connectors/github -count=1)
HELM_TEST_POSTGRES_URL='postgres://...' make test-effect-reservation-postgres
make verify-approval-ceremony-vectors
make verify-effect-close-vectors
make docs-coverage
make docs-truth
```

The PostgreSQL proof covers exact replay, `ADMITTED -> STARTED -> UNCERTAIN`,
`ADMITTED -> NOT_STARTED`, terminal transitions, active-work listing,
cross-tenant RLS, append-only rejection, and concurrent admission/revocation,
start/FENCE, and start/revocation races. For each start race, the only accepted
outcomes are `STARTED` committed before the new authority or a typed start
denial after that authority committed; denial is then durably closed as
`NOT_STARTED`. Separate checks prove single-winner concurrent `STARTED`, bridge
and connector denial without HTTP, and read-only recovery of active work. They
also prove that `STARTED` correlation references cannot be rewritten and that
mutating HTTP 307/308 redirects do not reach their target. Signed-close checks
cover direct and reconciled `COMPLETED`, exact/conflicting replay, concurrent
single-winner close, signature recovery, forced-RLS closure isolation,
append-only closure history, and refusal of a terminal event without its exact
closure.

## Remaining production gates

- deploy a source-owned release signing/import service and audited trust-root
  rotation instead of test/admin construction;
- implement the production approval `BindingProvider` that derives the signed
  connector snapshot only from the verified current release;
- wire `EffectReservationAdmitter` and signed dispatch admission retrieval into
  the deployed Kernel/Data Plane configuration; the code path is opt-in today;
- wire the source-owned connector acknowledgement and signed close contracts
  into real connectors, sealed EvidencePack production, and the deployed Data
  Plane; the internal close boundary exists but no deployed adapter invokes it;
- add FENCE/revocation active-work disposition commands and cross-plane
  acknowledgement reconciliation rather than listing alone;
- add Data Plane deployment, restart/crash recovery, load, failover, and live
  controlled-effect evidence before production or Emergency Stop claims.
