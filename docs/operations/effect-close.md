---
title: Signed Connector Effect Close
status: internal-foundation
last_reviewed: 2026-09-06
---

<!-- quantum_posture: documents classical Ed25519 connector effect-close acknowledgement and receipt signing plus offline verification; no post-quantum control is added or claimed. -->

# Signed connector effect close

Status: retired (helm-tracker#266). `EffectCloser`'s close and recovery path,
the PostgreSQL closure writes and their tests were deleted: no shipped binary
called them (`controls.yaml` CTL-040, retired). The tree keeps the contract
types and schemas, the `approval_effect_closures` table, the receipt signing
payloads with the v2 and v3 receipt signature checks, and the reference
vectors. No shipped binary writes a closure, so the authority, transaction,
persistence and recovery sections below describe the design, not running code.

In that design the v1 Kernel close atomically closes a durable connector effect
reservation from `STARTED` or `UNCERTAIN` when it receives a verified connector
acknowledgement and a verified, sealed EvidencePack. The close appends
`COMPLETED`, but the outcome remains explicit as `APPLIED` or `NOT_APPLIED`.

There is no Data Plane close endpoint, connector acknowledgement publisher,
cross-plane disposition controller, or controlled-live effect proof.

Versions 2 and 3 add contracts and reference vectors only. The authority,
transaction, persistence, and recovery sections below describe v1; they are not
evidence of a v2 runtime or database implementation.

## Two independent authorities

A connector cannot make its own execution terminal in the Kernel.

1. The connector runtime emits a self-hashed
   `connector-effect-acknowledgement.v1` and detached Ed25519 signature.
2. The Kernel verifies a deployment-pinned key selected by issuer, key ref,
   connector ID, and exact connector version. The acknowledgement observation
   must be inside that key's configured lifetime.
3. A required `EffectEvidencePackVerifier` verifies the supplied EvidencePack
   reference and hash before the database transaction begins.
4. Under the tenant/workspace transaction lock, the Kernel binds the
   acknowledgement to the exact current reservation, its signed dispatch
   admission, historical certified release envelope, and correlation refs.
5. The Kernel emits a self-hashed `effect-close-receipt.v1`, signs it under the
   deployment-pinned Kernel trust root, and atomically inserts both the close
   proof and the successor `COMPLETED` event.

The connector acknowledgement states a source observation. The Kernel receipt
is terminal authority. Neither signature establishes trust from embedded key
material; deployments must pin the corresponding trust roots.

## Exact bindings

The acknowledgement and receipt bind:

- tenant, workspace, audience, admission, attempt, and exact connector action;
- connector ID/version and the release-bound connector signer identity;
- original idempotency-key hash and effect hash;
- connector execution, proof-session, intent, effect, and reconciliation refs;
- under FENCE, the exact latest current-FENCE non-`HOLD` disposition receipt
  hash;
- source response hash and outcome;
- the prior reservation state, sequence, and canonical head hash;
- verified EvidencePack ref/hash; and
- Kernel trust-root ID, signing-key ref, closer identity, and database close
  time.

`APPLIED` requires an exact `effect_ref`. `NOT_APPLIED` forbids one. Closing an
`UNCERTAIN` reservation requires a `reconciliation_ref`; the close cannot erase
the execution identity that created the uncertainty.

The connector and PostgreSQL clocks may differ by at most five minutes at the
contract boundary. The acknowledgement cannot predate the relevant reservation
timeline beyond that bounded skew and cannot be in the future beyond the same
window. The Kernel receipt uses the PostgreSQL clock.

## Transaction and stop semantics

`EffectCloser.Close` verifies the acknowledgement signature and EvidencePack
before taking database locks. The storage transaction then:

1. establishes forced-RLS tenant/workspace context;
2. acquires the same scope advisory lock as FENCE;
3. loads the latest reservation and verifies its immutable signed authorities;
4. returns a previously committed exact close replay, or rejects a conflict;
5. requires a current `STARTED` or `UNCERTAIN` head;
6. loads current FENCE state; while fenced, requires a latest disposition,
   fully verifies its Control Plane and Kernel signatures plus historical
   authority, requires it to bind the exact current FENCE, and rejects `HOLD`;
7. requires the acknowledgement's receipt hash and reconciliation ref to bind
   that disposition exactly;
8. validates every acknowledgement binding and the bounded clock window;
9. derives a deterministic close ID from admission, acknowledgement, and
   EvidencePack hashes;
10. inserts the immutable signed closure;
11. appends the matching `COMPLETED` event; and
12. commits both records atomically.

Close remains possible after FENCE only through a disposition bound to the
exact current FENCE. A missing disposition, a receipt from an older FENCE
epoch, or `HOLD` fails closed. A connector-release revocation does not prevent
reconciling already-active work. Close creates no new execution authority and
performs no external effect; current FENCE is evaluated as reconciliation
authority, not as a new execution grant. The persisted historical release
envelope and all signed admission bindings are still verified.

This behavior does not cancel, retry, or compensate active work. The separate
signed disposition contract records `HOLD`, `RECONCILE_SOURCE`,
`REQUEST_CANCEL`, or `REQUEST_COMPENSATE`, but its receipt explicitly carries
`execution_authority: NONE`; any external cancel or compensation still requires
a separate governed effect path and source-specific connector. See
`docs/operations/effect-disposition.md`.

## Persistence invariants

Migration `003_effect_closures.sql` adds:

- a forced-RLS, append-only `approval_effect_closures` table; and
- the `COMPLETED` successor shape in
  `approval_effect_reservation_events`.

Database triggers reject shadow-column/JSON drift, mutation, skipped sequence,
changed authority, a closure not bound to the current closable head, and a
`COMPLETED` event without its exact closure record. Runtime roles need
`SELECT, INSERT`; production should use a dedicated least-privilege close
writer and must not grant DDL, superuser, or `BYPASSRLS`.

The legal terminal paths are:

```text
ADMITTED -> STARTED -> COMPLETED(APPLIED | NOT_APPLIED)
ADMITTED -> UNCERTAIN -> COMPLETED(APPLIED | NOT_APPLIED)
ADMITTED -> STARTED -> UNCERTAIN -> COMPLETED(APPLIED | NOT_APPLIED)
```

`ADMITTED -> NOT_STARTED` remains the separate proven-no-dispatch terminal
path. `COMPLETED` cannot be reopened or mutated.

## Recovery

`EffectCloser.Recover` reads the closure under authenticated scope, verifies
both signatures, reloads the exact prior reservation event, recomputes its head
hash, and checks the complete closure-to-event binding. It creates no new
authority and remains valid after FENCE or revocation.

Callers that need authoritative terminal evidence must recover through
`EffectCloser`, not infer proof from the latest lifecycle state alone. An exact
close replay returns the original signed record; a changed acknowledgement,
EvidencePack ref, or EvidencePack hash conflicts.

## Portable verification

The source-owned `reference_packs/effect-close-v1` pack contains canonical
acknowledgement, envelope, signing payload, receipt, signing payload, positive
vectors, and negative mutations. An independent Python implementation
verifies exact hashes, signature domains, pinned identities, outcome semantics,
clock rules, latest-disposition binding, and cross-artifact bindings. The Go
tests that checked the same vectors were deleted with the close path; the
remaining Go tests validate the schemas.

Run:

```bash
make verify-effect-close-vectors
make docs-coverage
make docs-truth
```

The PostgreSQL proof and its `make` target were deleted with the close path.
That proof included direct and reconciled close, exact replay,
conflicting replay, verified recovery, concurrent single-winner close, forced
RLS isolation, append-only rejection, schema idempotence, and database refusal
of `COMPLETED` without a matching closure. It also rejects close under FENCE
without a disposition, with a pre-rotation disposition, under `HOLD`, or from a
structurally valid but cryptographically forged disposition row.

## Version 2: contracts and reference vectors only

`connector-effect-acknowledgement.v2` and `effect-close-receipt.v2` retain the
separate connector-observation and Kernel-closure authorities. Their source
types live in `core/pkg/contracts/effect_close.go`; detached signing and
verification live in `core/pkg/boundary/approvalceremony/effect_close_signature.go`.
They do not replace the v1 types consumed by `EffectCloser` and its PostgreSQL
store.

V2 additionally binds the activation record ref/hash, exact adapter ID/version,
adapter capability ref/hash, expected finality predicate ref/hash, sorted unique
observed external-fact refs/hashes, reconciliation deadline, and resolution
ref/state. The acknowledgement and receipt must agree on those fields. A
signature establishes integrity under a pinned key; it does not independently
establish provider readback or evaluate the referenced finality predicate.

Every v2 close receipt has `state: COMPLETED`. The permitted outcome relations
are:

| Resolution state | Outcome | Conditional compensation ref |
|---|---|---|
| `FINALIZED_SUCCESS` | `APPLIED` | Forbidden |
| `FINALIZED_FAILURE` | `NOT_APPLIED` | Forbidden |
| `COMPENSATED` | `APPLIED` | Required |

An unresolved, provisional, or partial result cannot produce a v2 terminal
receipt. A compensation ref records resolved compensation evidence; it grants
no authority to execute compensation.

`reference_packs/effect-close-v2` verifies canonical hashes, detached signatures,
exact acknowledgement/receipt bindings, and seven negative mutations in Go and
independent Python. `make verify-effect-close-vectors` runs the v1, v2, and v3
packs. These checks do not establish v2 persistence, an authenticated close
route, connector publication, durable signed EvidencePack lineage, or live
provider finality. Those runtime paths remain unimplemented.

## Version 3: disposition binding prerequisite

V3 restores the optional `disposition_receipt_hash` in both the acknowledgement
and receipt while retaining V2 activation, adapter capability, and finality
semantics. When present, the hash requires a reconciliation ref and must match
between acknowledgement and receipt. It participates in their complete artifact
hashes and their separate V3 signature domains.

The published V2 schemas reject additional fields and have no signed extension
slot. V1/V2 schemas, canonical payloads, signature domains, and reference vectors
remain unchanged; V3 is an explicit successor, not a reinterpretation of V2.

`reference_packs/effect-close-v3` supplies canonical vectors and an independent
Python verifier. `make verify-effect-close-vectors` checks all three versions.
This is a contract prerequisite only. `EffectCloser` and its PostgreSQL store
still consume V1. V3 does not establish a close route, durable lineage, source
readback, or permission to dispatch an effect. Runtime adoption must preserve
the current exact-reservation, current-FENCE, signed-disposition and non-`HOLD`
checks; a valid V3 hash alone cannot satisfy those checks.

## Remaining production gates

- expose the close boundary only through an authenticated, workload-bound Data
  Plane API and durable worker/outbox;
- make certified connectors produce acknowledgement and sealed EvidencePack
  artifacts from actual source-system responses;
- deploy and rotate connector acknowledgement and Kernel receipt trust roots
  through source-owned KMS/HSM configuration;
- give close writers a dedicated least-privilege PostgreSQL role;
- deploy the existing internal signed-disposition boundary through a durable
  Control Plane command ledger/outbox and authenticated Data Plane adapter;
- add separate governed cancellation/compensation execution policy and
  source-specific connectors; disposition acceptance itself has no effect
  authority;
- prove restart recovery, retry safety, load, failover, backup/restore, and
  controlled-live source outcomes; and
- pass the repository's source-owned release gates before any production,
  Emergency Stop, or GA claim.
