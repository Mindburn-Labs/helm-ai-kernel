---
title: Signed Active-Work Disposition
status: internal-foundation
last_reviewed: 2026-07-18
---

# Signed active-work disposition

<!-- quantum_posture: documents classical Ed25519 command and receipt signatures and the RSA-JWKS (RS256) workload token boundary; no post-quantum control is added or claimed. -->

The Kernel can durably accept a Control Plane instruction about connector work
that is already `STARTED` or `UNCERTAIN`. Every command is bound to one active
tenant/workspace FENCE, one exact reservation head, and one position in an
append-only disposition chain. The Kernel returns a separately signed receipt.

This is source-owned contract, persistence, internal workload-authenticated
Kernel transport, and real-PostgreSQL evidence. It is internal and
pre-production. There is no deployed cross-plane path, connector disposition
adapter, or controlled-live cancellation, compensation, or reconciliation
proof.

## No execution authority

The allowed actions are:

- `HOLD` — keep automatic retry and terminal inference quarantined;
- `RECONCILE_SOURCE` — request a source-system observation using the original
  execution and idempotency identities;
- `REQUEST_CANCEL` — record operator intent to request cancellation; and
- `REQUEST_COMPENSATE` — record operator intent to request a compensating
  operation.

Acceptance is not permission to perform any of those external effects. Every
`effect-disposition-receipt.v1` contains `execution_authority: NONE`. A Data
Plane that cancels or compensates still needs a separate, current, governed
effect authority and source-specific connector path. Neither the command nor
its receipt may be presented as an EffectPermit.

## Internal workload transport

When both `HELM_APPROVAL_CONSUMPTION_ENABLED=1` and
`HELM_EFFECT_DISPOSITION_ENABLED=1`, the Kernel exposes:

- `POST /internal/v1/effect-dispositions` for one strict signed command
  envelope; and
- `POST /internal/v1/effect-dispositions/recover` with a strict `command_id`
  JSON body for tenant/workspace scoped recovery of the committed signed
  record.

Both routes use the existing JWKS workload boundary and require the distinct
`HELM_EFFECT_DISPOSITION_SCOPE` capability (default
`helm.effect.disposition`). The authenticated token supplies subject, tenant,
workspace, and the configured workload audience; caller-controlled headers do
not. Responses are `no-store` and marked `internal_non_production`.

Startup fails closed unless PostgreSQL, the approval signing identity, JWKS
configuration, and both deployment-pinned public keyrings are present. The
strict JSON keyrings are supplied in
`HELM_EFFECT_DISPOSITION_COMMAND_KEYRING` with version
`effect-disposition-command-keyring.v1` and
`HELM_CONNECTOR_RELEASE_AUTHORITY_KEYRING` with version
`connector-release-authority-keyring.v1`. Entries bind authority ID, signing
key ref, canonical Ed25519 public key, enabled state, and UTC key lifetime;
command keys additionally bind the exact workload audience. Multiple entries
support explicit overlapping key rotation. HTTP error bodies are sanitized and
unsigned statuses remain transport evidence only, never disposition authority.

The environment values are compact JSON. Replace the example keys, identities,
and lifetimes with deployment-owned values; keep historical verification keys
until every dependent disposition and close artifact has passed its retention
window.

```json
{"keyring_version":"effect-disposition-command-keyring.v1","keys":[{"authority_id":"spiffe://helm/control-plane","signing_key_ref":"kms://helm/control-plane/disposition-2026-07","audience":"helm-data-plane","public_key":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","enabled":true,"not_before":"2026-07-18T00:00:00Z","not_after":"2026-10-18T00:00:00Z"}]}
```

```json
{"keyring_version":"connector-release-authority-keyring.v1","keys":[{"authority_id":"connector-registry-prod","signing_key_ref":"kms://helm/connector-registry-2026-07","public_key":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","enabled":true,"not_before":"2026-07-18T00:00:00Z","not_after":"2026-10-18T00:00:00Z"}]}
```

### Response and recovery contract

Every route response, including authentication and validation failures, sets
`Cache-Control: no-store` and
`X-Helm-Contract-Status: internal_non_production`. Only a valid signed record
is durable disposition evidence; HTTP status alone is unsigned transport
evidence.

| Status | Meaning | Caller action |
| --- | --- | --- |
| `400` | Malformed, non-canonical, unknown-field, trailing, or invalid signed-command input. | Do not retry unchanged input. |
| `401` | Missing, invalid, expired, or overlong workload token. | Obtain a fresh resource-bound token. |
| `403` | Required scope or verified workload identity is absent, or the pinned command authority rejects the envelope. | Treat as a security denial; do not substitute caller-controlled scope. |
| `404` | Recovery found no committed record in the authenticated tenant/workspace scope. | The outbox may retry the exact same signed command; never synthesize a receipt. |
| `409` | Current FENCE, reservation head/state, command sequence, predecessor, or immutable replay binding rejects the command. | Stop automatic mutation and reconcile source-owned state. |
| `415` | Request is not `application/json`. | Correct the client contract. |
| `503` | Durable authority, signing, release verification, or runtime wiring is unavailable. | Keep the operation uncertain and retry recovery after repair. |

After a timeout, connection loss, or any other ambiguous record response, the
caller must first `POST /internal/v1/effect-dispositions/recover` with the exact
`command_id`. A valid signed record closes the ambiguity. Authenticated `404`
permits replay of only the exact original signed envelope; `503`, timeout, or
an unsigned/malformed body remains uncertain and never permits a new command
or external connector action.

## Exact authority binding

The Control Plane signs `effect-disposition-command.v1` under a
deployment-pinned authority ID, key ref, audience, and key lifetime. The
command binds:

- tenant, workspace, and workload audience;
- the exact current FENCE command ID/hash, epoch, and Kernel receipt hash;
- admission ID and exact active reservation sequence/head/state;
- connector ID/version/action and the original execution, proof-session,
  intent, effect, idempotency, and effect-hash identities;
- action, disposition ref, actor, and reason;
- monotonic disposition sequence and predecessor receipt hash; and
- issue/expiry timestamps with a maximum ten-minute lifetime.

The first disposition has sequence 1 and no predecessor. Every successor must
name the immediately preceding Kernel receipt hash. A new FENCE epoch makes an
old command stale even if the reservation did not change.

## Transaction behavior

`EffectDispositionService.Record` verifies the Control Plane signature before
opening the storage transaction. The PostgreSQL operation then:

1. establishes authenticated tenant/workspace RLS context;
2. acquires the shared tenant/workspace FENCE lock;
3. returns an exact committed command replay, or rejects changed content;
4. checks command liveness against the PostgreSQL clock;
5. requires the command's exact FENCE to be the current active FENCE;
6. loads and cryptographically verifies the exact current reservation and its
   historical signed authorities;
7. requires `STARTED` or `UNCERTAIN` and exact reservation bindings;
8. loads and cryptographically re-verifies every existing chain record, then
   requires the next sequence and predecessor hash;
9. emits a self-hashed Kernel receipt with `execution_authority: NONE`, signs
   it under the deployment-pinned Kernel trust root, and appends the immutable
   record; and
10. commits the command, FENCE snapshot, receipt, and signature atomically.

Concurrent commands for the same next chain position have one winner. The
loser conflicts unless it is an exact replay of the committed command.
`Recover` and `ListForEffect` re-verify Control Plane and Kernel signatures,
FENCE receipt integrity, reservation authority, and chain continuity. These
read paths create no execution authority.

## Signed close binding

Once any disposition exists for an effect, terminal close must acknowledge the
latest one. The connector acknowledgement and Kernel close receipt both carry
the exact latest `disposition_receipt_hash`; their `reconciliation_ref` must
equal that command's `disposition_ref`. A missing, stale, or substituted hash
fails closed.

While the scope is fenced, close requires a disposition bound to the exact
current FENCE. Rotating the FENCE invalidates the earlier disposition for close
until a fresh successor is recorded. `HOLD` explicitly blocks terminal close;
another signed current-FENCE successor must request reconciliation, cancel, or
compensation before verified source evidence can close the reservation.

This binding proves which operator instruction the source observation answers.
It does not prove the connector actually performed a cancel or compensation;
the acknowledgement outcome and sealed EvidencePack must describe the real
source observation explicitly.

## Persistence invariants

Migration `004_effect_dispositions.sql` adds forced-RLS, append-only
`approval_effect_dispositions`. Database triggers enforce scope, JSON/shadow
parity, immutable rows, active reservation binding, active exact FENCE binding,
and monotonic chain order. The application layer additionally verifies both
signatures and all historical authorities during record, recovery, and list.

The steady-state disposition data path needs `SELECT, INSERT`, but the current
process still calls the approval store's idempotent `Init` at startup. The
configured role therefore currently must own the source-owned schema objects;
a separate owner-applied migration and DML-only runtime credential split is
not implemented in this slice. It must remain non-superuser and must not have
`BYPASSRLS`. Production promotion is blocked until that split and an explicit
startup/readiness check for `connector_release_authorities` are source-owned
and live-proven. Signing inside a database transaction also requires bounded
KMS/HSM latency and explicit failure telemetry before deployment.

## Portable and database verification

The source-owned `reference_packs/effect-disposition-v1` pack contains canonical
command, envelope, signing payload, receipt, receipt signing payload, and
negative mutations. Go and independent Python implementations verify hashes,
signature domains, pinned identities and lifetimes, exact cross-artifact
bindings, chain semantics, and the `NONE` authority invariant.

Run:

```bash
make verify-effect-disposition-vectors
make verify-effect-close-vectors
HELM_TEST_POSTGRES_URL='postgres://...' make test-effect-reservation-postgres
go -C core test ./cmd/helm-ai-kernel -run 'Test(EffectDisposition|ApprovalConsumption|RuntimeRoute)' -count=1
make docs-coverage
make docs-truth
```

The PostgreSQL proof covers no-FENCE rejection, chained dispositions, exact and
conflicting replay, recovery, listing, concurrent single-winner insertion,
stale-FENCE rejection, expiry, forced-RLS isolation, append-only rejection, and
mandatory current-FENCE non-`HOLD` disposition binding at close. Direct
wrong-scope insert and delete attempts are rejected. These are local and CI
proofs, including rejection of a structurally valid but cryptographically
forged row at both successor append and close. They are not deployed or
controlled-live evidence.

## Remaining production gates

- deploy the Control Plane durable signed-command ledger, leased outbox,
  retry/reconciliation state, and pinned Kernel receipt verification;
- expose and deploy the workload-authenticated Data Plane record/recover
  adapter with least-privilege credentials and replay-safe worker semantics;
- implement certified connector adapters for source reconciliation and keep
  cancel/compensate behind separate current governed effect authority;
- bind real connector acknowledgements and sealed EvidencePacks to disposition
  results and surface unresolved active work in the operator Console;
- deploy and rotate Control Plane and Kernel keys through source-owned KMS/HSM
  configuration, including historical verification retention;
- prove crash recovery, KMS latency/failure behavior, load, failover,
  backup/restore, and controlled-live source outcomes; and
- pass source-owned release gates before any production, Emergency Stop, or GA
  claim.
