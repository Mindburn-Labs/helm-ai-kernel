---
title: Scoped Emergency-Stop Fence
status: internal-foundation
last_reviewed: 2026-07-17
---

<!-- quantum_posture: FENCE command verification is raw classical Ed25519;
acknowledgement profile binding fails closed and this foundation makes no PQ guarantee. -->

# Scoped Emergency-Stop Fence

The Kernel has an internal, opt-in fence for a specific tenant/workspace. When
active, the Guardian denies new governed dispatches for that scope. It is not
an operator-ready Emergency Stop yet.

## Activation boundary

Set `HELM_EMERGENCY_STOP_FENCE_ENABLED=1` only when all of the following are
present:

- a durable Kernel database;
- a Control Plane that implements the shared `emergency-stop-fence.v1`
  contract and persists its own command ledger/outbox;
- `HELM_EMERGENCY_STOP_COMMAND_AUDIENCE`, unique to this Kernel deployment;
- `HELM_EMERGENCY_STOP_COMMAND_PUBLIC_KEYS`, a comma-separated
  `key_id=hex-ed25519-public-key` keyring; and
- `HELM_RUNTIME_TENANT_ID` and `HELM_RUNTIME_WORKSPACE_ID`, each pinned to
  the deployed scope; and
- a service credential for the fixed internal Kernel route.

Multiple keyring entries are permitted only for an intentional signing-key
rotation overlap. The command signs its `audience` and `key_id`, so a command
for one deployment cannot be replayed to another deployment that uses a
different audience.

## Kernel contract behavior

`POST /internal/emergency-stop/fence` requires both the internal service
credential and an Ed25519 signature over the canonical v1 command. It stores
only the active fence state, verifies exact idempotent replay by canonical
command hash, and returns a Kernel-signed acknowledgement. The acknowledgement
state binds the Kernel signer key ID, closed signer profile, and public key
into its receipt hash and signature. A consumer must resolve that identity
through a deployment-pinned Kernel keyring and compare the returned key before
accepting the signature; an acknowledgement never establishes its own trust.

The active-state table is not an immutable command/audit ledger. The Control
Plane must persist the signed command, retry the same command through a
leased outbox, verify the Kernel acknowledgement against a pinned Kernel key,
and reconcile uncertainty before a Console can show enforcement as complete.
An exact replay whose Kernel acknowledgement signer identity differs from the
persisted state is rejected fail-closed rather than repackaged under a new key.

## Scope and coverage

- A configured fence requires an authoritative tenant/workspace binding for
  governed evaluation. `HELM_RUNTIME_TENANT_ID` must match the authenticated
  tenant and `HELM_RUNTIME_WORKSPACE_ID` must match the trusted workspace
  header or ext-authz request. Missing or unverified scope denies fail-closed.
- `POST /api/v1/evaluate` uses `X-Helm-Workspace-ID` matched against
  `HELM_RUNTIME_WORKSPACE_ID`; it never trusts a workspace supplied in JSON.
- The unauthenticated OpenAI-compatible proxy is unavailable while the fence
  is enabled, because it cannot establish a tenant/workspace binding. It may
  only return after an authenticated adapter contract binds that scope.
- The fence covers new governed dispatches only.
- When approval-grant consumption is enabled on PostgreSQL, FENCE and
  `GRANT_ISSUED -> CONSUMED` share one tenant/workspace advisory transaction
  lock. FENCE-first rejects consumption; consumption-first only establishes
  that the signed consumption record committed before the later FENCE. The
  separate connector dispatch may not have begun and still needs a final
  data-plane near-effect fence check.
- Approval consumption response-loss recovery remains a read-only evidence
  operation after FENCE: it returns the existing record and creates no new
  authority. The current internal Data Plane can still use any valid persisted
  consumption record as dispatch input, so this Kernel change is merge/deploy
  blocked on a final same-scope near-effect Data Plane fence gate.
- It does not revoke existing permits, cancel in-flight work, stop unmanaged
  adapters, or implement release/unfence. Those remain separate contracts.

Do not describe this feature as an Emergency Stop in release notes, public
copy, or operator UI until the cross-plane command ledger, acknowledgement
reconciliation, in-flight coverage, and live evidence gates exist.
