---
title: Scoped Emergency-Stop Fence
status: internal-foundation
last_reviewed: 2026-07-18
---

<!-- quantum_posture: FENCE command verification is raw classical Ed25519;
acknowledgement profile binding fails closed and this foundation makes no PQ guarantee. -->

# Scoped Emergency-Stop Fence

The Kernel has an internal, opt-in fence for a specific tenant/workspace. When
active, the Kernel-owned guarded evaluation, approval-consumption, and
dispatch-admission paths deny their covered new transitions for that scope.
This is not end-to-end connector enforcement or an operator-ready Emergency
Stop yet.

## Activation boundary

Set `HELM_EMERGENCY_STOP_FENCE_ENABLED=1` only when all of the following are
present:

- a durable Kernel database;
- a Control Plane that implements the shared `emergency-stop-fence.v1`
  contract and persists its own command ledger/outbox;
- `HELM_EMERGENCY_STOP_COMMAND_AUDIENCE`, the current audience unique to this
  Kernel deployment;
- `HELM_EMERGENCY_STOP_COMMAND_PUBLIC_KEYS`, a comma-separated
  `key_id=hex-ed25519-public-key` active keyring; and
- `HELM_RUNTIME_TENANT_ID` and `HELM_RUNTIME_WORKSPACE_ID`, each pinned to
  the deployed scope; and
- a service credential for the fixed internal Kernel route.

Multiple active-keyring entries are permitted only for an intentional
signing-key rotation overlap. The command signs its `audience` and `key_id`,
so a command for one deployment cannot be replayed to another deployment that
uses a different audience by default.

For a deliberate command key or audience rotation, an operator may additionally
pin prior command identities in
`HELM_EMERGENCY_STOP_COMMAND_REPLAY_KEYRING`:

```json
{
  "keyring_version": "emergency-stop-fence-command-replay-keyring.v1",
  "keys": [
    {
      "command_key_id": "cp-before-rotation",
      "command_audience": "kernel-before-rotation",
      "command_public_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ]
}
```

Each entry binds one exact key ID, audience, and Ed25519 public key. The
Kernel never re-signs a queued command; it accepts only its original signature
under that exact authority. Unknown or mismatched old audiences/keys are
forbidden. A key ID may span an active and prior audience only when its public
key is identical; duplicate key-ID/audience pairs or conflicting public
material reject configuration. Remove prior entries only after the Control
Plane has drained or otherwise reconciled its signed command outbox.

For the bundled Helm chart, set the JSON directly through
`helm.emergencyStop.commandReplayKeyring`, or source it from the existing
command-authority Secret by setting
`helm.emergencyStop.commandReplayKeyringSecretKey`. The two chart inputs are
mutually exclusive; a Secret-backed replay keyring requires
`helm.emergencyStop.existingSecret`.

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
- The intended fence coverage is new governed dispatches only. Current proven
  coverage is limited to the Kernel-owned gates listed here; connector-boundary
  coverage still depends on the Data Plane integration below.
- When approval-grant consumption is enabled on PostgreSQL, FENCE and
  `GRANT_ISSUED -> CONSUMED` share one tenant/workspace advisory transaction
  lock. FENCE-first rejects consumption; consumption-first only establishes
  that the signed consumption record committed before the later FENCE. The
  separate connector dispatch may not have begun.
- Approval consumption response-loss recovery remains a read-only evidence
  operation after FENCE: it returns the existing record and creates no new
  authority.
- Kernel dispatch admission is the near-effect ordering gate for new governed
  pack dispatches. It shares the same tenant/workspace advisory lock with
  FENCE and persists a short-lived signed admission bound to the exact
  consumption, attempt, idempotency-key hash, effect, connector, and action.
  FENCE-first denies new admission; admission-first creates a pre-FENCE
  admitted record even when its signed state is still `NOT_STARTED`. Exact
  replay returns the original record without extending expiry; changed
  bindings conflict. Admission alone no longer authorizes a later connector
  start: the separate internal effect reservation stream reacquires the same
  scope lock at `MarkStarted`, rechecks current FENCE, and rechecks the current
  certified exact-release head before durably crossing the pre-network seam.
  If FENCE/revocation commits first, the connector closes `NOT_STARTED` and
  emits no network request; if `STARTED` commits first, the effect is active
  work that the later stop must reconcile. The stream exposes active
  `ADMITTED / STARTED / UNCERTAIN` work. A separate internal signed-close
  boundary can reconcile `STARTED` or `UNCERTAIN` after FENCE/revocation by
  verifying a connector acknowledgement and EvidencePack and atomically
  appending a Kernel-signed `COMPLETED` receipt. Close creates no execution
  authority and does not re-open the stopped scope. A separate internal signed
  disposition chain now binds operator intent to the exact current FENCE and
  active reservation head, with Kernel receipts explicitly declaring
  `execution_authority: NONE`; close must bind the latest current-FENCE
  disposition receipt and rejects `HOLD`.
  There is still no deployed close/disposition adapter, Control Plane durable
  command outbox, governed compensation controller, or renewal after expiry.
- This Kernel gate does not by itself enforce the connector boundary. Merge,
  deploy, and production claims remain blocked until the Data Plane requires
  and atomically persists the signed admission before every
  `CONSUMED -> DISPATCHING` transition, including cached and recovered
  consumption records. The internal boundary now implements append-only
  lifecycle transitions, active-work listing, exact current-release locking at
  both admission and start, typed no-network denial, and the GitHub pre-network
  seam when configured. Production remains blocked on deployed Data Plane
  wiring, deployed connector acknowledgement/close evidence, cross-plane
  disposition delivery/reconciliation, and controlled runtime proof. The
  dispatch workload cannot select
  `connector_id`, `connector_action`, release scope, or revision; the Kernel
  derives them from the signed approval chain.
- It does not revoke existing permits, cancel in-flight work, stop unmanaged
  adapters, or implement release/unfence. Those remain separate contracts.

Do not describe this feature as an Emergency Stop in release notes, public
copy, or operator UI until the cross-plane command ledger, acknowledgement
reconciliation, in-flight coverage, and live evidence gates exist.
