# Runtime Policy Reconciliation

<!-- quantum_posture: policy bundle verification uses classical Ed25519 when
configured; this runtime contract makes no post-quantum resistance claim. -->

`--policy` is bootstrap/source configuration. Runtime authority is installed by
the policy reconciler after source lookup, hash verification, optional signature
verification, compile, validation, and atomic snapshot swap.

## Environment

- `HELM_POLICY_SOURCE_KIND`: `mountedFile` (default), `controlplane`, or `crd`.
- `HELM_POLICY_CONTROLPLANE_URL`: required when `HELM_POLICY_SOURCE_KIND=controlplane`.
- `HELM_POLICY_BEARER_TOKEN`: optional bearer token for the control-plane source.
- `HELM_POLICY_SIGNATURE_REQUIRED`: when true, unsigned bundles fail closed.
- `HELM_POLICY_TRUST_PUBLIC_KEY`: hex Ed25519 public key used when signatures are required.
- `HELM_POLICY_ON_INVALID_UPDATE`: `keepLastKnownGood` (default) or `deny`.
- `HELM_POLICY_LAST_KNOWN_GOOD_MAX_AGE`: positive Go duration; defaults to `10m` when last-known-good retention is enabled.

## Failure Behavior

- Bad signatures do not install a snapshot.
- Malformed bundles do not partially install.
- Source, hash, signature, compile, and validation faults retain an active
  last-known-good snapshot only inside its configured bounded window (10
  minutes by default); a snapshot without an install time is not fresh. `deny`
  invalidates immediately.
- On a fault after expiry, or when last-known-good retention is disabled, the reconciler
  invalidates the snapshot and clears its Graph, PDP, and policy layers, so
  Guardian denies it.
- Expiry is evaluated when a source fault is reconciled. With the normal polling
  loop, the operational window is the configured age plus at most one poll
  interval; monitor a stopped reconciler as a runtime fault.
- Initial startup without a valid source fails closed.
- Reconcile status records policy epoch/hash, bundle ref, source refs, and the
  `policy_reconcile` audit event marker for operator evidence.

Wake the reconciler through `POST /internal/policy/reconcile` with
`HELM_SERVICE_API_KEY`; the route is wake-only and does not accept policy bytes.
