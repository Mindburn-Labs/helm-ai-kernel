# Runtime Policy Reconciliation

`--policy` is bootstrap/source configuration. Runtime authority is installed by
the policy reconciler after source lookup, hash verification, optional signature
verification, compile, validation, and atomic snapshot swap.

## Environment

- `HELM_POLICY_SOURCE_KIND`: `mountedFile` (default), `controlplane`, or `crd`.
- `HELM_POLICY_CONTROLPLANE_URL`: required when `HELM_POLICY_SOURCE_KIND=controlplane`.
- `HELM_POLICY_CONTROLPLANE_TOKEN`: optional bearer token for the control-plane source.
- `HELM_POLICY_SIGNATURE_REQUIRED`: when true, unsigned bundles fail closed.
- `HELM_POLICY_TRUST_PUBLIC_KEY`: hex Ed25519 public key used when signatures are required.

## Failure Behavior

- Bad signatures do not install a snapshot.
- Malformed bundles do not partially install.
- Unavailable sources preserve last-known-good snapshots when one exists.
- Initial startup without a valid source fails closed.
- Reconcile status records policy epoch/hash, bundle ref, source refs, and the
  `policy_reconcile` audit event marker for operator evidence.

Wake the reconciler through `POST /internal/policy/reconcile` with
`HELM_SERVICE_API_KEY`; the route is wake-only and does not accept policy bytes.
