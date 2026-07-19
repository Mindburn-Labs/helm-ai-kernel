# Launch Mission v1 reference pack

This pack proves deterministic Go/Python parity for the provider-neutral
Launch Mission preview contracts. It covers ten approval-bound route
artifacts, all six preview effect inputs, signed provider certification,
canonical `ApprovalGrant` consumption, the Kernel verdict envelope, receipt
lineage, safe-integer normalization, and negative tamper vectors. A second
provider-neutral vector routes one repository graph across two distinct cloud
profiles and preserves an ephemeral API, a stateful database, and their exact
cross-cloud dependency instead of flattening the repository into a website.

Run:

```bash
make verify-launch-mission-vectors
```

The DigitalOcean-shaped record is a deterministic conformance fixture. It is
not production connector certification, proof of a live cloud deployment, or a
claim that any named provider is currently enabled. Production dispatch still
requires a current source-owned certification record, exact route approval,
and the atomic data-plane finalization guard.

To regenerate the byte-exact vector file from the Go source implementation:

```bash
HELM_DUMP_LAUNCH_REFERENCE_PACK=1 \
HELM_LAUNCH_REFERENCE_PACK_OUTPUT=/tmp/launch-mission-vectors.json \
go test ./core/pkg/contracts -run TestDumpLaunchMissionReferencePack -count=1
```

Review the diff before replacing the committed vector and update
`SOURCE-MANIFEST.json` only after both independent verifiers pass.
