# OpenCode HELM Reference Proof Pack

This reference pack contains deterministic, offline-verifiable fixtures for OpenCode on the
local-container substrate: a launch plan, an EvidencePack, a teardown record, and receipts.

**These are fixtures, not a capture of a customer or production run.** The launch plan and
EvidencePack are specific to OpenCode (`app_id: opencode`, and this pack's `evidence-pack.tar`
hashes differently from every sibling pack). The receipts file is a shared kernel-verdict
fixture — `receipts.jsonl` is byte-identical across all four launchpad packs — and the
launch identifiers are reserved placeholders, not run identifiers. Treat the pack as a
conformance vector you can verify offline, not as evidence that this application was run.

## Verification

The seal on this pack is **self-attested**: its verification key travels inside the pack.
Verifying it proves the bundle is internally consistent and untampered. It does **not** prove
provenance — nothing here attests who produced it or on what machine.

The kernel refuses a self-attested seal by default, so the plain command exits non-zero. To
verify the bundle while accepting that limit explicitly:

```bash
HELM_ALLOW_SELF_ATTESTED_EVIDENCE=1 helm-ai-kernel verify --bundle evidence-pack.tar
```

```
envelope ep_84f9bca59aee · seal valid · sig 1/1 · trust dev-local
VERIFIED · sealed 2026-06-04T14:21:26Z · anchor local-only · storage local-only
```

For a pack whose provenance you can actually check, supply a trusted key
(`HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX` or a trust config) and use
`--profile team|customer|high-assurance`. That is the path a real EvidencePack takes; these
fixtures deliberately do not, which is why the default refusal is correct behaviour rather
than a bug to work around.
