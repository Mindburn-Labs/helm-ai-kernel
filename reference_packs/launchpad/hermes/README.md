# Hermes HELM Reference Proof Pack

This reference pack contains deterministic, offline-verifiable fixtures for Hermes on the
local-container substrate: a launch plan, an EvidencePack, a teardown record, and receipts.

**These are fixtures, not a capture of a customer or production run.** The launch plan and
EvidencePack are specific to Hermes (`app_id: hermes`, and this pack's `evidence-pack.tar`
hashes differently from every sibling pack). The receipts file is a shared kernel-verdict
fixture — `receipts.jsonl` is byte-identical across all four launchpad packs — and the
launch identifiers are reserved placeholders, not run identifiers. Treat the pack as a
conformance vector you can verify offline, not as evidence that this application was run.

## Verification

To verify the EvidencePack bundle offline:

```bash
helm-ai-kernel verify --bundle evidence-pack.tar
```
