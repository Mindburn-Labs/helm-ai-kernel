# Agent Provenance Pack v1

`agent_provenance_pack.v1` records agent authoring provenance: sessions, turns, tool invocations, file effects, commits, validation runs, redaction status, and an optional `agent_run_receipt.v1` binding.

It is advisory evidence. It is not an authorization boundary, connector certification, production release proof, or HELM-native execution receipt.

## Verification Ladder

- `unverified`: manifest, object hashes, signature, or redaction status failed.
- `hash_conformant`: content-addressed objects and root hash are internally consistent.
- `crypto_conformant_advisory`: root hash signature verifies against a trusted local key.
- `helm_bound_advisory`: crypto-conformant and the optional agent-run receipt links to a real HELM EvidencePack, receipt, or ProofGraph ref.

No verifier may return `helm_native` for this format.

## Hashing And Signing

Objects are JCS canonical JSON and addressed by lowercase SHA-256 hex. The manifest root is the JCS/SHA-256 hash over sorted object refs plus the redaction report and optional agent-run receipt object. The manifest signature signs:

```json
{
  "capture_profile": "hash_only",
  "pack_id": "pack-...",
  "root_hash": "...",
  "version": "agent_provenance_pack.v1"
}
```

with Ed25519.

## Import Boundary

EvidencePack importers may place packs under `host_evidence/agent_provenance/`. Import reports must include this limitation:

> agent authoring provenance; advisory unless bound to HELM verdict receipts

