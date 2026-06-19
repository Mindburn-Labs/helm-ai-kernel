# externalhost/testdata — vendor receipt golden vectors

## Vector status

| File | Vendor | Status | Source |
|------|--------|--------|--------|
| `signet_v1_synthetic.json` | Prismer-AI/signet | **SYNTHETIC** | Test keypair generated in-process. No real-world published sample with known public key was available at time of authoring (2026-06-15). The Signet project (https://github.com/Prismer-AI/signet) generates keys at agent startup; receipts are not published with fixed test keys. |
| `agt_cedar_v1_synthetic.json` | microsoft/agent-governance-toolkit | **SYNTHETIC** | Test keypair generated in-process. No real-world published sample with known public key was available at time of authoring (2026-06-15). The AGT project (https://github.com/microsoft/agent-governance-toolkit) generates keys per deployment; no shipped fixed-key test vectors were found in the public repo. |

## Signing scope

### Signet (signet-v4)

Signet signs with Ed25519 over RFC 8785 JCS of the receipt body **excluding** the `sig` and `id` fields. The signable object is:

```json
{"action": {...}, "nonce": "...", "policy": {...}, "signer": {...}, "ts": "...", "v": 1}
```

The `id` field is derived from the signature (not part of the signed scope). Public key format: `ed25519:<base64>`. Signature format: `ed25519:<base64>`. Hash chaining is provided by the surrounding `AuditRecord` wrapper (`prev_hash`, `record_hash`), not inside the Receipt itself.

Ref: https://github.com/Prismer-AI/signet/blob/main/crates/signet-core/src/sign.rs

### AGT (agt-cedar-v1)

AGT signs with Ed25519 over `json.dumps({...fields...}, sort_keys=True, separators=(",", ":"))` of `{agent_did, args_hash, cedar_decision, cedar_policy_id, receipt_id, timestamp, tool_name[, parent_receipt_hash, session_id]}`. The `signature` and `signer_public_key` fields are excluded from the signed scope. Public key format: hex (64 chars). Signature format: hex. Hash chaining: `parent_receipt_hash` = `sha256hex(canonical_payload_of_previous_receipt)`.

Ref: https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agentmesh-integrations/mcp-receipt-governed/mcp_receipt_governed/receipt.py
