# HELM x Nostr Web-of-Trust (Python)

Identity bridge that maps Nostr pubkeys to HELM trust scores.

## Install

```bash
pip install helm
```

## Quick Integration

```python
from helm_nostr_wot import NostrWoTBridge

bridge = NostrWoTBridge(helm_url="http://localhost:8080")

# Resolve trust score for a Nostr pubkey
score = bridge.resolve_trust("ab12cd34...")
print(f"Trust: {score.score}, Confidence: {score.confidence}")

# Verify a Nostr event through HELM governance
result = bridge.verify_event({
    "id": "event-001",
    "pubkey": "ab12cd34...",
    "kind": 1,
    "content": "Hello world",
    "tags": [],
})
print(f"Verdict: {result.verdict}")  # ALLOW or DENY

# Export evidence
bridge.export_evidence_pack("evidence.tar")
```

## Configuration

| Parameter                  | Default                | Description                              |
| -------------------------- | ---------------------- | ---------------------------------------- |
| `helm_url`                 | `http://localhost:8080` | HELM kernel URL                         |
| `fail_closed`              | `True`                 | Zero trust on HELM errors                |
| `default_principal_prefix` | `nostr:`               | Prefix for Nostr-to-HELM principal maps  |
| `metadata`                 | `None`                 | Global metadata for receipts             |

## Tests

```bash
cd sdk/python && pytest nostr_wot/ -v
```

## License

Apache-2.0
