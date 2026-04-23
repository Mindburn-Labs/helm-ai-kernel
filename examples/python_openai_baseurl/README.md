# Python — OpenAI base_url Example

Shows HELM integration with the OpenAI Python SDK using a single `base_url` swap.

## Prerequisites

- HELM running at `http://localhost:8080` (`docker compose up -d`)
- Python 3.9+

## Run

```bash
pip install httpx
python main.py
```

## What It Does

1. Sends a chat completion through HELM proxy
2. Exports an EvidencePack
3. Verifies the evidence offline
4. Runs L2 conformance
5. Checks health

## Expected Output

```
=== Chat Completions ===
Denied: DENY_TOOL_NOT_FOUND — Tool not found: ...

=== Evidence ===
Exported 1234 bytes
Verification: PASS

=== Conformance ===
Verdict: PASS, Gates: 12, Failed: 0

=== Health ===
Status: {'status': 'ok', 'version': '0.1.0'}
```
