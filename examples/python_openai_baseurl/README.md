# Python — OpenAI base_url Example

Shows HELM integration with the OpenAI Python SDK using a single `base_url` swap.

## Prerequisites

- HELM running at `http://localhost:8080` (`docker compose up -d`)
- Python 3.9+

## Run

```bash
cd examples/python_openai_baseurl
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

The example prints sections for chat completions, evidence export and
verification, conformance, and health. The exact verdict, reason code, byte
count, and version depend on the policy and HELM server you run locally.
