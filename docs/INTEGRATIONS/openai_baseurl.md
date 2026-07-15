---
title: OpenAI Proxy
last_reviewed: 2026-07-01
---

# OpenAI Proxy

Use the OpenAI-compatible proxy when an app already speaks the OpenAI API shape
and can set a custom base URL. HELM stays local, evaluates requests before they
reach the upstream, and writes receipts for allowed, denied, or escalated
decisions.

This page covers the standalone `helm-ai-kernel proxy` sidecar on `:9090`.
It is separate from the tenant-authenticated governed chat route served by
`helm-ai-kernel serve` on `:7714`; see
[`HTTP API`](../reference/http-api.md) for that runtime contract.

## Start Locally

Build the CLI:

```bash
make build
```

Start the local HELM boundary:

```bash
./bin/helm-ai-kernel serve --policy ./release.high_risk.v3.toml
```

Start a local mock upstream and proxy:

```bash
python3 scripts/launch/mock-openai-upstream.py --port 19090

./bin/helm-ai-kernel proxy \
  --upstream http://127.0.0.1:19090/v1 \
  --port 9090 \
  --receipts-dir ./helm-receipts
```

Point OpenAI-shaped clients at:

```text
http://127.0.0.1:9090/v1
```

## Configure A Client

Environment-only setup:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:9090/v1
export OPENAI_API_KEY=local-dev-key
```

Python client example:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:9090/v1",
    api_key="local-dev-key",
)
```

Raw request:

```bash
curl -sS http://127.0.0.1:9090/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer local-dev-key' \
  -d '{"model":"helm-local-mock","messages":[{"role":"user","content":"hello through HELM"}]}'
```

## Prove The Boundary

The response should include HELM metadata when the client exposes headers:

| Header | Meaning |
| --- | --- |
| `X-Helm-Decision-ID` | Decision emitted by HELM |
| `X-Helm-Receipt-ID` | Receipt for the governed request |
| `X-Helm-Reason-Code` | Reason context |
| `X-Helm-Status` | Boundary status |

If a client hides headers, inspect the local receipt stream:

```bash
./bin/helm-ai-kernel receipts tail \
  --agent <agent-id> \
  --server http://127.0.0.1:7714
```

Run the maintained local proof:

```bash
./scripts/launch/demo-openai-proxy.sh
```

The proxy is a local request boundary. A successful model response is not proof
that the request crossed HELM unless a receipt or response metadata proves it.
