---
title: OpenAI Proxy
last_reviewed: 2026-07-01
---

# OpenAI Proxy

<!-- quantum_posture: this page mentions optional classical Ed25519 proxy receipt signatures and adds no post-quantum cryptographic control. -->

Use the OpenAI-compatible proxy when an app already speaks the OpenAI API shape
and can set a custom base URL. HELM stays local, forwards the request, then holds
every tool call in the response for a Guardian decision: a denied call never
reaches the client, and each decision gets a receipt. A stream that declares
tools is refused, and a stream without tools passes through without a receipt
(`controls.yaml` CTL-031).

## Start Locally

Build the CLI:

```bash
make build
```

Start a local mock upstream and proxy. The proxy builds its own Guardian and
receipt log and does not call `helm-ai-kernel serve`:

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

Started this way the proxy denies every tool call: tool calls are allowed only
by a serve policy file passed with `--policy`. Its receipts are hash-chained and
unsigned; `--sign <seed>` adds an Ed25519 signature to each receipt
([proxy guide](../guides/use-openai-compatible-proxy.md#receipts-and-signatures)).

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
| `X-Helm-Decision-ID` | Guardian decision, present when the response carried a tool call |
| `X-Helm-Receipt-ID` | Receipt for the governed response |
| `X-Helm-Reason-Code` | Reason code of a blocked response |
| `X-Helm-Status` | Boundary status, for example `APPROVED` or `DENIED` |

If a client hides headers, read the proxy's receipt log:

```bash
curl -sS http://127.0.0.1:9090/helm/receipts
```

Run the maintained local proof:

```bash
./scripts/launch/demo-openai-proxy.sh
```

The proxy is a local request boundary. A successful model response is not proof
that the request crossed HELM unless a receipt or response metadata proves it.
