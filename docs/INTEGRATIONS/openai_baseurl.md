---
title: OpenAI-Compatible Proxy Integration
last_reviewed: 2026-06-29
---

# OpenAI-Compatible Proxy Integration

Use this path when an app already speaks the OpenAI chat-completions API and
you want requests to cross a local HELM boundary before reaching an upstream.

## Quick Setup

Start the HELM boundary:

```bash
helm-ai-kernel serve --policy ./release.high_risk.v3.toml
```

Start a mock upstream and the proxy:

```bash
python3 scripts/launch/mock-openai-upstream.py --port 19090
helm-ai-kernel proxy \
  --upstream http://127.0.0.1:19090/v1 \
  --port 9090 \
  --receipts-dir ./helm-receipts
```

Point the client at:

```text
http://127.0.0.1:9090/v1
```

## Environment Setup

```bash
export OPENAI_BASE_URL=http://127.0.0.1:9090/v1
export OPENAI_API_KEY=local-dev-key
```

## cURL Request

```bash
curl -sS http://127.0.0.1:9090/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer local-dev-key' \
  -d '{"model":"helm-local-mock","messages":[{"role":"user","content":"hello through HELM"}]}'
```

## OpenAI Agents SDK

```python
from openai import AsyncOpenAI
from agents import Agent, Runner, set_default_openai_api, set_default_openai_client

set_default_openai_client(
    AsyncOpenAI(base_url="http://127.0.0.1:9090/v1", api_key="local-dev-key"),
    use_for_tracing=False,
)
set_default_openai_api("chat_completions")

agent = Agent(name="governed", instructions="Route tool effects through HELM.")
result = await Runner.run(agent, "summarize the current task")
```

## Verify Denial Behavior

The mock upstream has a deny fixture. Request model `helm-local-tool-fixture`
and the proxy must stop the response before executable `tool_calls` reach the
caller.

```bash
curl -sS -D headers.txt -o denied.json -w '%{http_code}\n' \
  http://127.0.0.1:9090/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer local-dev-key' \
  -d '{"model":"helm-local-tool-fixture","messages":[{"role":"user","content":"call a denied tool"}]}'
```

Expected result:

- HTTP status is `403`.
- `X-Helm-Status` is `DENIED`.
- `X-Helm-Receipt-ID` is present.
- `denied.json` contains a HELM error body and no executable `tool_calls`.

Run the maintained proof:

```bash
./scripts/launch/demo-openai-proxy.sh
```

## Receipt Headers

| Header | Meaning |
| --- | --- |
| `X-Helm-Decision-ID` | Decision identifier emitted by the HELM boundary |
| `X-Helm-Receipt-ID` | Receipt identifier for the governed request |
| `X-Helm-Reason-Code` | ALLOW, DENY, or ESCALATE reason context |
| `X-Helm-Output-Hash` | Hash of the governed output |
| `X-Helm-Status` | Governance status for the proxied response |
| `X-Helm-Correlation-ID` | Trace and receipt correlation value |

Some clients hide response headers. In that case, inspect the receipt stream or
use a HELM SDK path that exposes receipt metadata.

## Source Truth

- `core/cmd/helm-ai-kernel/proxy_cmd.go`
- `core/cmd/helm-ai-kernel/server_cmd.go`
- `core/cmd/helm-ai-kernel/serve_policy.go`
- `core/cmd/helm-ai-kernel/receipt_routes.go`
- `scripts/launch/demo-openai-proxy.sh`
- `scripts/launch/mock-openai-upstream.py`
- `examples/python_openai_baseurl/`
- `examples/ts_openai_baseurl/`
- `examples/js_openai_baseurl/`
