---
title: Use The OpenAI-Compatible Proxy
last_reviewed: 2026-09-24
---

# Use The OpenAI-Compatible Proxy

Keep an OpenAI-shaped client interface while HELM makes the boundary decision
and emits receipts.

<!-- quantum_posture: this page describes optional classical Ed25519 proxy receipt signatures and adds no post-quantum cryptographic control. -->

## 1. Start The Proxy

The proxy builds its own Guardian and receipt log. It does not call
`helm-ai-kernel serve`, so no server needs to run beside it.

```bash
python3 scripts/launch/mock-openai-upstream.py --port 19090
helm-ai-kernel proxy \
  --upstream http://127.0.0.1:19090/v1 \
  --port 9090 \
  --receipts-dir ./helm-receipts
```

The proxy binds `127.0.0.1`. It reads `HELM_PROXY_BIND_ADDR`, not the
`HELM_BIND_ADDR` that `serve` uses, and refuses a non-loopback bind unless
`HELM_PROXY_TOKEN` is set. With a token, every route except `/health` and
`/healthz` requires `Authorization: Bearer <token>` (set it as the client's
`OPENAI_API_KEY`); the proxy strips it and forwards `--api-key` upstream.
`mcp serve --transport http` follows the same rule with `HELM_MCP_BIND_ADDR`
and refuses `--auth none` off loopback.

## 2. Point The Client At HELM

```bash
export OPENAI_BASE_URL=http://127.0.0.1:9090/v1
export OPENAI_API_KEY=local-dev-key
```

## 3. Verify Denial

```bash
./scripts/launch/demo-openai-proxy.sh
```

The script starts its own mock upstream and proxy on separate ports. Expected
denial responses include `X-Helm-Status: DENIED` and `X-Helm-Receipt-ID`.

## What The Proxy Governs

- Tool calls are decided by the Guardian against `--policy` (a serve policy
  file). Without `--policy`, every tool call is denied.
- Only OpenAI Chat Completions tool calls (`choices[].message.tool_calls`) are
  parsed. When a request offers tools, any other response shape is withheld
  with `X-Helm-Status: UNGOVERNABLE_RESPONSE`.
- A request that offers tools must send `"stream": false`. A streamed request
  with tools is refused with `400` and `PROXY_STREAMING_TOOLS_REFUSED` before
  it reaches the upstream. Streams without tools pass through unreceipted.
- `--max-iterations` and `--max-wallclock` count per session, named by an
  `X-Helm-Session-ID` UUID header or, without one, the request's correlation ID.
- `--daily-limit` and `--monthly-limit` are refused: the proxy sees token
  counts, not prices.

## Receipts And Signatures

- Each governed response appends one receipt to a hash-chained JSONL file under
  `--receipts-dir`; the proxy serves the file at `/helm/receipts`.
- Receipts are unsigned unless the proxy starts with `--sign <seed>`. The
  commands on this page do not pass it. The seed is a 32-byte Ed25519 seed in
  hex or base64; any other string is hashed into one, with a warning.
- With `--sign`, each receipt carries an Ed25519 signature over
  `<receipt_id>:<output_hash>:<status>:<lamport_clock>`, also returned as
  `X-Helm-Signature`. No shipped command verifies that signature.

## Source Truth

- `core/cmd/helm-ai-kernel/proxy_cmd.go`
- `scripts/launch/demo-openai-proxy.sh`
- `scripts/launch/mock-openai-upstream.py`
- `docs/INTEGRATIONS/openai_baseurl.md`
