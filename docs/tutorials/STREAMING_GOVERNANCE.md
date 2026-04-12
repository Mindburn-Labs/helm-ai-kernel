# Streaming Governance with HELM

This tutorial explains how HELM governs streaming (SSE) LLM responses, ensuring every token-by-token completion is covered by a fail-closed policy evaluation, a signed receipt, and a proof graph entry.

## Why Streaming Governance Matters

Modern LLM applications stream responses token-by-token using Server-Sent Events (SSE). Without governance, streamed completions bypass policy enforcement entirely -- there is no decision record, no receipt, and no audit trail.

HELM solves this by intercepting the SSE stream at the proxy layer. The governance evaluation happens **before** the first token arrives. If policy denies the request, the stream never starts.

## Architecture

```
                          HELM Proxy (port 9090)
                         +----------------------+
                         |                      |
Client ──POST stream=true──> Parse request      |
                         |      |               |
                         |  Guardian Pipeline   |
                         |  (6 gates)           |
                         |      |               |
                         |  DENY ──> 403 + DecisionRecord (stream never starts)
                         |      |               |
                         |  ALLOW               |
                         |      |               |
                         |  Forward to upstream  |
                         |      |               |
Upstream LLM <───────────── POST stream=true    |
                         |                      |
Upstream LLM ──SSE tokens──> Buffer + forward   |
                         |      |               |
Client <──SSE tokens──────── Stream to client   |
                         |      |               |
Upstream LLM ──[DONE]────── Finalize            |
                         |      |               |
                         |  Hash full output    |
                         |  Sign Receipt        |
                         |  Append ProofGraph   |
                         |      node            |
                         +----------------------+
```

### Key Properties

1. **Fail-closed**: If any of the 6 Guardian gates (Freeze, Context, Identity, Egress, Threat, Delegation) denies the request, the connection returns an error immediately. No tokens are streamed.

2. **Pre-stream evaluation**: Policy evaluation completes **before** the request is forwarded upstream. This means the latency cost of governance is paid once at the start, not per token.

3. **Output hash capture**: HELM buffers the streamed output to compute a SHA-256 hash after the stream completes. This hash is bound into the signed Receipt.

4. **Transparent to the client**: The client uses the standard OpenAI SDK with only a `base_url` change. No SDK modifications, no custom protocols.

## Governance Flow in Detail

### Step 1: Request Interception

When a client sends `POST /v1/chat/completions` with `"stream": true`, the HELM proxy parses the request body and extracts:

- Model name
- Messages (system, user, assistant)
- Tool definitions (if any)
- Temperature, max_tokens, and other parameters

### Step 2: Guardian Evaluation

The extracted request is evaluated through the 6-gate Guardian pipeline:

| Gate | What It Checks |
|------|----------------|
| **Freeze** | Is the system in maintenance or emergency freeze? |
| **Context** | Does the session context meet policy requirements? |
| **Identity** | Is the caller authenticated and authorized? |
| **Egress** | Is the target model/endpoint permitted by egress policy? |
| **Threat** | Does the request contain threat indicators (prompt injection, data exfiltration)? |
| **Delegation** | Does the caller have delegation authority for this action? |

If any gate returns DENY, a `DecisionRecord` is created with the denial reason and the HTTP response is an error. The stream never starts.

### Step 3: Upstream Forwarding

If all gates return ALLOW, HELM forwards the request to the upstream LLM with `stream: true` preserved. The Authorization header (API key) is passed through.

### Step 4: Token Streaming

As SSE chunks arrive from the upstream LLM, HELM:

1. Forwards each chunk to the client immediately (no buffering delay)
2. Accumulates the full response text for hash computation
3. Tracks token count and timing metadata

### Step 5: Receipt Generation

After the stream completes (the upstream sends `[DONE]`), HELM:

1. Computes the SHA-256 hash of the full concatenated output
2. Creates a `Receipt` binding: `hash(input) -> hash(output)`
3. Signs the Receipt with the node's Ed25519 key
4. Appends a `ProofGraph` node linking the `DecisionRecord` to the `Receipt`

### Step 6: Evidence Export

All governance artifacts are stored locally and can be exported:

```bash
# Export to a content-addressed evidence pack
helm export --evidence ./data/evidence

# Verify the evidence pack offline
helm verify ./data/evidence
```

## Quick Start

### Python

```bash
# Start HELM proxy
helm onboard --yes
helm proxy --upstream https://api.openai.com/v1

# In another terminal
pip install openai
export OPENAI_API_KEY=sk-...
```

```python
import os
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:9090/v1",
    api_key=os.environ["OPENAI_API_KEY"],
)

stream = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "What is HELM?"}],
    stream=True,
)

for chunk in stream:
    if chunk.choices and chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)
```

### TypeScript

```bash
# Start HELM proxy
helm onboard --yes
helm proxy --upstream https://api.openai.com/v1

# In another terminal
npm install openai
```

```typescript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://localhost:9090/v1",
  apiKey: process.env.OPENAI_API_KEY,
});

const stream = await client.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "What is HELM?" }],
  stream: true,
});

for await (const chunk of stream) {
  const token = chunk.choices[0]?.delta?.content || "";
  process.stdout.write(token);
}
```

### cURL (raw SSE)

```bash
curl -N http://localhost:9090/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4o-mini",
    "stream": true,
    "messages": [{"role": "user", "content": "What is HELM?"}]
  }'
```

## Verifying Streaming Receipts

After a streaming request completes, verify the governance artifacts:

```bash
# List recent decisions
helm export --format json ./data/evidence | jq '.decisions[-1]'

# Verify the entire evidence pack
helm verify ./data/evidence
```

Each receipt contains:

| Field | Description |
|-------|-------------|
| `input_hash` | SHA-256 of the canonicalized request (JCS) |
| `output_hash` | SHA-256 of the concatenated streamed output |
| `verdict` | ALLOW (or DENY if the request was blocked) |
| `timestamp` | RFC 3339 timestamp of the decision |
| `signature` | Ed25519 signature over the receipt |
| `node_id` | Identity of the HELM node that governed the request |

## Streaming with Tool Calls

When tool definitions are included in the request, HELM evaluates them against the active policy:

```python
stream = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Search for recent news"}],
    tools=[{
        "type": "function",
        "function": {
            "name": "web_search",
            "parameters": {"type": "object", "properties": {"query": {"type": "string"}}},
        },
    }],
    stream=True,
)
```

If `web_search` is not in the HELM allowlist, the request is denied and the stream never starts. This is the fail-closed guarantee: tools that are not explicitly permitted cannot be invoked, even through streaming.

## Non-streaming Comparison

For comparison, a non-streaming governed request works identically except:

1. The full response arrives as a single JSON object (not SSE chunks)
2. The output hash is computed from the complete response body
3. There is no token-by-token forwarding

The governance guarantees are identical. Streaming adds no security gaps -- the same 6 Guardian gates evaluate the request, and the same Receipt is generated.

## Runnable Examples

- **Python**: [`examples/streaming_python/`](../../examples/streaming_python/)
- **TypeScript**: [`examples/streaming_ts/`](../../examples/streaming_ts/)

## Further Reading

- [Proxy Integration Snippets](../INTEGRATIONS/PROXY_SNIPPETS.md) -- Drop-in proxy snippets for all languages
- [Governance Spec](../GOVERNANCE_SPEC.md) -- Full governance model specification
- [Verification](../VERIFICATION.md) -- How to verify evidence packs and receipts
- [Security Model](../SECURITY_MODEL.md) -- Threat model and security guarantees
