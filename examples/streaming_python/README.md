# Streaming Governance Example (Python)

Demonstrates token-by-token LLM streaming through HELM's governed proxy using the standard OpenAI Python SDK.

## How It Works

1. Your application uses the standard OpenAI SDK with `base_url` pointed at the HELM proxy
2. HELM evaluates the request through the Guardian pipeline (6 gates: Freeze, Context, Identity, Egress, Threat, Delegation)
3. If **allowed**, HELM forwards to the upstream LLM and streams SSE tokens back
4. If **denied**, the stream never starts (fail-closed)
5. HELM captures the full output hash for receipt generation after the stream completes

```
Client ──POST /v1/chat/completions──> HELM Proxy ──Guardian eval──> Decision
                                                       |
                                            ALLOW: Forward to LLM
                                                       |
                                  LLM ──SSE tokens──> HELM ──SSE tokens──> Client
                                                       |
                                                Capture output hash
                                                       |
                                                Generate Receipt
                                                       |
                                                ProofGraph node
```

## Prerequisites

- HELM binary (`make build` from repo root)
- Python 3.9+
- An OpenAI API key (or any OpenAI-compatible provider)

## Setup

```bash
# Terminal 1: Start HELM proxy
helm onboard --yes
helm proxy --upstream https://api.openai.com/v1

# Terminal 2: Run the example
cd examples/streaming_python
pip install openai
export OPENAI_API_KEY=sk-...
python main.py
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HELM_PROXY_URL` | `http://localhost:9090/v1` | HELM proxy endpoint |
| `OPENAI_API_KEY` | (required) | API key forwarded to upstream |
| `OPENAI_MODEL` | `gpt-4o-mini` | Model to use for completions |

## What the Example Demonstrates

1. **Basic streaming** -- A simple chat completion streamed token-by-token through the governed proxy
2. **Streaming with tool calls** -- Tool definitions are evaluated by HELM policy; denied tools never reach the upstream LLM

## Governance Artifacts

After each streaming request, HELM produces:

| Artifact | Description |
|----------|-------------|
| `DecisionRecord` | Signed ALLOW or DENY verdict for the request |
| `Receipt` | Signed binding of input hash to output hash |
| `ProofGraph node` | Causal DAG entry linking decision to receipt |

Export and verify:

```bash
helm export --evidence ./data/evidence
helm verify ./data/evidence
```

## Expected Output

```
============================================================
HELM Streaming Governance Example
Proxy: http://localhost:9090/v1
============================================================

--- Example 1: Basic Streaming ---

A proof graph is a directed acyclic graph (DAG) that captures the
causal relationships between decisions, actions, and their evidence.
Each node represents a cryptographically signed event, and edges
encode temporal ordering via Lamport timestamps. This structure
enables offline verification of an entire decision chain without
trusting any single party.

  Characters: 312
  Time: 1.84s

--- Example 2: Streaming with Tool Calls ---

  Tool calls requested: 1

--- Governance Artifacts ---

After streaming, HELM has generated:
  1. DecisionRecord  - Signed ALLOW/DENY verdict for the request
  2. Receipt         - Signed binding of input hash -> output hash
  3. ProofGraph node - Causal DAG entry linking decision to receipt

Export evidence:  helm export --evidence ./data/evidence
Verify receipts:  helm verify ./data/evidence
```
