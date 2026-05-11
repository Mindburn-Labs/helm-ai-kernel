# HELM Launch Demo

Welcome to the 5-minute HELM OSS Launch Demo. This suite demonstrates HELM as a **Fail-Closed Execution Firewall** for your agentic systems.

## Prerequisites

- [jq](https://stedolan.github.io/jq/) installed (for pretty-printing JSON outputs)
- A working Go environment (for building the binary)

## The Scenario

You have an AI agent that is integrated into your backend. It can read tickets, process refunds, and run shell commands.
We will place HELM in front of it using the `agent.boundary.v1` policy.

Our policy enforces:
- `read-ticket` → **ALLOW**
- `export-customer-list` → **DENY**
- `dangerous-shell` → **DENY**
- `large-refund` → **ESCALATE** (Requires explicit human approval artifact)

## Running the Demo

Run the local demo script which builds HELM, starts the server with our strict policy, executes the 4 payloads, and outputs the cryptographically signed receipts:

```bash
./scripts/launch/demo-local.sh
```

## What Happens?

1. **ALLOW**: The `read-ticket` payload evaluates to `ALLOW` because it is an explicitly allowed capability.
2. **DENY**: The `export-customer-list` and `dangerous-shell` payloads evaluate to `DENY` with reason `PDP_DENY` because they are explicitly blocked at the boundary.
3. **ESCALATE**: The `large-refund` payload evaluates to `DENY` with reason `MISSING_REQUIREMENT`. This is HELM escalating the action—it requires a `human_approval` cryptographic artifact to proceed.
4. **Receipts**: Every single decision is logged as a causally-linked, signed receipt in the local SQLite database. Even the denied actions leave an immutable trail.

## Further Demos

- **`demo-proof.sh`**: Shows how to extract and offline-verify the tamper-proof evidence chain.
- **`demo-mcp.sh`**: Demonstrates the MCP interceptor capabilities.
- **`demo-openai-proxy.sh`**: Shows how to route standard OpenAI SDK calls through HELM's enforcement layer.
- **`demo-console.sh`**: Walkthrough of the local governance console.
