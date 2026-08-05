# HELM SDK - TypeScript

Typed TypeScript client for the retained HELM kernel API.

## Local Install

```bash
cd sdk/ts
npm ci
npm run build
```

Package metadata identifies source target `0.8.0`; this README does not claim
that a registry package has been published.

## Local Development

```bash
npm ci
npm test -- --run
npm run build
```

## Source Layout

- `src/client.ts` is the hand-maintained HTTP wrapper.
- `src/types.gen.ts` contains OpenAPI-derived model types.
- `src/adapters/agent-frameworks.ts` contains the source-backed framework
  adapter helpers.
- Protobuf bindings under `src/generated/` are generated from
  `protocols/proto/` with `ts-proto` when codegen has been run.

## Usage

```ts
import { HelmClient } from "@mindburn/helm-ai-kernel";

const client = new HelmClient({ baseUrl: "http://127.0.0.1:7714" });
const decision = await client.evaluateDecisionV5({
  tool: "read-ticket",
  effect_level: "ticket:123",
  session_id: "example-session",
});
console.log(decision.verdict); // ALLOW or DENY
```

`tool`, `effect_level`, and `session_id` must all be non-blank for
`evaluateDecisionV5`. The legacy `evaluateDecision` method remains available
for existing direct-daemon callers. The authenticated principal, not a body
`principal`, is recorded on the receipt.

Run the first-class local example with `make sdk-examples-smoke` or directly
from `examples/ts_sdk/`.

## Agent Framework Adapters

The TypeScript SDK includes lightweight adapter helpers for Codex, Claude Code,
Hermes, LangChain/LangGraph, AutoGen, CrewAI, OpenAI Agents SDK, Semantic
Kernel, PydanticAI, LlamaIndex, LiteLLM, n8n, Zapier-style webhooks, and raw MCP
tool-call events. These helpers normalize each framework event into a HELM
governance request and submit it through `chatCompletionsWithReceipt`,
preserving the kernel receipt returned in `X-Helm-*` headers. Frameworks
without a named adapter can use the raw MCP adapter; no model-specific policy
path is required.

```ts
import { HelmClient, createAgentFrameworkAdapter, fromOpenAIAgentsToolCall } from "@mindburn/helm-ai-kernel";

const helm = new HelmClient({ baseUrl: "http://127.0.0.1:7714" });
const adapter = createAgentFrameworkAdapter(helm, { model: "helm-governance" });

const result = await adapter.submit(
  fromOpenAIAgentsToolCall({
    id: "call_123",
    function: {
      name: "crm.update_customer",
      arguments: '{"customer_id":"cus_123","tier":"enterprise"}',
    },
  }),
);

console.log(result.governance.receiptId);
```

The helpers do not add Microsoft Agent Governance Toolkit as a dependency and
do not claim Microsoft certification. They cover the same framework families
so HELM can sit behind AGT or another orchestrator as the receipt-bearing
enforcement boundary.

## Execution Boundary Methods

The client also exposes methods for proof-bearing boundary operations:
evidence envelope manifests, boundary records and checkpoints, conformance
vectors, MCP quarantine and authorization profiles, sandbox profiles and
grants, authz snapshots, approvals, budgets, telemetry export, and coexistence
capabilities. These methods keep external envelopes, MCP quarantine decisions,
and sandbox grants attached to HELM-native receipts and EvidencePacks.

## Source target

The SDK sends canonical typed evaluation requests and returns receipt-bearing
V5 responses. Verify registry evidence before relying on a pinned package.
