# HELM SDK - TypeScript

Typed TypeScript client for the retained HELM kernel API.

## Local Install

```bash
cd sdk/ts
npm ci
npm run build
```

Package metadata declares version `0.7.2` in `package.json`; this README does
not claim that a registry package has been published.

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

const client = new HelmClient({
  baseUrl: "http://127.0.0.1:7714",
  apiKey: process.env.HELM_ADMIN_API_KEY,
  tenantId: "tenant-a",
  principalId: "operator-a",
});
const decision = await client.evaluateDecision({
  action: "read-ticket",
  resource: "ticket:123",
});
console.log(decision.verdict); // ALLOW, DENY, or ESCALATE
```

`evaluateDecision` requires API key, tenant ID, and principal ID. Set
`workspaceId` whenever scoped emergency-stop fencing or runtime policy snapshot
authority is enabled. It sends `X-Helm-Workspace-ID`, which must match
server-owned `HELM_RUNTIME_WORKSPACE_ID`; otherwise `POST /api/v1/evaluate`
fails closed with `403`. The request body accepts only `action`, `resource`,
and optional `context`; body identity and legacy evaluator payloads are retired.

Run the first-class local example with `make sdk-examples-smoke` or directly
from `examples/ts_sdk/`.

## Agent Framework Adapters

The TypeScript SDK includes lightweight adapter helpers for LangGraph, CrewAI, OpenAI Agents SDK, PydanticAI, and LlamaIndex tool-call events. These helpers normalize each framework event into a HELM governance request and submit it through `chatCompletionsWithReceipt`, preserving the kernel receipt returned in `X-Helm-*` headers.

They use `chatCompletionsWithReceipt`, not `/api/v1/evaluate`, so they are not
direct evaluator-contract conformance evidence.

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

## Release Notes

`0.7.2` is the release-hardening patch with the retained OpenAPI client surface and protobuf message bindings.
