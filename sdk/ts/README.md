# HELM SDK — TypeScript

Typed TypeScript client for the retained HELM kernel API.

## Install

```bash
npm install @mindburn/helm
```

Published package version is `0.4.0` and is declared in `package.json`.

## Local Development

```bash
npm ci
npm test -- --run
npm run build
```

## Generated Sources

The HTTP wrapper uses OpenAPI-derived types. Protobuf bindings under `src/generated/` are generated from `protocols/proto/` with `ts-proto`.

## Usage

```ts
import { HelmApiError, HelmClient } from "@mindburn/helm";

const client = new HelmClient({ baseUrl: "http://localhost:8080" });

try {
  const result = await client.chatCompletions({
    model: "gpt-4",
    messages: [{ role: "user", content: "hello" }],
  });
  console.log(result.choices[0].message.content);
} catch (error) {
  if (error instanceof HelmApiError) {
    console.log(error.reasonCode);
  }
}
```

## Agent Framework Adapters

The TypeScript SDK includes lightweight adapter helpers for LangGraph, CrewAI, OpenAI Agents SDK, PydanticAI, and LlamaIndex tool-call events. These helpers normalize each framework event into a HELM governance request and submit it through `chatCompletionsWithReceipt`, preserving the kernel receipt returned in `X-Helm-*` headers.

```ts
import { HelmClient, createAgentFrameworkAdapter, fromOpenAIAgentsToolCall } from "@mindburn/helm";

const helm = new HelmClient({ baseUrl: "http://localhost:8080" });
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

The helpers do not add Microsoft Agent Governance Toolkit as a dependency and do not claim Microsoft certification. They cover the same framework families so HELM can sit behind AGT or another orchestrator as the receipt-bearing enforcement boundary.

## Release Notes

`0.4.0` is the cleaned OSS kernel baseline with the retained OpenAPI client surface and protobuf message bindings.
