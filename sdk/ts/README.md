# HELM SDK - TypeScript

Typed TypeScript client for the retained HELM kernel API.

## Local Install

```bash
cd sdk/ts
npm ci
npm run build
```

Package metadata identifies source target `0.12.0`; this README does not claim
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
- `src/adapters/native-gateway.ts` contains `NativeGatewayClient`, which sends
  framework tool calls to the effect gateway.
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
const decision = await client.evaluateDecisionV5({
  tool: "read-ticket",
  effect_level: "ticket:123",
  session_id: "example-session",
});
console.log(decision.verdict); // ALLOW, DENY or ESCALATE
```

`/api/v1/evaluate` needs the API key and the tenant and principal the server is
configured for; without them the call throws `HelmApiError` with status 401.

`tool`, `effect_level`, and `session_id` must all be non-blank for
`evaluateDecisionV5`. The legacy `evaluateDecision` method remains available
for existing direct-daemon callers. The authenticated principal, not a body
`principal`, is recorded on the receipt.

Run the first-class local example with `make sdk-examples-smoke` or directly
from `examples/ts_sdk/`.

## Agent Framework Tool Calls

`NativeGatewayClient` sends a framework's tool call to the effect gateway's
native MCP interface (`core/pkg/gateway/mcpserver`). Pass the exact tool name
returned by `listTools`, the framework's arguments and an explicit target. The
gateway decides, dispatches and records the attempt; the client holds no
authority.

```ts
import { NativeGatewayClient } from "@mindburn/helm-ai-kernel";

const gateway = new NativeGatewayClient({
  mcpUrl, // HTTPS, or HTTP on literal loopback only
  episodeToken: getEpisodeToken, // gateway episode bearer, read per request
});

const tools = await gateway.listTools();
const result = await gateway.callEffect({
  toolName: "github_repository_get",
  target: "github.com/owner/repository",
  arguments: { schema: "helm.github.repository.get.v1", branch: "main" },
});

console.log(result.structuredContent.status, result.structuredContent.attempt_id);
if (result.structuredContent.status === "reconciling") {
  await gateway.getAttempt(result.structuredContent.attempt_id!);
}
```

A call is made once and never retried by the client. On failure,
`NativeGatewayError.effectMayHaveOccurred` says whether the request may still
have been dispatched; read the attempt with `getAttempt` instead of calling
again.

The earlier chat-completion helpers (`createAgentFrameworkAdapter` and the
`from*ToolCall` normalizers) were removed. They sent the tool call as chat
text, so nothing evaluated the named tool.

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
