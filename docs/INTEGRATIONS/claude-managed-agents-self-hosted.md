# Claude Managed Agents Self-Hosted Workers

> Status: compatible / preview. This profile certifies the customer-controlled
> worker execution boundary. It does not certify Anthropic orchestration
> internals, and MCP tunnels remain research-preview until live evidence packs
> are published.

HELM treats Claude Managed Agents as the orchestration and model layer. HELM is
the authority boundary around local tool execution, filesystem access, egress,
MCP tool calls, and offline-verifiable receipts.

Anthropic's self-hosted sandbox model keeps orchestration on Anthropic's side
while moving tool execution into infrastructure controlled by the customer:
<https://platform.claude.com/docs/en/managed-agents/self-hosted-sandboxes>.
Anthropic's security model makes worker image verification, egress controls,
tool isolation, key storage, and retention the customer's responsibility:
<https://platform.claude.com/docs/en/managed-agents/self-hosted-sandboxes-security>.

## Required HELM posture

- Run the self-hosted worker behind `core/pkg/connectors/sandbox/claudemanaged`.
- Pin the worker image with a `sha256:` digest.
- Pin downloaded Managed Agent skills with a `sha256:` manifest hash.
- Keep `ANTHROPIC_ENVIRONMENT_KEY` in a secrets manager.
- Never place an organization-scoped `ANTHROPIC_API_KEY` on the worker host.
- Enforce egress at the worker/VPC boundary before permitting tool execution.
- Emit `managed_agent_execution_receipt.v1` and sandbox receipt fragments.

## MCP tunnels

Anthropic MCP tunnels provide outbound-only private connectivity and are a
research-preview feature:
<https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/overview>.

For HELM, tunnel hostnames must route to the HELM MCP Gateway. Raw routing from
Anthropic directly to internal MCP servers is a denial condition because it
bypasses schema pinning, OAuth scope checks, quarantine/rugpull checks,
argument hashing, and `ExecutionBoundaryRecord` sealing.

## Validation

```bash
cd core
go test ./pkg/connectors/sandbox/claudemanaged -count=1
go test ./pkg/conformance/sandbox ./pkg/mcp ./pkg/contracts/... -count=1
cd ..
make verify-fixtures
```
