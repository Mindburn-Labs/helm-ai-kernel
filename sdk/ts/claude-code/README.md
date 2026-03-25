# @mindburn/helm-claude-code

HELM governance adapter for Anthropic Claude Code — MCP-native tool governance.

Every tool call goes through HELM's governance plane: policy-evaluated, receipt-producing, fail-closed by default.

## Install

```bash
npm install @mindburn/helm-claude-code
```

## Usage

```ts
import { HelmToolProxy } from '@mindburn/helm-claude-code';

const proxy = new HelmToolProxy({ baseUrl: 'http://localhost:8080' });

// Wrap MCP tools
const governed = proxy.wrapTools(mcpTools);

// Or govern individual calls
const result = await proxy.executeGoverned('file_write', { path, content }, executor);

// Convert to Anthropic API format
const anthropicTools = proxy.toAnthropicTools(mcpTools);

// Get receipts
console.log(proxy.getReceipts());
```

## Features

- **MCP native** — works with MCP ToolDefinition format
- **Anthropic conversion** — `toAnthropicTools()` for Claude messages API
- **Fail-closed** — denied tools never execute (configurable)
- **Receipts** — cryptographic proof of every tool call
- **Lamport clocks** — causal ordering of tool executions

## License

Apache-2.0
