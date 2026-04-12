# @mindburn/helm-anthropic

HELM governance adapter for [Anthropic Claude TypeScript SDK](https://github.com/anthropics/anthropic-sdk-typescript) -- tool_use governor.

Every tool_use block goes through HELM's governance plane: policy-evaluated, receipt-producing, fail-closed by default.

## Install

```bash
npm install @mindburn/helm-anthropic
```

## Quick Start

```ts
import { HelmAnthropicGovernor } from '@mindburn/helm-anthropic';

const governor = new HelmAnthropicGovernor({
  baseUrl: 'http://localhost:8080',
  principal: 'my-claude-agent',
});

// Govern tool_use blocks from Claude's response before executing them
const response = await anthropic.messages.create({ model: 'claude-sonnet-4-20250514', ... });
for (const block of response.content) {
  if (block.type === 'tool_use') {
    await governor.governToolUse(block);
  }
}

// Inspect receipts
console.log(governor.getReceipts());
```

## Features

- **tool_use governor** -- intercept and govern Claude tool_use content blocks
- **Fail-closed** -- denied tools never execute (configurable)
- **Receipts** -- cryptographic proof chain for every tool call
- **Lamport clocks** -- causal ordering across tool executions
- **Zero runtime deps** -- uses native fetch, no Anthropic SDK import required

## License

Apache-2.0
