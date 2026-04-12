# @mindburn/helm-dify

HELM governance adapter for [Dify](https://dify.ai) platform API -- tool call governor.

Every Dify tool/API call goes through HELM's governance plane: policy-evaluated, receipt-producing, fail-closed by default.

## Install

```bash
npm install @mindburn/helm-dify
```

## Quick Start

```ts
import { HelmDifyGovernor } from '@mindburn/helm-dify';

const governor = new HelmDifyGovernor({
  baseUrl: 'http://localhost:8080',
  principal: 'my-dify-workflow',
});

// Govern a Dify tool call before execution
await governor.governToolCall({
  toolName: 'search_knowledge',
  inputs: { query: 'HELM governance' },
  workflowId: 'wf-123',
});

// Inspect receipts
console.log(governor.getReceipts());
```

## Features

- **Tool call governor** -- intercept and govern Dify platform API tool calls
- **Workflow governance** -- govern entire Dify workflow executions
- **Fail-closed** -- denied calls never execute (configurable)
- **Receipts** -- cryptographic proof chain for every tool call
- **Lamport clocks** -- causal ordering across tool executions
- **Zero runtime deps** -- uses native fetch, no Dify SDK required

## License

Apache-2.0
