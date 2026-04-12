# @mindburn/helm-flowise

HELM governance adapter for [Flowise](https://flowiseai.com) API -- tool call governor.

Every Flowise chatflow/tool call goes through HELM's governance plane: policy-evaluated, receipt-producing, fail-closed by default.

## Install

```bash
npm install @mindburn/helm-flowise
```

## Quick Start

```ts
import { HelmFlowiseGovernor } from '@mindburn/helm-flowise';

const governor = new HelmFlowiseGovernor({
  baseUrl: 'http://localhost:8080',
  principal: 'my-flowise-chatflow',
});

// Govern a Flowise tool call before execution
await governor.governToolCall({
  toolName: 'search_documents',
  inputs: { query: 'HELM governance' },
  chatflowId: 'cf-123',
});

// Govern an entire chatflow prediction
await governor.governPrediction({
  chatflowId: 'cf-123',
  question: 'What is HELM?',
});

// Inspect receipts
console.log(governor.getReceipts());
```

## Features

- **Tool call governor** -- intercept and govern Flowise tool calls
- **Prediction governor** -- govern entire chatflow predictions
- **Fail-closed** -- denied calls never execute (configurable)
- **Receipts** -- cryptographic proof chain for every tool call
- **Lamport clocks** -- causal ordering across tool executions
- **Zero runtime deps** -- uses native fetch, no Flowise client required

## License

Apache-2.0
