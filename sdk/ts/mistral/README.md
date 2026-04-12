# @mindburn/helm-mistral

HELM governance adapter for [Mistral AI TypeScript SDK](https://github.com/mistralai/client-ts) -- function call governor.

Every tool call goes through HELM's governance plane: policy-evaluated, receipt-producing, fail-closed by default.

## Install

```bash
npm install @mindburn/helm-mistral
```

## Quick Start

```ts
import { HelmMistralGovernor } from '@mindburn/helm-mistral';

const governor = new HelmMistralGovernor({
  baseUrl: 'http://localhost:8080',
  principal: 'my-mistral-agent',
});

// Govern a Mistral function call before execution
const receipt = await governor.governFunctionCall({
  name: 'search_web',
  arguments: '{"query": "HELM governance"}',
});

// Inspect receipts
console.log(governor.getReceipts());
```

## Features

- **Function call governor** -- intercept and govern Mistral AI function calls
- **Fail-closed** -- denied calls never execute (configurable)
- **Receipts** -- cryptographic proof chain for every tool call
- **Lamport clocks** -- causal ordering across tool executions
- **Zero runtime deps** -- uses native fetch, no Mistral SDK import required

## License

Apache-2.0
