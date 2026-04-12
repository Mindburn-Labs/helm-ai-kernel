# @mindburn/helm-haystack

HELM governance adapter for [Haystack](https://haystack.deepset.ai) Node.js client -- pipeline call governor.

Every pipeline component call goes through HELM's governance plane: policy-evaluated, receipt-producing, fail-closed by default.

## Install

```bash
npm install @mindburn/helm-haystack
```

## Quick Start

```ts
import { HelmHaystackGovernor } from '@mindburn/helm-haystack';

const governor = new HelmHaystackGovernor({
  baseUrl: 'http://localhost:8080',
  principal: 'my-haystack-pipeline',
});

// Govern a pipeline component call before execution
await governor.governComponentCall({
  componentName: 'retriever',
  componentType: 'InMemoryBM25Retriever',
  inputs: { query: 'What is HELM?' },
  pipelineName: 'rag-pipeline',
});

// Inspect receipts
console.log(governor.getReceipts());
```

## Features

- **Component governor** -- intercept and govern Haystack pipeline component calls
- **Pipeline governor** -- govern entire pipeline executions
- **Fail-closed** -- denied components never execute (configurable)
- **Receipts** -- cryptographic proof chain for every component call
- **Lamport clocks** -- causal ordering across component executions
- **Zero runtime deps** -- uses native fetch, no Haystack client required

## License

Apache-2.0
