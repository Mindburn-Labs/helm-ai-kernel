# @mindburn/helm-langgraph

HELM governance adapter for [LangGraph.js](https://langchain-ai.github.io/langgraphjs/) -- node execution governor.

Every graph node execution goes through HELM's governance plane: policy-evaluated, receipt-producing, fail-closed by default.

## Install

```bash
npm install @mindburn/helm-langgraph
```

## Quick Start

```ts
import { HelmLangGraphGovernor } from '@mindburn/helm-langgraph';
import { StateGraph } from '@langchain/langgraph';

const governor = new HelmLangGraphGovernor({
  baseUrl: 'http://localhost:8080',
  principal: 'my-langgraph-agent',
});

// Wrap a graph node function with governance
const graph = new StateGraph({ channels: { messages: { value: [] } } });
graph.addNode('search', governor.governNode('search', async (state) => {
  return { messages: [...state.messages, 'search result'] };
}));

// Inspect receipts
console.log(governor.getReceipts());
```

## Features

- **Node governor** -- wrap LangGraph.js node functions with HELM governance
- **Tool governor** -- govern individual tool calls within graph nodes
- **Fail-closed** -- denied nodes never execute (configurable)
- **Receipts** -- cryptographic proof chain for every node execution
- **Lamport clocks** -- causal ordering across node executions
- **Zero runtime deps** -- uses native fetch, no LangGraph import required

## License

Apache-2.0
