# @mindburn/helm-llamaindex-ts

HELM governance adapter for [LlamaIndex TypeScript](https://ts.llamaindex.ai) -- query engine, retriever, and tool governance.

Every query and tool call goes through HELM's governance plane: policy-evaluated, receipt-producing, fail-closed by default.

## Install

```bash
npm install @mindburn/helm-llamaindex-ts
```

## Usage: Query Engine Governance

Wrap query engine calls with `HelmQueryEngineWrapper`:

```ts
import { HelmQueryEngineWrapper } from '@mindburn/helm-llamaindex-ts';
import { VectorStoreIndex } from 'llamaindex';

const wrapper = new HelmQueryEngineWrapper({
  baseUrl: 'http://localhost:8080',
  principal: 'rag-agent',
});

// Build your index as usual
const index = await VectorStoreIndex.fromDocuments(documents);
const queryEngine = index.asQueryEngine();

// Every query is now governed by HELM
const response = await wrapper.governedQuery(queryEngine, 'What is HELM?');
console.log(response.response);

// Inspect receipts
console.log(wrapper.getReceipts());
```

## Usage: Retriever Governance

Govern retriever calls:

```ts
const retriever = index.asRetriever({ similarityTopK: 3 });
const nodes = await wrapper.governedRetrieve(retriever, 'HELM architecture');
```

## Usage: Tool Governance

Wrap tools used with LlamaIndex agents:

```ts
import { HelmToolSpec } from '@mindburn/helm-llamaindex-ts';

const spec = new HelmToolSpec({
  baseUrl: 'http://localhost:8080',
});

const governedSearch = spec.governTool('web-search', async (query: string) => {
  return await searchEngine.search(query);
});

// Or govern a batch
const governedTools = spec.governTools([
  { name: 'search', fn: searchFn },
  { name: 'calculator', fn: calcFn },
]);
```

## Features

- **Query engine governance** -- `governedQuery()` wraps any LlamaIndex query engine
- **Retriever governance** -- `governedRetrieve()` wraps LlamaIndex retrievers
- **Tool governance** -- `HelmToolSpec` wraps individual tool functions
- **Fail-closed** -- denied queries/tools never execute (configurable)
- **Receipts** -- cryptographic proof chain for every operation
- **Lamport clocks** -- causal ordering across operations
- **Zero runtime deps** -- uses native fetch, no LlamaIndex import required

## Configuration

| Option            | Default              | Description                        |
| ----------------- | -------------------- | ---------------------------------- |
| `baseUrl`         | required             | HELM kernel URL                    |
| `apiKey`          | -                    | HELM API key                       |
| `principal`       | `llamaindex-agent`   | Identity for governance evaluation |
| `failClosed`      | `true`               | Deny on HELM errors                |
| `collectReceipts` | `true`               | Collect receipt chain              |
| `timeout`         | `30000`              | Request timeout (ms)               |

## License

Apache-2.0
