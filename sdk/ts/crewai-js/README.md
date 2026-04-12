# @mindburn/helm-crewai-js

HELM governance adapter for CrewAI JavaScript/TypeScript -- task and tool governance.

Every task and tool execution goes through HELM's governance plane: policy-evaluated, receipt-producing, fail-closed by default.

## Install

```bash
npm install @mindburn/helm-crewai-js
```

## Usage: Task Governance

Wrap individual task executions with `governTask`:

```ts
import { HelmCrewGovernor } from '@mindburn/helm-crewai-js';

const governor = new HelmCrewGovernor({
  baseUrl: 'http://localhost:8080',
  principal: 'research-crew',
});

// Govern a task execution
const result = await governor.governTask('market-research', async () => {
  const data = await fetchMarketData();
  return analyzeMarket(data);
});

// Inspect receipts
console.log(governor.getReceipts());
```

## Usage: Tool Governance

Wrap tool functions to govern every invocation:

```ts
const governedSearch = governor.governTool('web-search', async (query: string) => {
  return await searchEngine.search(query);
});

// Or govern an entire tool set
const governedTools = governor.governTools([
  { name: 'search', fn: searchFn },
  { name: 'calculate', fn: calcFn },
]);
```

## Features

- **Task governance** -- `governTask()` wraps any async execution with HELM policy evaluation
- **Tool governance** -- `governTool()` / `governTools()` for function-level wrapping
- **Fail-closed** -- denied tasks/tools never execute (configurable)
- **Receipts** -- cryptographic proof chain for every execution
- **Lamport clocks** -- causal ordering across executions
- **Zero runtime deps** -- uses native fetch, no CrewAI import required

## Configuration

| Option            | Default          | Description                        |
| ----------------- | ---------------- | ---------------------------------- |
| `baseUrl`         | required         | HELM kernel URL                    |
| `apiKey`          | -                | HELM API key                       |
| `principal`       | `crewai-agent`   | Identity for governance evaluation |
| `failClosed`      | `true`           | Deny on HELM errors                |
| `collectReceipts` | `true`           | Collect receipt chain              |
| `timeout`         | `30000`          | Request timeout (ms)               |

## License

Apache-2.0
