# @mindburn/helm-langchain

HELM governance adapter for [LangChain.js](https://js.langchain.com) -- callback handler and tool governor.

Every tool call goes through HELM's governance plane: policy-evaluated, receipt-producing, fail-closed by default.

## Install

```bash
npm install @mindburn/helm-langchain
```

## Usage: Callback Handler

Attach `HelmCallbackHandler` to any LangChain chain, agent, or model via the `callbacks` option. Tool calls are intercepted and governed automatically.

```ts
import { HelmCallbackHandler } from '@mindburn/helm-langchain';
import { ChatOpenAI } from '@langchain/openai';
import { AgentExecutor, createOpenAIToolsAgent } from 'langchain/agents';

const handler = new HelmCallbackHandler({
  baseUrl: 'http://localhost:8080',
  principal: 'my-langchain-agent',
});

const model = new ChatOpenAI({
  modelName: 'gpt-4o-mini',
  callbacks: [handler],
});

// Every tool call in agents is now governed by HELM
const agent = await createOpenAIToolsAgent({ llm: model, tools, prompt });
const executor = new AgentExecutor({ agent, tools, callbacks: [handler] });
const result = await executor.invoke({ input: 'What is the weather?' });

// Inspect receipts
console.log(handler.getReceipts());
```

## Usage: Tool Governor

For direct control over individual tool governance, use `HelmToolGovernor`:

```ts
import { HelmToolGovernor } from '@mindburn/helm-langchain';
import { DynamicTool } from 'langchain/tools';

const governor = new HelmToolGovernor({
  baseUrl: 'http://localhost:8080',
});

const tool = new DynamicTool({
  name: 'search',
  description: 'Search the web',
  func: governor.governTool('search', async (query: string) => {
    return `Results for: ${query}`;
  }),
});
```

## Features

- **Callback handler** -- drop-in governance via LangChain's callback system
- **Tool governor** -- imperative API for wrapping individual tool functions
- **Fail-closed** -- denied tools never execute (configurable)
- **Receipts** -- cryptographic proof chain for every tool call
- **Lamport clocks** -- causal ordering across tool executions
- **Zero runtime deps** -- uses native fetch, no LangChain import required

## Configuration

| Option            | Default             | Description                        |
| ----------------- | ------------------- | ---------------------------------- |
| `baseUrl`         | required            | HELM kernel URL                    |
| `apiKey`          | -                   | HELM API key                       |
| `principal`       | `langchain-agent`   | Identity for governance evaluation |
| `failClosed`      | `true`              | Deny on HELM errors                |
| `collectReceipts` | `true`              | Collect receipt chain              |
| `timeout`         | `30000`             | Request timeout (ms)               |

## License

Apache-2.0
