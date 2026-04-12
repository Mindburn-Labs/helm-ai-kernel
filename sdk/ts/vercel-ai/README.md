# @mindburn/helm-vercel-ai

HELM governance adapter for [Vercel AI SDK](https://sdk.vercel.ai) (`ai` package) -- tool call governor.

Every tool call goes through HELM's governance plane: policy-evaluated, receipt-producing, fail-closed by default.

## Install

```bash
npm install @mindburn/helm-vercel-ai
```

## Quick Start

```ts
import { HelmVercelAIGovernor } from '@mindburn/helm-vercel-ai';
import { generateText, tool } from 'ai';

const governor = new HelmVercelAIGovernor({
  baseUrl: 'http://localhost:8080',
  principal: 'my-nextjs-agent',
});

// Wrap a Vercel AI SDK tool with governance
const weatherTool = tool({
  description: 'Get weather',
  parameters: z.object({ city: z.string() }),
  execute: governor.governTool('weather', async ({ city }) => {
    return `Weather in ${city}: sunny`;
  }),
});

// Inspect receipts
console.log(governor.getReceipts());
```

## Features

- **Tool governor** -- wrap Vercel AI SDK tools with HELM governance
- **Middleware support** -- intercept tool calls via middleware pattern
- **Fail-closed** -- denied tools never execute (configurable)
- **Receipts** -- cryptographic proof chain for every tool call
- **Lamport clocks** -- causal ordering across tool executions
- **Zero runtime deps** -- uses native fetch, no AI SDK import required

## License

Apache-2.0
