# @mindburn/helm-gemini

HELM governance adapter for Google Gemini — function calling governance.

Every function call goes through HELM's governance plane: policy-evaluated, receipt-producing, fail-closed by default.

## Install

```bash
npm install @mindburn/helm-gemini
```

## Usage

```ts
import { HelmToolProxy } from '@mindburn/helm-gemini';

const proxy = new HelmToolProxy({ baseUrl: 'http://localhost:8080' });

// Wrap Gemini function declarations
const governed = proxy.wrapTools(myFunctions);

// Process a Gemini function_call response
const result = await proxy.governFunctionCall(
  { name: 'search', args: { query: 'HELM' } },
  searchExecutor
);

// Get receipts
console.log(proxy.getReceipts());
```

## Features

- **Gemini native** — works with `@google/genai` FunctionDeclaration format
- **Function call governance** — `governFunctionCall()` for Gemini response processing
- **OpenAI conversion** — `toOpenAITools()` for HELM proxy compatibility
- **Fail-closed** — denied functions never execute (configurable)
- **Receipts** — cryptographic proof of every function call
- **Lamport clocks** — causal ordering of function executions

## License

Apache-2.0
