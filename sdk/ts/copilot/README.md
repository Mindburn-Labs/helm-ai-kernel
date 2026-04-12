# @mindburn/helm-copilot

HELM governance adapter for [GitHub Copilot Extensions](https://docs.github.com/en/copilot/building-copilot-extensions) -- tool call governor.

Every Copilot extension tool call goes through HELM's governance plane: policy-evaluated, receipt-producing, fail-closed by default.

## Install

```bash
npm install @mindburn/helm-copilot
```

## Quick Start

```ts
import { HelmCopilotGovernor } from '@mindburn/helm-copilot';

const governor = new HelmCopilotGovernor({
  baseUrl: 'http://localhost:8080',
  principal: 'my-copilot-extension',
});

// Govern a Copilot extension tool call before execution
await governor.governToolCall({
  toolName: 'run_query',
  arguments: { sql: 'SELECT * FROM users LIMIT 10' },
  confirmationId: 'conf-123',
});

// Wrap a tool function with governance
const governed = governor.governTool('run_query', async (args) => {
  return db.query(args.sql);
});

// Inspect receipts
console.log(governor.getReceipts());
```

## Features

- **Tool call governor** -- intercept and govern Copilot extension tool calls
- **Confirmation governor** -- govern tool calls requiring user confirmation
- **Fail-closed** -- denied tools never execute (configurable)
- **Receipts** -- cryptographic proof chain for every tool call
- **Lamport clocks** -- causal ordering across tool executions
- **Zero runtime deps** -- uses native fetch, no Copilot SDK required

## License

Apache-2.0
