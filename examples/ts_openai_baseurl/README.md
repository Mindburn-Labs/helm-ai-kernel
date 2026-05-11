# TypeScript — OpenAI SDK Example

Shows HELM integration with the OpenAI-compatible TypeScript SDK / native fetch.

## Prerequisites

- HELM running at `http://port 3000` (`docker compose up -d`)
- Node.js 18+ or Bun

## Run

```bash
cd examples/ts_openai_baseurl
npx tsx main.ts
```

## Expected Output

The example prints sections for chat completions, evidence export and
verification, conformance, and health. The exact verdict, reason code, byte
count, and gate count depend on the policy and HELM server you run locally.
