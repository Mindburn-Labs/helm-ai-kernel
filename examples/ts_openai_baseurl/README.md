# TypeScript — OpenAI SDK Example

Shows HELM integration with the OpenAI-compatible TypeScript SDK / native fetch.

## Prerequisites

- HELM running at `http://localhost:8080` (`docker compose up -d`)
- Node.js 18+ or Bun

## Run

```bash
npx tsx main.ts
```

## Expected Output

```
=== Chat Completions ===
Denied: DENY_TOOL_NOT_FOUND - Tool not found

=== Evidence ===
Exported: 1234 bytes
Verification: PASS

=== Conformance ===
Verdict: PASS Gates: 12 Failed: 0
```
