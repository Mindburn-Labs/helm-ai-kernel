# TypeScript — OpenAI SDK Example

Shows the TypeScript HELM SDK calling the governed OpenAI-compatible
`POST /v1/chat/completions` route exposed by `helm-ai-kernel serve`.

## Prerequisites

- Node.js 18+ or Bun
- A governed `helm-ai-kernel serve` runtime with a permitted `LLM_INFERENCE`
  policy and an OpenAI-compatible upstream. It is not the standalone
  `helm-ai-kernel proxy` sidecar.

## Run

```bash
# From the repository root:
# Terminal 1: local mock upstream
python3 scripts/launch/mock-openai-upstream.py --port 19090

# Terminal 2: governed runtime. The upstream base may include /v1 or omit it.
# The provider key is server-owned and distinct from the runtime admin key.
HELM_ADMIN_API_KEY=local-admin-key \
HELM_RUNTIME_TENANT_ID=default \
HELM_RUNTIME_PRINCIPAL_ID=example-agent \
HELM_UPSTREAM_URL=http://127.0.0.1:19090 \
HELM_UPSTREAM_API_KEY=local-upstream-key \
./bin/helm-ai-kernel serve --policy <policy-that-permits-LLM_INFERENCE>

# Terminal 3: client
cd examples/ts_openai_baseurl
export HELM_URL=http://127.0.0.1:7714
export HELM_ADMIN_API_KEY=local-admin-key
export HELM_TENANT_ID=default
export HELM_PRINCIPAL_ID=example-agent
export HELM_SESSION_ID=example-session
npx tsx main.ts
```

If the emergency-stop fence is enabled, configure matching
`HELM_RUNTIME_WORKSPACE_ID` and `HELM_WORKSPACE_ID` values as well.

## Expected Output

The example prints sections for chat completions, evidence export and
verification, conformance, and health. The exact verdict, reason code, byte
count, and gate count depend on the policy and HELM server you run locally.
