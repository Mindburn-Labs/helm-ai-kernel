# TypeScript SDK Example

Runs against a local HELM boundary at `HELM_URL` and validates the primary developer path:

- allowed tool decision
- denied dangerous action
- MCP authorization denial for an unknown server
- signed public demo receipt verification
- sandbox preflight
- evidence export and verification

```bash
make build
cd sdk/ts && npm ci && npm run build
cd ../..
HELM_ADMIN_API_KEY=local-admin-key \
HELM_RUNTIME_TENANT_ID=default \
HELM_RUNTIME_PRINCIPAL_ID=sdk-ts-agent \
./bin/helm-ai-kernel serve --policy examples/launch/policies/agent_tool_call_boundary.toml

# In a second terminal:
HELM_URL=http://127.0.0.1:7715 ./sdk/ts/node_modules/.bin/tsc -p examples/ts_sdk/tsconfig.json
HELM_URL=http://127.0.0.1:7715 \
HELM_ADMIN_API_KEY=local-admin-key \
HELM_TENANT_ID=default \
HELM_PRINCIPAL_ID=sdk-ts-agent \
HELM_SESSION_ID=sdk-ts-session \
node examples/ts_sdk/dist/main.js
```

The script uses sample policy data and local receipts only. The admin key is
required for its governed tenant-scoped calls. The server's runtime tenant and
principal must match the client values; `HELM_SESSION_ID` binds evaluator and
evidence records to one causal session.
