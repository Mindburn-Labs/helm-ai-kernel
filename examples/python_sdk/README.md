# Python SDK Example

Runs against a local HELM boundary at `HELM_URL` and validates the primary developer path:

- allowed tool decision
- denied dangerous action
- MCP authorization denial for an unknown server
- signed public demo receipt verification
- sandbox preflight
- evidence export and verification

```bash
make build
HELM_ADMIN_API_KEY=local-admin-key ./bin/helm-ai-kernel serve --policy examples/launch/policies/agent_tool_call_boundary.toml
HELM_URL=http://127.0.0.1:7715 HELM_ADMIN_API_KEY=local-admin-key HELM_TENANT_ID=local-demo python examples/python_sdk/main.py
```

The script uses sample policy data and local receipts only. `HELM_ADMIN_API_KEY`
is needed only for the local sandbox preflight admin route; `HELM_TENANT_ID`
scopes the local evidence export.
