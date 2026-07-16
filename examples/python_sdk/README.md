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
HELM_ADMIN_API_KEY=local-admin-key HELM_RUNTIME_TENANT_ID=default HELM_RUNTIME_PRINCIPAL_ID=local-demo-agent HELM_RUNTIME_WORKSPACE_ID=default ./bin/helm-ai-kernel serve --policy examples/launch/policies/agent_tool_call_boundary.toml
HELM_URL=http://127.0.0.1:7715 HELM_ADMIN_API_KEY=local-admin-key HELM_TENANT_ID=default HELM_PRINCIPAL_ID=local-demo-agent HELM_WORKSPACE_ID=default python examples/python_sdk/main.py
```

The script uses sample policy data and local receipts only. Its evaluator calls
require `HELM_ADMIN_API_KEY`, `HELM_TENANT_ID`, `HELM_PRINCIPAL_ID`, and
`HELM_WORKSPACE_ID`; the latter three must match the running boundary's
configured bindings. The bundled policy is installed for the local
`default/default` scope.
