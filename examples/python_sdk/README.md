# Python SDK Example

Runs against a local HELM boundary at `HELM_URL` and validates:

- an allowed tool decision and a denied dangerous action;
- MCP authorization denial for an unknown server;
- signed public demo receipt verification;
- sandbox preflight;
- evidence export and verification.

From the repository root, install the SDK from the same source checkout into
an isolated Python environment and build the server:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install ./sdk/python
make build
```

Start the server in one terminal. It generates a local admin key in the data
directory when none is supplied:

```bash
env -u DATABASE_URL -u HELM_ADMIN_API_KEY \
  HELM_RUNTIME_TENANT_ID=local-demo \
  HELM_RUNTIME_PRINCIPAL_ID=local-demo-principal \
  ./bin/helm-ai-kernel serve \
    --policy examples/launch/policies/agent_tool_call_boundary.toml \
    --data-dir ./data/python-sdk-example
```

In another terminal at the same repository root:

```bash
HELM_URL=http://127.0.0.1:7715 \
  HELM_ADMIN_API_KEY="$(cat ./data/python-sdk-example/admin.key)" \
  HELM_TENANT_ID=local-demo \
  HELM_PRINCIPAL_ID=local-demo-principal \
  .venv/bin/python examples/python_sdk/main.py
```

The script uses sample policy data and local receipts. `HELM_ADMIN_API_KEY`
authenticates the local request; `HELM_TENANT_ID` and `HELM_PRINCIPAL_ID` must
match the server's configured scope. Keep the data directory private and stop
the server with Ctrl-C when finished.

The public demo verification above calls the server. To fetch the evaluation
receipts and verify them with the standalone, offline `receipt_verify` binary,
run the [HTTP first-use walkthrough](../first-use/README.md).
