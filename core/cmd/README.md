# Kernel commands

The [main binary](helm-ai-kernel/main.go) registers commands. The command
files define their flags, outputs, and exit statuses. The [product documentation](../../docs/) describes the public interfaces.

- [Server](helm-ai-kernel/server_cmd.go) and [proxy](helm-ai-kernel/proxy_cmd.go)
  start the daemon and the OpenAI-compatible proxy.
- [Setup](helm-ai-kernel/setup_cmd.go) configures a supported client for the
  current project or user. The [local Console](helm-ai-kernel/local_console.go)
  validates its installed release before the process starts.
- [Receipt routes](helm-ai-kernel/receipt_routes.go) register the HTTP API.
  [Queries](helm-ai-kernel/receipt_query.go) apply tenant scope and pagination.
  [Persistence](helm-ai-kernel/receipt_persistence.go) issues and anchors receipts.
- [MCP](helm-ai-kernel/mcp_cmd.go), [verification](helm-ai-kernel/verify_cmd.go),
  and [conformance](helm-ai-kernel/conform.go) own those CLI entry points.

[helm-gateway](helm-gateway/) runs the gateway. [receipt_verify](receipt_verify/)
and [receipt_verify_wasm](receipt_verify_wasm/) provide standalone verification.
[semantic-model-gen](semantic-model-gen/) generates the semantic model.

From the repository root, run the CLI package tests and the documentation checks.

```sh
go -C core test ./cmd/helm-ai-kernel -count=1
make docs-coverage docs-truth
```
