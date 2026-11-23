# Kernel commands

The [main entry point](helm-ai-kernel/main.go) dispatches CLI arguments. Command
files define their flags, outputs, and exit statuses and register them with the
[command registry](helm-ai-kernel/registry.go). The [product documentation](../../docs/) describes the public interfaces.

- [Server flags](helm-ai-kernel/server_cmd.go) feed the [daemon lifecycle](helm-ai-kernel/server_runtime.go).
  The [runtime configuration](helm-ai-kernel/server_runtime_config.go) reads environment settings.
  The [HTTP pipeline](helm-ai-kernel/server_http.go) applies middleware and rate limits.
  The [proxy command](helm-ai-kernel/proxy_cmd.go) starts the OpenAI-compatible proxy.
- [Quickstart](helm-ai-kernel/quickstart_cmd.go) runs local onboarding.
  [State preparation](helm-ai-kernel/quickstart_state.go) validates and initializes local state.
  [Output](helm-ai-kernel/quickstart_output.go) renders help, errors and startup summaries.
- [Setup](helm-ai-kernel/setup_cmd.go) configures a supported client for the
  current project or user. The [local Console](helm-ai-kernel/local_console.go)
  validates its installed release before the process starts.
- [Console routes](helm-ai-kernel/console_routes.go) expose read-only Kernel state.
  [Route diagnostics](helm-ai-kernel/console_route_diagnostics.go) describe the registered API,
  and [receipt views](helm-ai-kernel/console_receipt_views.go) use tenant-scoped receipts.
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
