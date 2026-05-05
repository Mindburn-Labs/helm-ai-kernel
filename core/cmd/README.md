# HELM OSS CLI Source Owner

## Audience

Use this file when changing `helm` commands, local server routes, proxy behavior, receipt routes, MCP commands, conformance commands, evidence export, or release-facing CLI flags.

## Responsibility

`core/cmd` owns binaries and command wiring. The public docs should describe supported commands and examples; this directory owns flags, route registration, defaults, and command-level tests.

## Source Map

- `helm/main.go` wires the primary CLI.
- `helm/serve_*`, `helm/server_*`, and route files own local API behavior.
- `helm/proxy_cmd.go` owns OpenAI-compatible proxy entrypoints.
- `helm/mcp_*` owns MCP server, bundle, install, and runtime behavior.
- `helm/verify_cmd.go`, `helm/export_*`, and receipt route files own evidence and verification workflows.
- `helm/conform.go` owns conformance entrypoints.

## Validation

Run focused CLI tests before changing public command docs:

```bash
cd core
go test ./cmd/helm -count=1
```

Then run the docs truth gates from the repo root.
