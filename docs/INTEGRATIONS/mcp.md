# MCP Integration

HELM retains an MCP surface for governed tool access.

The local boundary quickstart remains the entry point:

```bash
helm serve --policy ./release.high_risk.v3.toml
```

## Run the Server

```bash
./bin/helm mcp serve
```

## Build a Bundle

```bash
./bin/helm mcp pack --client claude-desktop --out helm.mcpb
```

## Install a Local Client Configuration

```bash
./bin/helm mcp install --client claude-code
```

Use `./bin/helm mcp print-config --client <name>` for text configuration snippets where supported by the CLI.

MCP activity that emits receipts can be inspected with:

```bash
helm receipts tail --agent agent.titan.exec
```
