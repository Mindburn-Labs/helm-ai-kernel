---
title: MCP Integration
last_reviewed: 2026-06-29
---

# MCP Integration

Route MCP tool calls through HELM so unknown servers, unknown tools, and
unpinned schemas are quarantined before dispatch.

## Quick Setup

Start the local boundary:

```bash
helm-ai-kernel serve --policy ./release.high_risk.v3.toml
```

Wrap an upstream shell MCP server:

```bash
helm-ai-kernel mcp wrap \
  --server-id shell-mcp-server \
  --upstream-command "npx -y shell-mcp-server" \
  --require-pinned-schema=true \
  --json
```

Print configuration for a client:

```bash
helm-ai-kernel mcp print-config --client codex
```

Claude Code has a direct installer:

```bash
helm-ai-kernel mcp install --client claude-code
```

## Run The Maintained Demo

```bash
./scripts/launch/demo-mcp.sh
```

The demo checks that unknown servers, unknown tools, and missing schema pins
return `DENY` or `ESCALATE`; they do not dispatch to the fixture server.

## Receipt Inspection

```bash
helm-ai-kernel receipts tail --agent mcp-demo-agent --server http://127.0.0.1:7714
```

Use the receipt ID or decision ID in support reports. Do not include provider
keys, private prompts, or production tenant data.

## Policy Fixture

The minimal shell fixture is
`examples/launch/policies/shell_mcp_server_boundary.json`.

| Command class | Verdict | Reason |
| --- | --- | --- |
| `ls` | `ALLOW` | Read-only directory listing |
| `pwd` | `ALLOW` | Read-only current-directory inspection |
| `cat <path>` | `ALLOW` | Read-only file inspection |
| `git status` | `ALLOW` | Read-only worktree status |
| `rm -rf` and equivalent recursive force delete patterns | `DENY` | Destructive deletion |
| `dd`, `mkfs`, and raw-device write patterns | `DENY` | Disk or filesystem destruction |
| `git clean -f`, `git clean -fd`, `git clean -fdx`, `git clean --force` | `DENY` | Destructive worktree cleanup |

## OAuth Mode

`helm-ai-kernel mcp serve --auth oauth` supports production JWKS validation and
the dev-only `HELM_OAUTH_BEARER_TOKEN` fallback.

| Variable | Purpose |
| --- | --- |
| `HELM_OAUTH_JWKS_URL` | JWKS endpoint used to verify bearer-token signatures |
| `HELM_OAUTH_ISSUER` | Required `iss` claim |
| `HELM_OAUTH_AUDIENCE` | Required `aud` claim |
| `HELM_OAUTH_RESOURCE` | Required RFC 8707 resource indicator; defaults to `<base-url>/mcp` |
| `HELM_OAUTH_SCOPES` | Scopes required before gateway entry |

Tool definitions can declare `required_scopes`. HELM surfaces them as
`requiredScopes` in `tools/list` and enforces them again at execution time.

## Debug

| Symptom | First check |
| --- | --- |
| Client cannot see the MCP server | Re-run `helm-ai-kernel mcp print-config --client <client>` and compare the installed config. |
| Tool is stuck quarantined | Inspect the server ID, schema hash, and approval receipt. |
| Receipts are missing | Confirm the boundary is running on `127.0.0.1:7714` and tail receipts for the expected agent ID. |
| OAuth calls fail | Check issuer, audience, resource, scopes, and token expiry. |

## Source Truth

- `core/cmd/helm-ai-kernel/mcp_cmd.go`
- `core/cmd/helm-ai-kernel/mcp_runtime.go`
- `core/cmd/helm-ai-kernel/mcp_boundary_cmd.go`
- `core/cmd/helm-ai-kernel/receipt_routes.go`
- `scripts/launch/demo-mcp.sh`
- `examples/launch/policies/shell_mcp_server_boundary.json`
- `docs/use-cases/mcp-execution-firewall.md`
