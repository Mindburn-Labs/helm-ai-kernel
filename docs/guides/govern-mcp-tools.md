---
title: Govern MCP Tools
last_reviewed: 2026-07-15
---

# Govern MCP Tools

Generate a scoped MCP profile, require schema pins, and inspect authorization
receipts before you wire an executor or upstream proxy.

## 1. Start HELM

```bash
helm-ai-kernel serve --policy ./release.high_risk.v3.toml
```

## 2. Generate The Wrapper Profile

```bash
helm-ai-kernel mcp wrap \
  --server-id shell-mcp-server \
  --upstream-command "npx -y shell-mcp-server" \
  --require-pinned-schema=true \
  --json
```

This emits configuration. It does not start the upstream command or prove that a
native MCP client loaded the profile.

## 3. Generate Client Configuration

```bash
helm-ai-kernel mcp print-config --client codex
```

Supported print targets include `windsurf`, `codex`, `vscode`, and `cursor`.
Claude Code uses:

```bash
helm-ai-kernel mcp install --client claude-code
```

That command writes plugin and MCP configuration artifacts, then prints the
separate client-owned install command. Inspect and run that step explicitly.

## 4. Verify The Local Proof

```bash
helm-ai-kernel mcp proof --json --out ~/.helm-ai-kernel/proofs
```

## 5. Inspect And Verify Receipts

```bash
helm-ai-kernel mcp receipts --json
helm-ai-kernel verify \
  --bundle ~/.helm-ai-kernel/proofs/<run-id>/evidencepacks/<run-id> \
  --profile dev-local \
  --json
```

Before a live rollout, prove client load, policy-graph wiring, the exact routed
call, a real executor or upstream proxy, no-dispatch on `DENY` and `ESCALATE`,
revocation, schema drift, and offline verification. The profile-generation path
alone is not a general-purpose MCP proxy.

## Source Truth

- `core/cmd/helm-ai-kernel/mcp_cmd.go`
- `core/cmd/helm-ai-kernel/mcp_runtime.go`
- `scripts/launch/demo-mcp.sh`
- `examples/launch/policies/shell_mcp_server_boundary.json`
- `docs/INTEGRATIONS/mcp.md`
