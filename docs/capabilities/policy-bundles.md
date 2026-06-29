---
title: Policy Bundles
last_reviewed: 2026-06-29
---

# Policy Bundles

Policy bundles define what the HELM boundary allows, denies, or escalates.
Public docs should name the active command and example paths instead of
inventing a second policy language.

## Run With A Policy

```bash
helm-ai-kernel serve --policy ./release.high_risk.v3.toml
```

## MCP Fixture

```text
examples/launch/policies/shell_mcp_server_boundary.json
```

The fixture gives the public MCP quickstart concrete allow and deny examples.
The active policy bundle still decides enforcement.

## Verdicts

- `ALLOW` permits the action.
- `DENY` blocks the action.
- `ESCALATE` holds the action for explicit approval.

## Source Truth

- `docs/VERDICT_CANONICALIZATION.md`
- `docs/architecture/policy-languages.md`
- `docs/reference/cli.md`
- `release.high_risk.v3.toml`
- `examples/launch/policies/shell_mcp_server_boundary.json`
