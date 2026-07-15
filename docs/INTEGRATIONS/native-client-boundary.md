---
title: Native Client Integration Boundary
last_reviewed: 2026-07-14
---

# Native Client Integration Boundary

HELM can generate scoped local configuration for supported coding clients. That
is useful local setup evidence, but it is not proof that a native client has
loaded the configuration or that every client action crosses HELM.

## What Local Setup Establishes

For a scoped setup, HELM can record exact configuration ownership, a signed
lifecycle receipt, and a Kernel-only synthetic denial. The setup result
intentionally reports `client_load_observed=false`. It establishes that HELM
generated and checked its local artifacts; it does not establish that Codex or
Claude Code opened them, started a configured server, or blocked an action in a
real session.

## What HELM Can Govern

HELM can govern only the configured hook classes that a client actually invokes
and MCP calls routed through the configured HELM server. Direct upstream calls,
unconfigured tool classes, terminal commands, browser actions, desktop actions,
and other paths that do not reach HELM remain outside this integration boundary.

## Evidence Levels

Keep these distinct when reviewing an integration:

1. **Local setup evidence** — source, tests, generated configuration, lifecycle
   receipt, and synthetic denial.
2. **Sterile client observation** — an authorized reviewer uses a disposable
   client home and workspace, observes the scoped configuration load, and
   exercises only the configured hook classes and routed MCP call.
3. **Release and deployment evidence** — source-owned repository gates, release
   authority, GitOps, and deployed smoke evidence remain separate from client
   setup.

Neither a local configuration receipt nor a screenshot substitutes for a
sterile client observation. A client observation does not itself authorize a
merge, deployment, or release.

## Safe Next Steps

Use a dry run to inspect the paths HELM would manage before writing them:

```bash
helm-ai-kernel setup codex --scope project --dry-run --json
helm-ai-kernel setup claude-code --dry-run --json
```

Use the CLI reference for supported setup, status, removal, and recovery
commands. Maintainer-only lifecycle and recovery procedures are deliberately
kept outside the public documentation surface.
