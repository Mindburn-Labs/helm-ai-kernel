---
title: Codebase Memory MCP Integration
last_reviewed: 2026-06-18
---

# Codebase Memory MCP Integration

## Audience

Developers and reviewers who want local codebase intelligence for HELM AI
Kernel, adjacent HELM repositories, or a larger polyrepo workspace.

## Outcome

After this page you should know how `codebase-memory-mcp` fits beside HELM:
it is a local read/query MCP server for code discovery, not a HELM execution
boundary and not proof of governed side effects.

## Source Truth

- Upstream project: <https://github.com/DeusData/codebase-memory-mcp>
- Upstream docs: <https://deusdata.github.io/codebase-memory-mcp/>
- HELM governed MCP path: [MCP integration](mcp.md)
- Validation: `make docs-coverage` and `make docs-truth`

## Local Setup

Install the UI build when you want the optional graph browser:

```bash
curl -fsSL https://raw.githubusercontent.com/DeusData/codebase-memory-mcp/main/install.sh | bash -s -- --ui
codebase-memory-mcp config set auto_index true
codebase-memory-mcp config set auto_index_limit 100000
```

Index a checkout:

```bash
codebase-memory-mcp cli index_repository '{"repo_path":"/absolute/path/to/helm-ai-kernel"}'
codebase-memory-mcp cli get_architecture '{"project":"helm-ai-kernel","aspects":["all"]}'
```

For a polyrepo workspace, add a root `.cbmignore` before indexing so duplicate
worktrees, generated scans, and recovery archives do not dominate the graph.

## HELM Boundary

Use Codebase Memory for read-oriented discovery:

- finding symbols, routes, functions, and call paths
- architecture orientation across repositories
- local semantic search over indexed source
- diff impact review before a HELM change

Do not treat Codebase Memory output as a HELM receipt, EvidencePack, policy
decision, production deployment fact, or approval artifact. If an MCP tool can
write files, call networks, mutate infrastructure, spend money, or dispatch
another tool, route that side effect through the HELM MCP gateway and keep the
receipt-backed path in [MCP integration](mcp.md).

## Optional UI

The UI variant can serve the local graph browser:

```bash
codebase-memory-mcp --ui=true --port=9749
```

The UI is local developer tooling. It does not publish HELM source truth and
does not replace `make docs-truth`, conformance tests, or verifier output.
