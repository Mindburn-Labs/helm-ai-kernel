---
title: Skill Packs
last_reviewed: 2026-07-01
---

# Skill Packs

Skill Packs are scoped instruction packages for agents. They can guide an
agent, but they do not grant tool permissions.

## Inspect

```bash
helm-ai-kernel skills search --json
helm-ai-kernel skills inspect helm/repo-auditor --json
helm-ai-kernel skills scan helm/repo-auditor --json
```

## Install For A Repo

```bash
helm-ai-kernel skills install helm/repo-auditor \
  --agent codex \
  --scope repo \
  --json
```

Repo-scoped install writes the projected skill and receipt metadata. User-scope
install escalates and writes no projected skill by default.

## Export A Codex Plugin

```bash
helm-ai-kernel skills export helm/repo-auditor \
  --format codex-plugin \
  --output ./dist/repo-auditor
```

Exported plugin MCP entries stay pending and hooks stay off by default.

## Revoke

```bash
helm-ai-kernel skills revoke helm/repo-auditor --json
```

Revocation removes HELM-managed projection files and writes a revoke receipt.
