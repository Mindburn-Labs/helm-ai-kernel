---
title: HELM Skill Packs Flow Catalog
last_reviewed: 2026-05-20
---

# HELM Skill Packs Flow Catalog

HELM Skill Packs are signed, scoped procedural packages for agents. A skill can guide behavior, but it cannot grant tool permissions or execution authority.

## Audience

This page is for developers and reviewers evaluating HELM-managed skill
installation, projection, disable, revoke, and marketplace flows.

## Outcome

You should leave with the command sequence for each skill-pack flow and the
authority boundary that keeps skills from granting tools or execution rights.

## Source Truth

- Skill runtime commands: `core/cmd/helm-ai-kernel/skills_cmd.go`
- Skill runtime packages: `core/pkg/skills/`
- Skill registry: `registry/skills/`
- Skill policy fixtures: `policies/skills/`
- Skill docs: `docs/skills/`

```mermaid
flowchart TD
    subgraph Ingestion["1. Ingestion & Context Plane"]
        search["search registry"]
        scan["scan content and metadata"]
        install["repo-scoped install"]
        export["Codex plugin export"]
        revoke["disable or revoke"]
    end

    subgraph Evaluation["2. Evaluation & Policy Plane"]
        inspect["inspect skill"]
    end

    subgraph Ledger["4. Tamper-Evident Ledger Plane"]
        receipts["install/projection receipts"]
    end

    %% Operational Flow Edges
    search --> inspect
    inspect --> scan
    scan --> install
    install --> receipts
    scan --> export
    install --> revoke

    %% Premium Styling Rules
    style inspect fill:#2d3748,stroke:#4a5568,stroke-width:2px,color:#fff
    style receipts fill:#2f855a,stroke:#276749,stroke-width:2px,color:#fff
```


## OSS Flows

### Search

`helm-ai-kernel skills search --json`

Loads the first-party skill registry and returns skills as `verified`, `experimental`, `blocked`, or `external`.

### Inspect

`helm-ai-kernel skills inspect helm/repo-auditor --json`

Shows manifest, requested projections, and the authority boundary: this skill does not grant tool permissions.

### Scan

`helm-ai-kernel skills scan <path_or_ref> --json`

Computes `skill_content_hash`, scans `SKILL.md`, metadata, scripts, symlinks, and MCP/tool requests, then emits `SKILL_SCAN_ATTESTATION`.

### Repo-Scoped Install

`helm-ai-kernel skills install helm/repo-auditor --agent codex --scope repo`

Runs scan, writes managed projection files atomically, and emits `SKILL_INSTALL_RECEIPT` plus `SKILL_PROJECTION_RECEIPT`.

### User Or Global Install

`helm-ai-kernel skills install helm/repo-auditor --agent codex --scope user`

Returns `ESCALATE` by default and writes no projection files.

### Export Codex Plugin

`helm-ai-kernel skills export helm/repo-auditor --format codex-plugin --output ./dist/repo-auditor`

Writes `.codex-plugin/plugin.json`, bundled skill files, pending/quarantined MCP metadata, and off-by-default hooks.

### Marketplace

`helm-ai-kernel skills marketplace init --scope repo`

Creates `.agents/plugins/marketplace.json`.

`helm-ai-kernel skills marketplace add <plugin_path>`

Adds only plugins inside the repo root and records policy/source hashes.

### Disable And Revoke

`helm-ai-kernel skills disable <skill_ref>`

Marks a HELM-managed install disabled and emits `SKILL_DISABLE_RECEIPT`.

`helm-ai-kernel skills revoke <skill_ref>`

Removes managed projection files, updates install state, and emits `SKILL_REVOKE_RECEIPT`.

## Negative Flows

- Policy bypass attempt -> `DENY`.
- Secret exfiltration attempt -> `DENY`.
- Global install request -> `ESCALATE`.
- MCP side-effect auto-enable -> `ESCALATE`.
- Plugin hook auto-approval -> `DENY`.
- Symlink escape -> `DENY`.
- Opaque binary payload -> `DENY` until provenance is available.

## Completion Gaps

Deferred: remote GitHub skill fetch, key-backed signature verification, full plugin marketplace e2e, and Enterprise global rollout approvals remain outside this MVP slice.

## Troubleshooting

| Condition | Response |
| --- | --- |
| Scan returns `DENY` | Inspect the attestation and remove unsafe file, symlink, or payload content before install. |
| User/global install escalates | Keep the install repo-scoped unless an operator approves the wider projection. |
| Marketplace add fails | Confirm the plugin path stays inside the repo root and has stable source hashes. |
| Revoke leaves files | Compare projection receipt paths with the working tree and remove only HELM-managed projections. |
