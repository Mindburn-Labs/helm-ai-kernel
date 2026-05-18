---
title: HELM Launchpad
last_reviewed: 2026-05-18
---

# HELM Launchpad

Status: partial implementation, fail-closed by default.

Launchpad is the OSS app launcher surface for HELM AI Kernel. The current implementation provides registry loading, policy validation, deterministic plan compilation, guarded CLI flows, session records, receipts, and EvidencePack directory generation for escalated plans. It does not yet perform live Docker, cloud, or app install side effects.

## Audience

Operators and maintainers evaluating the source-backed Launchpad slice in HELM AI Kernel.

## Outcome

You can identify the implemented Launchpad command surface, current safety model, app classifications, and conformance sources without relying on retired planning reports.

## Source Truth

- CLI entrypoint: `core/cmd/helm-ai-kernel/launch_cmd.go`
- Runtime package: `core/pkg/launchpad/`
- App and substrate registry: `registry/launchpad/`
- Policy packs: `policies/launchpad/`
- Contract schemas: `schemas/launchpad/`
- Conformance status: `docs/launchpad/CONFORMANCE.md`

## Current CLI

```sh
helm-ai-kernel launch matrix --json
helm-ai-kernel launch apps --json
helm-ai-kernel launch substrates --json
helm-ai-kernel launch plan openclaw local-container --json
helm-ai-kernel launch openclaw local-container --headless --output json
helm-ai-kernel launch status <launch_id> --json
helm-ai-kernel launch logs <launch_id>
helm-ai-kernel launch repair <launch_id>
helm-ai-kernel launch delete <launch_id> --cascade
```

## Safety Model

- Runtime verdicts are only `ALLOW`, `DENY`, or `ESCALATE`.
- `oss_supported` is blocked unless license, artifact, policy, sandbox, healthcheck, e2e, teardown, receipts, and EvidencePack conformance pass.
- External proprietary tools are BYO adapters only.
- Local default substrate is `local-container`.
- Cloud substrates are dry-run/stub until operator approval and idempotency reconciliation exist.
- No host `curl | bash`, mutable live git update, or package-manager mutation inside the current worktree is allowed.

```mermaid
flowchart LR
  Registry["Registry entry"] --> Policy["Policy pack"]
  Policy --> Plan["Deterministic launch plan"]
  Plan --> Gate["ALLOW / DENY / ESCALATE"]
  Gate --> Receipt["Launch receipt"]
  Receipt --> Evidence["EvidencePack directory"]
```

## Current App Classification

- `openclaw`, `hermes`, `opencode`, `kilocode`: `oss_candidate`.
- `codex`, `claude-code.external`, `cursor.external`, `junie.external`: `external_proprietary_adapter`.

For current source-backed details, use the Launchpad specs and conformance docs:
`docs/launchpad/APP_SPEC.md`, `docs/launchpad/SUBSTRATE_SPEC.md`,
`docs/launchpad/POLICY_PACKS.md`, `docs/launchpad/SECURITY_REVIEW.md`, and
`docs/launchpad/CONFORMANCE.md`.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| Published output is stale or incomplete | Run `npm run helm-public:accuracy` in `docs-platform`, then check the source path and public manifest row for this page. |
| A claim needs implementation backing | Check the Source Truth files above and update the implementation, manifest, source inventory, or page in the same change. |
