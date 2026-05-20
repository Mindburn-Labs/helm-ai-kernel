---
title: Launchpad Clean Install GA
last_reviewed: 2026-05-20
---

# Launchpad Clean Install GA

Status: v0.5.5 gate implemented; v1.0 extends the gate to OpenCode and Kilo
Code so the check fails closed until those apps have complete signed evidence.

Launchpad GA is a product-adoption gate for the `v0.5.4` release. It proves the
Homebrew package, signed Launchpad artifacts, local-container app launcher,
MCP interceptor posture, signed receipts, teardown, and offline EvidencePack
verification survive a machine that did not build the release.

## Audience

Use this page if you are release-managing Launchpad GA, reproducing a clean install on a developer Mac, or validating that signed artifacts and EvidencePacks survive outside the build machine.

## Outcome

After reading this page, you should know which commands prove clean-install readiness, where the canonical reports live, and what evidence is required before promoting Launchpad app support.

## Gate Flow

```mermaid
flowchart LR
  release["Signed release"] --> install["Clean Homebrew install"]
  install --> matrix["Launch matrix"]
  matrix --> apps["Launch supported apps"]
  apps --> teardown["Cascade teardown"]
  teardown --> verify["Offline EvidencePack verify"]
  verify --> report["Clean-install report"]
```

## Source Truth

- Release: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.4>
- Launchpad artifact workflow: <https://github.com/Mindburn-Labs/helm-ai-kernel/actions/runs/26110916296>
- Release workflow: <https://github.com/Mindburn-Labs/helm-ai-kernel/actions/runs/26131090671>
- Homebrew tap PR: <https://github.com/mindburnlabs/homebrew-tap/pull/2>
- Final release report: `docs/launchpad/final_report.json`
- Clean-install report: `docs/launchpad/clean_install_report.json`

## Required Secret

Live local-container conformance uses a scoped OpenRouter test key. Store the
fresh CI-only key as `HELM_LAUNCHPAD_CI_OPENROUTER_API_KEY`. Workflows map it to
`OPENROUTER_API_KEY` only inside the live Launchpad test step. Do not commit the
key, fragments, screenshots, or raw logs.

## Clean Machine Commands

Run these from a clean macOS developer machine with Homebrew, `gh`, and a
Docker-compatible runtime such as Docker Desktop or Colima:

```bash
brew update
brew install mindburnlabs/tap/helm-ai-kernel
helm-ai-kernel launch matrix --json
helm-ai-kernel launch secrets set model_gateway --provider openrouter --value-env OPENROUTER_API_KEY
helm-ai-kernel launch openclaw local-container --headless --output json
helm-ai-kernel launch hermes local-container --headless --output json
helm-ai-kernel launch opencode local-container --headless --output json
helm-ai-kernel launch kilocode local-container --headless --output json
helm-ai-kernel launch delete <launch_id> --cascade
helm-ai-kernel verify --bundle <pack>
```

Use the repo-native gate to collect redacted evidence:

```bash
export HELM_LAUNCHPAD_CI_OPENROUTER_API_KEY='<fresh CI-only key>'
bash scripts/launch/clean_install_gate.sh \
  --release-tag v0.5.4 \
  --artifact-run-id 26110916296 \
  --host-kind developer_macos \
  --output docs/launchpad/clean_install_report.json
```

The script downloads the signed Launchpad artifact manifest, resolves the
immutable egress-proxy image, confirms app GHCR digests, launches every v1 app
through `local-container`, deletes each launch with `--cascade`, verifies every
produced EvidencePack, and scans command output, GitHub logs, release
notes/assets, reports, and EvidencePacks for the CI key and fixed-length key
fragments without printing the secret. The v1 app set is OpenClaw, Hermes,
OpenCode, and Kilo Code; the last two remain expected failures until promoted
from signed evidence.

## Supported App Digests

| App | Availability | Image |
| --- | --- | --- |
| OpenClaw | `oss_supported` | `ghcr.io/mindburn-labs/helm-launchpad/openclaw@sha256:808d750ed3ce3e29ed45d68c00c9c77ff50990204b3fe563b9f45d00f1beb88e` |
| Hermes | `oss_supported` | `ghcr.io/mindburn-labs/helm-launchpad/hermes@sha256:b970c2308182384377670704f6769e200eef89e18cc1a1102de9cba0d2437527` |
| OpenCode | `oss_candidate` | Pending signed CI artifact and promotion manifest |
| Kilo Code | `oss_candidate` | Pending signed CI artifact and promotion manifest |

Codex, Claude Code, Cursor, and Junie remain external/BYO adapters.

## CI Gate

Manual CI entrypoint:

```bash
gh workflow run launchpad-clean-install.yml \
  --repo Mindburn-Labs/helm-ai-kernel \
  -f release_tag=v0.5.4 \
  -f artifact_run_id=26110916296
```

The CI report is a repeatability signal. The separate clean Mac report remains
the canonical GA evidence for developer experience.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| Homebrew install fails | Confirm the tap PR and release tag in Source Truth still resolve. |
| Launch cannot reach OpenRouter | Confirm `HELM_LAUNCHPAD_CI_OPENROUTER_API_KEY` is present only in the live test environment. |
| EvidencePack verification fails | Inspect the produced bundle before updating app support status. |
| OpenCode or Kilo Code fail the gate | Treat them as expected failures until signed evidence promotes them from candidate status. |
