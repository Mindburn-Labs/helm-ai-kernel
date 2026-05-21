---
title: Launchpad Clean Install GA
last_reviewed: 2026-05-20
---

# Launchpad Clean Install GA

Status: v0.5.5 gate implemented; v1 promotes OpenClaw, Hermes, OpenCode, and
Kilo Code into the supported-app clean-install set after workflow
`26198407296` passed signed artifact, live conformance, teardown, receipts, and
offline EvidencePack verification.

Launchpad GA is a product-adoption gate for the `v0.5.5` release. It proves the
Homebrew package, signed Launchpad artifacts, local-container app launcher,
MCP interceptor posture, signed receipts, teardown, and offline EvidencePack
verification survive a machine that did not build the release.

## Audience

This page is for release owners, Launchpad maintainers, and operators who need
to prove a supported app can be installed and removed from a clean workstation
without relying on a developer checkout.

## Outcome

You should leave with the supported-app gate, the exact clean-machine command
sequence, and the evidence files that prove install, launch, teardown, and
offline verification.

## Source Truth

- Release target: `v0.5.5`
- Current four-app Launchpad artifact workflow: <https://github.com/Mindburn-Labs/helm-ai-kernel/actions/runs/26198407296>
- Current macOS Homebrew clean-install workflow: <https://github.com/Mindburn-Labs/helm-ai-kernel/actions/runs/26199878246>
- Current Launchpad v1 report: `docs/launchpad/v1_report.json`
- Historical `v0.5.4` release report: `docs/launchpad/final_report.json`
- Clean-install report: `docs/launchpad/clean_install_report.json`

```mermaid
flowchart LR
  brew["Homebrew install"] --> matrix["Launch matrix"]
  matrix --> secret["Logical model_gateway secret"]
  secret --> apps["OpenClaw / Hermes / OpenCode / Kilo"]
  apps --> teardown["Cascade delete"]
  teardown --> verify["Offline EvidencePack verify"]
  verify --> audit["Secret-fragment audit"]
```

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
  --release-tag v0.5.5 \
  --artifact-run-id 26198407296 \
  --host-kind developer_macos \
  --output docs/launchpad/clean_install_report.json
```

The script downloads the signed Launchpad artifact manifest, resolves the
immutable egress-proxy image, confirms app GHCR digests, launches the selected
app set through `local-container`, deletes each launch with `--cascade`, verifies every
produced EvidencePack, and scans command output, GitHub logs, release
notes/assets, reports, and EvidencePacks for the CI key and fixed-length key
fragments without printing the secret. The default supported app set is
OpenClaw, Hermes, OpenCode, and Kilo Code. `--include-candidates` remains
accepted for backward compatibility.

## Supported App Digests

| App | Availability | Image |
| --- | --- | --- |
| OpenClaw | `oss_supported` | `ghcr.io/mindburn-labs/helm-launchpad/openclaw@sha256:4da80a1e48b5603fd203b7d2b98539a01f796142b0ed9315e5ed86b25bf5d995` |
| Hermes | `oss_supported` | `ghcr.io/mindburn-labs/helm-launchpad/hermes@sha256:4ec024dd8d0191fc887f04dc92c959fc865808d1526f782b5093f395fdd41652` |
| OpenCode | `oss_supported` | `ghcr.io/mindburn-labs/helm-launchpad/opencode@sha256:cdbeb88cfbd698809e673339d525083cdf1cdb3e91529e01c6834cd90b778550` |
| Kilo Code | `oss_supported` | `ghcr.io/mindburn-labs/helm-launchpad/kilocode@sha256:7b03834725235714ea8e698d38d89ce9b8bd81230b7e784016cb20a2c3c93ca6` |

Codex, Claude Code, Cursor, and Junie remain external/BYO adapters.

## CI Gate

Manual CI entrypoint:

```bash
gh workflow run launchpad-clean-install.yml \
  --repo Mindburn-Labs/helm-ai-kernel \
  -f release_tag=v0.5.5 \
  -f artifact_run_id=26198407296
```

The CI report is the current repeatable macOS Homebrew gate. A separately
operated clean Mac transcript can be attached as an additional adoption artifact
when release owners need a non-CI workstation record.

## Troubleshooting

| Condition | Response |
| --- | --- |
| Homebrew package is unavailable | Recheck the release tag, tap PR, and release workflow before running app launch commands. |
| Launch fails before receipts | Treat the gate as failed and inspect policy, sandbox, and provider readiness from the redacted report. |
| EvidencePack verification fails | Do not promote the app; rerun with fresh artifacts and preserve the failed verification output. |
| Teardown leaves resources | Reconcile local/container resources before declaring the machine clean. |
