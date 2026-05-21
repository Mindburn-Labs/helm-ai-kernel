# Historical Final Implementation Report

Status: historical `v0.5.4` production report for HELM OSS Skill Packs MVP,
HELM Launchpad OpenClaw/Hermes local-container support, and HELM Commercial
Launchpad/Skills governance surfaces.

This file is not the current Launchpad GA support truth. Current Launchpad v1
truth is recorded in `docs/launchpad/v1_report.json`: OpenClaw, Hermes,
OpenCode, and Kilo Code are `oss_supported` after workflow `26186959337`
passed signed artifact build, SBOM, vulnerability scan, live OpenRouter
launch, teardown, and offline EvidencePack verification for all four.

`mission_100_percent_complete` is true for this production deployment milestone. Kernel PR #161 and Enterprise PR #30 are merged. Kernel release `v0.5.4` is published from `main`, release workflow `26131090671` passed, and the release EvidencePack verifies offline. Homebrew PR https://github.com/mindburnlabs/homebrew-tap/pull/2 merged the public tap update to v0.5.4. Public website claims remain blocked until docs-truth and owner review approve a public claims update.

## What Was Implemented

- [KEEP] OpenClaw and Hermes are promoted to `oss_supported` from HELM-built signed OCI artifacts, not from assertion or unsigned upstream assets.
- [KEEP] GitHub Actions workflow `26110916296` built and signed OpenClaw, Hermes, and the Launchpad egress proxy with GitHub OIDC keyless cosign, syft SBOM refs, grype vulnerability scan refs, and provenance refs.
- [KEEP] OpenClaw and Hermes live local-container conformance passed with scoped OpenRouter secret projection, sandbox preflight, MCP quarantine receipt, healthcheck receipt, launch receipt, teardown receipt, and EvidencePack output.
- [KEEP] EvidencePack verification passed offline for both downloaded directories and tar archives.
- [KEEP] The Launchpad live-evidence artifact upload now preserves hidden `.keep` placeholders so downloaded EvidencePack directories verify the same way archives do.
- [KEEP] OpenCode and Kilo Code remain `oss_candidate`; Codex, Claude Code, Cursor, and Junie remain external/BYO adapters.
- [KEEP] DigitalOcean and Hetzner remain dry-run by default; live mode requires explicit operator approval receipt and reconciliation.
- [KEEP] OSS Skill Packs MVP, Codex plugin export, repo projection, scan/install/revoke receipts, and Skill Pack conformance tests remain in this release candidate.
- [KEEP] Enterprise Launchpad and Skills APIs, route registry/OpenAPI parity, migrations, durable stores, Console Launchpad UI, Playwright coverage, and approved OSS boundary sync are merged through Enterprise PR #30.
- [KEEP] Kernel release `v0.5.4` ships CLI binaries, checksums, SBOM JSON, OpenVEX, release attestation metadata, Cosign bundles, `evidence-pack.tar`, `helm-ai-kernel.mcpb`, `helm-ai-kernel.rb`, and sample policy material.
- [KEEP] Release asset verification passed for `v0.5.4`: `SHA256SUMS.txt`, offline EvidencePack verification, and Cosign verification for all 14 signed assets.

## Exact Files Changed In This Final Pass

- `.github/workflows/launchpad-artifacts.yml`
- `docs/launch/LAUNCH_READINESS.md`
- `registry/launchpad/apps/openclaw.yaml`
- `registry/launchpad/apps/hermes.yaml`
- `docs/launchpad/FINAL_IMPLEMENTATION_REPORT.md`
- `docs/launchpad/final_report.json`

The full kernel branch diff also includes Launchpad runtime, promotion, receipts, Skill Packs, schemas, tests, policies, docs, and artifact recipe files. The Enterprise release candidate diff includes Launchpad/Skills APIs, Console feature files, migrations, OpenAPI, route registry, protected OSS sync, and route/parity tests.

## App Availability

| App | Availability | Evidence |
| --- | --- | --- |
| OpenClaw | `oss_supported` | `ghcr.io/mindburn-labs/helm-launchpad/openclaw@sha256:808d750ed3ce3e29ed45d68c00c9c77ff50990204b3fe563b9f45d00f1beb88e`; workflow `26110916296`; directory and tar EvidencePack verification passed |
| Hermes | `oss_supported` | `ghcr.io/mindburn-labs/helm-launchpad/hermes@sha256:b970c2308182384377670704f6769e200eef89e18cc1a1102de9cba0d2437527`; workflow `26110916296`; directory and tar EvidencePack verification passed |
| OpenCode | `oss_candidate` | Not promoted; same signed OCI/live e2e/teardown/EvidencePack bar has not been run |
| Kilo Code | `oss_candidate` | Not promoted; same signed OCI/live e2e/teardown/EvidencePack bar has not been run |
| Codex | `external_proprietary_adapter` | BYO/external only; HELM governs execution and does not redistribute Codex |
| Claude Code / Cursor / Junie | `external_proprietary_adapter` | BYO/external only; no redistribution |

## Evidence And Verification

- Artifact workflow: `26110916296`, attempt `1`, head `2a04e2e0cbf45459a2f155bc51f79fb1d7dbbc1b`.
- Kernel release: `v0.5.4`, workflow `26131090671`, source commit `0b60353c50eda54454fbb90e3e5ccd9db952ef8b`.
- Enterprise merge: PR #30, merge commit `89f319bae0d2186acd76b7e5764ade881a8650e1`.
- OpenClaw promotion refs: `github-actions://26110916296/1/artifact-verification/openclaw`, `github-actions://26110916296/1/live-e2e/openclaw`, `github-actions://26110916296/1/evidencepack/openclaw`, `github-actions://26110916296/1/teardown/openclaw`.
- Hermes promotion refs: `github-actions://26110916296/1/artifact-verification/hermes`, `github-actions://26110916296/1/live-e2e/hermes`, `github-actions://26110916296/1/evidencepack/hermes`, `github-actions://26110916296/1/teardown/hermes`.
- OpenClaw EvidencePack merkle root: `d309d1ab02b5238c5b7c6c6ee7ee5df8805fb42c994308919cdc94271199604c`.
- Hermes EvidencePack merkle root: `2ca2efb22f3c936cac7b8a1a57e331fc2f3175a5a9eb704e02b97ed685af8dc3`.
- Release EvidencePack verification: `helm-ai-kernel verify --bundle /tmp/helm-ai-kernel-v0.5.4-release/evidence-pack.tar` returned `VERIFIED`.
- Release asset signature verification: `bash scripts/release/verify_cosign.sh /tmp/helm-ai-kernel-v0.5.4-release` returned `verified=14 failed=0`.

## Tests Passing

Kernel:

- `launchpad-artifacts` workflow `26110916296`.
- `bin/helm-ai-kernel verify --bundle` for OpenClaw downloaded EvidencePack directory and tar archive.
- `bin/helm-ai-kernel verify --bundle` for Hermes downloaded EvidencePack directory and tar archive.
- `go test ./core/pkg/skillpacks/... ./core/pkg/launchpad/... ./core/cmd/helm-ai-kernel/... ./core/pkg/mcp/... ./core/pkg/evidencepack/... ./core/pkg/verifier ./tests/skills/... ./tests/launchpad/...`
- Prior gates on this branch: `make build`, `make test`, `make test-console`, `make test-platform`, `make launch-ready`, `make launch-security`.
- Release workflow `26131090671`.
- `shasum -a 256 -c SHA256SUMS.txt --ignore-missing` for downloaded v0.5.4 release assets.
- `bin/helm-ai-kernel verify --bundle` for downloaded v0.5.4 `evidence-pack.tar`.
- `bash scripts/release/verify_cosign.sh` for downloaded v0.5.4 release assets.

Enterprise:

- `make quality-pr`
- `make verify-boundary`
- `make openapi-route-parity`
- `go test ./apps/controlplane/internal/console/... ./apps/controlplane/internal/store/postgres`
- `pnpm --dir apps/console typecheck`
- `pnpm --dir apps/console test -- --run`
- `pnpm --dir apps/console build`
- `pnpm --dir e2e exec playwright test tests/launchpad.spec.ts --project=chromium`
- Enterprise PR #30 remote CI checks, including `race-detector`, `Mutation Analysis`, `Boundary Verification`, `openapi-lint`, `evidence-pack`, `doccheck`, and JS typecheck/lint/test/build.

## Tests Failing

None for this production release evidence set.

## Security Review Result

PASS for this production release. No app is promoted without signed OCI digest, cosign ref, SBOM ref, vulnerability scan ref, provenance ref, live e2e ref, teardown receipt ref, and offline EvidencePack verification. Proprietary apps remain external/BYO. Cloud live writes remain opt-in. Logs and reports do not include the OpenRouter key.

## Release Steps

1. [KEEP] Kernel PR #161 merged.
2. [KEEP] Kernel release `v0.5.4` published from `main`.
3. [KEEP] Release assets, checksums, Cosign bundles, SBOM, OpenVEX, release attestation, Homebrew formula asset, and EvidencePack are available.
4. [KEEP] Release EvidencePack verifies offline.
5. [KEEP] Enterprise PR #30 merged.
6. [KEEP] Homebrew tap PR https://github.com/mindburnlabs/homebrew-tap/pull/2 merged.
7. [DEFER] Public website claims remain blocked until docs-truth passes on `main` and owner review approves.

## Follow-Up PRs

- OpenCode signed OCI and live conformance promotion.
- Kilo Code signed OCI and live conformance promotion.
- Optional live DigitalOcean/Hetzner smoke behind approval receipts.
- Broader Codex/Claude/Cursor/OpenCode projection smoke matrix for Skill Packs.
