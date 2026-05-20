---
title: Launchpad Conformance
last_reviewed: 2026-05-20
---

# Launchpad Conformance

Status: OpenClaw, Hermes, OpenCode, and Kilo Code passed the v1.0 signed
artifact, live local-container, teardown, receipt, and offline EvidencePack
bar in workflow `26186959337`. DigitalOcean opt-in beta passed for all four
apps; Hetzner remains fail-closed until a scoped provider token is available.

## Audience

Maintainers validating whether Launchpad app, substrate, registry, policy,
runtime, receipt, and public GA claims are backed by source and release evidence.

## Outcome

You can see which Launchpad checks are release-backed, which apps are promoted,
and which commands prove the local-container app launcher and EvidencePacks on
a clean machine.

## Source Truth

- Runtime package and tests: `core/pkg/launchpad/`
- CLI launch command: `core/cmd/helm-ai-kernel/launch_cmd.go`
- Registry fixtures: `registry/launchpad/`
- Policy fixtures: `policies/launchpad/`
- Schemas under test: `schemas/launchpad/`
- Launchpad artifact workflow: `.github/workflows/launchpad-artifacts.yml`
- Clean install workflow: `.github/workflows/launchpad-clean-install.yml`
- Release evidence: `docs/launchpad/final_report.json`
- v1.0 evidence status: `docs/launchpad/v1_report.json`

Implemented checks currently prove:

- `launchpad-artifacts` workflow `26186959337` built pinned OpenClaw, Hermes,
  OpenCode, and Kilo Code upstream refs into GHCR OCI images, signed them with
  GitHub OIDC keyless cosign, generated syft SBOMs, ran grype scans, and
  published a promotion manifest.
- `helm-ai-kernel launch promote` refuses promotion unless the CI artifact
  manifest, immutable image digest, cosign signature, syft SBOM, grype/trivy
  scan, live e2e run, teardown receipt, and EvidencePack refs are present and
  tied to the same workflow run.
- OpenClaw, Hermes, OpenCode, and Kilo Code are `oss_supported` in the registry
  from signed CI evidence, live e2e, teardown, receipts, and offline
  EvidencePack verification, not from assertion.
- OpenClaw image:
  `ghcr.io/mindburn-labs/helm-launchpad/openclaw@sha256:c5b6d872798514cab6e1a27f9f168aa4c38adb7166d711d49fd2a501aec8b1f9`.
- Hermes image:
  `ghcr.io/mindburn-labs/helm-launchpad/hermes@sha256:807f96a9bcc831a810ac77a775dec8f8486ad7df68dd024feb3d75a0a148a03e`.
- OpenCode image:
  `ghcr.io/mindburn-labs/helm-launchpad/opencode@sha256:3e258a0b5424b6a141e0e71516754cd7598a71b5727443c9620a90152dcc0f38`.
- Kilo Code image:
  `ghcr.io/mindburn-labs/helm-launchpad/kilocode@sha256:59d6eec39e1eb7f3ccdf218055b9590cffe55fd19ca58feb5944369c833c8f65`.
- Local-container OpenRouter egress requires a launch-scoped egress proxy
  receipt, can use the signed egress-proxy image from the artifact workflow, and
  rejects non-OpenRouter allowlists.
- Installer tests reject missing digests, host `curl | bash`, mutable git
  update patterns, and package-manager mutation inside the current worktree.
- MCP governance rejects unknown or revoked tools and requires schema pins.
- Supported app specs must reference signed MCP manifests with pinned package
  digest, schema hashes, tool effects, required secrets, and grants.
- Substrate specs must declare capability metadata. `local-container` is the GA
  baseline; Docker microVM and hosted sandbox substrates are registry-visible
  but experimental until their adapters pass the same receipt/evidence/teardown
  bar.
- Generated Launchpad EvidencePacks include a hash-chained receipt graph at
  `04_EXPORTS/launchpad_evidence_graph.json`.
- Session store rejects `RUNNING` without launch receipt, healthcheck receipt,
  sandbox grant refs, and egress refs for networked launches.
- Session store rejects `DELETED` without teardown receipt.
- Generated and static Launchpad EvidencePacks verify offline through
  `helm-ai-kernel verify --bundle`.
- Enterprise Launchpad route tests, route registry/OpenAPI parity, Console
  Playwright coverage, evidence refs, teardown receipt, and EvidencePack
  visibility passed in PR #30.

Still gated:

- Clean Homebrew install from a separate developer machine.
- Hetzner live app launches across the four-app matrix.
- Codex redistribution; Codex remains external/BYO unless redistribution proof
  changes.

```mermaid
flowchart TD
  Candidate["Candidate app"] --> Registry["Registry and policy validation"]
  Registry --> SupplyChain["Signed OCI, SBOM, vuln scan, license proof"]
  SupplyChain --> Runtime["Live local-container e2e"]
  Runtime --> Teardown["Cascade teardown receipt"]
  Teardown --> Evidence["Offline EvidencePack verification"]
  Evidence --> Supported["oss_supported"]
```

No additional app may move to `oss_supported` until it passes the same bar.

## Clean Install Validation

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
helm-ai-kernel evidence inspect <pack>
helm-ai-kernel evidence diff <pack-a> <pack-b>
helm-ai-kernel verify --bundle <pack>
```

`scripts/launch/clean_install_gate.sh` automates the command sequence, digest
confirmation, EvidencePack verification, and secret-fragment audit. It writes
redacted JSON only.

OpenCode and Kilo Code are now part of the supported clean-install app set.
`--include-candidates` remains accepted by the clean-install gate for backward
compatibility only.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| Published output is stale or incomplete | Run `npm run helm-public:accuracy` in `docs-platform`, then check the source path and public manifest row for this page. |
| A claim needs implementation backing | Check the Source Truth files above and update the implementation, manifest, source inventory, or page in the same change. |
