---
title: Developer Surface Map
last_reviewed: 2026-05-05
---

# HELM AI Kernel Developer Surface Map

This page is the public map of HELM AI Kernel developer surfaces. It complements the
quickstart and developer journey by showing where each source-backed capability
lives in the repository and which public docs page owns the explanation.

## Audience

This page is for developers who need the full HELM AI Kernel surface area without
reading the repository directory by directory.

## Outcome

You should be able to pick the correct page for installation, local execution,
language SDKs, framework integration, deployment, schemas, conformance,
verification, release integrity, and troubleshooting.

## Surface Flow

```mermaid
flowchart LR
  install["Install / build"] --> boundary["Run HELM boundary"]
  boundary --> integrate["Integrate SDK or proxy"]
  integrate --> policy["Evaluate policy"]
  policy --> receipt["Capture receipt"]
  receipt --> verify["Verify evidence"]
  verify --> deploy["Deploy or publish"]
  deploy --> operate["Debug and conform"]
```

## Developer Surfaces

| Need | Public page | Source truth |
| --- | --- | --- |
| Install on macOS, Linux, Windows/WSL, Docker, or source | `/helm-ai-kernel/developer-journey` | `docs/DEVELOPER_JOURNEY.md`, `docs/QUICKSTART.md`, `Makefile`, `.goreleaser.yml` |
| Run the first local boundary | `/helm-ai-kernel/developer-journey` | `core/cmd/helm-ai-kernel/server_cmd.go`, `core/cmd/helm-ai-kernel/proxy_cmd.go` |
| Point OpenAI-compatible clients at HELM | `/helm-ai-kernel/integrations/openai-compatible-proxy` | `docs/INTEGRATIONS/openai_baseurl.md`, `examples/python_openai_baseurl/`, `examples/ts_openai_baseurl/` |
| Use MCP | `/helm-ai-kernel/integrations/mcp` | `docs/INTEGRATIONS/mcp.md`, `examples/mcp_client/`, `mcp-bundle.json` |
| Use Python, TypeScript, JavaScript, Go, Rust, or Java | `/helm-ai-kernel/sdks` | `sdk/`, `examples/*_client/`, `examples/*openai_baseurl/` |
| Understand policy languages and bundles | `/helm-ai-kernel/reference/protocols-and-schemas`, `/helm-ai-kernel/compatibility` | `docs/architecture/policy-languages.md`, `protocols/bundles/`, `examples/policies/` |
| Validate conformance | `/helm-ai-kernel/conformance` | `docs/CONFORMANCE.md`, `protocols/conformance/v1/`, `tests/conformance/` |
| Verify receipts and evidence packs | `/helm-ai-kernel/verification`, `/helm-ai-kernel/developer-journey` | `docs/VERIFICATION.md`, `examples/receipt_verification/`, `protocols/spec/evidence-pack-v1.md` |
| Deploy with Docker or Kubernetes | `/helm-ai-kernel/deployment-and-examples` | `docker-compose.yml`, `deploy/`, `deploy/helm-chart/` |
| Verify release artifacts | `/helm-ai-kernel/security/release-security`, `/helm-ai-kernel/publishing` | `SECURITY.md`, `RELEASE.md`, `release/`, `.github/workflows/release.yml` |

## Source Truth

The coverage gate is `docs/developer-coverage.manifest.json`. The docs platform
loads public pages from `docs/public-docs.manifest.json`, then validates that
coverage-backed claims appear in public docs, search, Markdown exports,
`llms.txt`, `llms-full.txt`, and MCP responses.

## Troubleshooting

| Symptom | Use this page |
| --- | --- |
| You know the source path but not the public route | Match the source family in the table above. |
| You know the integration but not the proof command | Open `docs/developer-coverage.manifest.json` and inspect `validation_commands`. |
| A public page claims a capability but no example exists | Treat it as a docs bug unless the coverage manifest lists a live `example_paths` entry. |

<!-- docs-depth-final-pass -->

## Surface Ownership Rules

The surface map is the index a maintainer checks before creating new public docs. Every meaningful code family should have exactly one owning doc, one validation command, and a decision about whether it is public direct, public hub, source-owner, generated/config, or private/internal. When a new directory, schema, SDK, example, or CLI command appears, update this map before adding marketing copy. The public site should expose supported developer paths; source-owner docs can carry implementation detail; generated/config rows can stay classified without standalone prose when they do not affect external workflows.

<!-- docs-depth-final-pass-extra -->
 Treat missing ownership as a release blocker for high-value surfaces such as CLI commands, SDK packages, schemas, release artifacts, conformance fixtures, verifier paths, deployment examples, and policy bundles.

<!-- docs-depth-final-pass-extra-2 -->
 This map is also the first stop for deciding whether a new doc belongs in public IA or source-owner docs.
