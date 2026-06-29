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
flowchart TD
    subgraph Ingestion["1. Ingestion & Context Plane"]
        install["Install / build"]
        integrate["Integrate SDK or proxy"]
        deploy["Deploy or publish"]
        operate["Debug and conform"]
    end

    subgraph Evaluation["2. Evaluation & Policy Plane"]
        policy["Evaluate policy"]
    end

    subgraph Execution["3. Execution & Verdict Plane"]
        boundary["Run HELM boundary"]
    end

    subgraph Ledger["4. Tamper-Evident Ledger Plane"]
        receipt["Capture receipt"]
        verify["Verify evidence"]
    end

    %% Operational Flow Edges
    install --> boundary
    boundary --> integrate
    integrate --> policy
    policy --> receipt
    receipt --> verify
    verify --> deploy
    deploy --> operate

    %% Premium Styling Rules
    style boundary fill:#3182ce,stroke:#2b6cb0,stroke-width:2px,color:#fff
    style policy fill:#2d3748,stroke:#4a5568,stroke-width:2px,color:#fff
    style receipt fill:#2f855a,stroke:#276749,stroke-width:2px,color:#fff
    style verify fill:#2f855a,stroke:#276749,stroke-width:2px,color:#fff
```


## Developer Surfaces

| Need | Public page | Source truth |
| --- | --- | --- |
| Install on macOS, Linux, Windows/WSL, Docker, or source | `/developer-journey` | `docs/DEVELOPER_JOURNEY.md`, `docs/QUICKSTART.md`, `Makefile`, `.goreleaser.yml` |
| Run the first local boundary | `/developer-journey` | `core/cmd/helm-ai-kernel/server_cmd.go`, `core/cmd/helm-ai-kernel/proxy_cmd.go` |
| Point OpenAI-compatible clients at HELM | `/integrations/openai-compatible-proxy` | `docs/INTEGRATIONS/openai_baseurl.md`, `examples/python_openai_baseurl/`, `examples/ts_openai_baseurl/` |
| Use MCP | `/integrations/mcp` | `docs/INTEGRATIONS/mcp.md`, `examples/mcp_client/`, `mcp-bundle.json` |
| Use Python, TypeScript, JavaScript, Go, Rust, or Java | `/sdks` | `sdk/`, `examples/*_client/`, `examples/*openai_baseurl/` |
| Understand policy languages and bundles | `/reference/protocols-and-schemas`, `/compatibility` | `docs/architecture/policy-languages.md`, `protocols/bundles/`, `examples/policies/` |
| Validate conformance | `/conformance` | `docs/CONFORMANCE.md`, `protocols/conformance/v1/`, `tests/conformance/` |
| Verify receipts and evidence packs | `/verification`, `/developer-journey` | `docs/VERIFICATION.md`, `examples/receipt_verification/`, `protocols/spec/evidence-pack-v1.md` |
| Deploy with Docker or Kubernetes | `/deployment-and-examples` | `docker-compose.yml`, `deploy/`, `deploy/helm-chart/` |
| Verify release artifacts | `/security/release-security`, `/publishing` | `SECURITY.md`, `RELEASE.md`, `release/`, `.github/workflows/release.yml` |

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
