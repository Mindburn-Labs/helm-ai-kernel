# HELM

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Mindburn-Labs/helm-oss/badge)](https://scorecard.dev/viewer/?uri=github.com/Mindburn-Labs/helm-oss)
[![OpenSSF Best Practices](https://img.shields.io/badge/OpenSSF-Best%20Practices-informational)](BEST_PRACTICES.md)
[![Release checksums](https://img.shields.io/badge/release-checksums-success)](docs/VERIFICATION.md)
[![SLSA Level 3](https://img.shields.io/badge/SLSA-Level%203-blue)](docs/PUBLISHING.md)
[![SBOM CycloneDX](https://img.shields.io/badge/SBOM-CycloneDX%201.5-orange)](docs/PUBLISHING.md)

HELM is an open-source execution kernel for governed AI tool calling. It sits on the execution boundary, applies fail-closed policy checks before dispatch, records signed receipts for allow and deny decisions, and exports evidence bundles that can be verified offline.

This repository is intentionally scoped to the OSS kernel:

- `core/` contains the Go kernel, CLI, HTTP API, proxy, evidence export, and verification logic.
- `apps/console/` contains the single self-hostable HELM OSS Console frontend.
- `packages/design-system-core/` contains the public React/token design-system package used by the Console.
- `protocols/`, `schemas/`, and `api/openapi/` define the wire contracts and generated SDK inputs.
- `sdk/` ships maintained public SDKs for Go, Python, TypeScript, Rust, and Java.
- `examples/` contains a small set of runnable integration examples.

## Quick Start

```bash
brew install mindburn/tap/helm
helm serve --policy ./release.high_risk.v3.toml
helm serve --policy ./release.high_risk.v3.toml --console
helm verify evidence-pack.tar
helm receipts tail --agent agent.titan.exec
```

`helm serve --policy` starts the local boundary on `127.0.0.1:7714` by default and stores receipts durably in SQLite unless `DATABASE_URL` is set. `helm verify evidence-pack.tar` runs offline by default. Add `--online` to check embedded pack metadata against the configured public proof API.

Build from source remains supported:

```bash
git clone https://github.com/Mindburn-Labs/helm-oss.git
cd helm-oss
make build
./bin/helm serve --policy ./release.high_risk.v3.toml
```

Run the retained validation targets before publishing changes:

```bash
make test
make test-console
make test-platform
make test-all
make crucible
```

Govern an existing OpenAI-compatible client:

```bash
./bin/helm proxy --upstream https://api.openai.com/v1
```

Then point your client at `http://localhost:8080/v1`.

## Public Interfaces

The retained public surfaces in this repository are:

- Go CLI and kernel API in `core/`
- Self-hostable HELM OSS Console in `apps/console`
- Public design-system package in `packages/design-system-core`
- OpenAI-compatible proxy surface
- MCP server and bundle generation commands
- Evidence export and verification commands
- Public SDKs in `sdk/go`, `sdk/python`, `sdk/ts`, `sdk/rust`, and `sdk/java`

This repository ships exactly one browser UI: the self-hostable OSS Console. It does not ship the managed Mindburn hosted service, billing, private operational tooling, proprietary connector programs, or generated HTML report surfaces.

## SDKs

| Language | Path | Install |
| --- | --- | --- |
| Go | `sdk/go` | `go get github.com/Mindburn-Labs/helm-oss/sdk/go` |
| Python | `sdk/python` | `pip install helm-sdk` |
| TypeScript | `sdk/ts` | `npm install @mindburn/helm` |
| Rust | `sdk/rust` | `cargo add helm-sdk` |
| Java | `sdk/java` | `com.github.Mindburn-Labs:helm-sdk:0.4.0` |

The HTTP client/types layer is generated from [`api/openapi/helm.openapi.yaml`](api/openapi/helm.openapi.yaml). Protobuf message bindings come from [`protocols/proto/`](protocols/proto/) where a language SDK ships them. Both surfaces are validated by the SDK test targets.

## Repository Map

| Path | Purpose |
| --- | --- |
| `core/` | Go implementation of the kernel, CLI, HTTP API, proxy, and verification paths |
| `apps/console/` | Self-hostable HELM OSS Console frontend |
| `packages/design-system-core/` | Public HELM React/token design-system package |
| `api/openapi/` | OpenAPI contract used by the generated SDKs |
| `protocols/` | Protocol specifications and schema sources |
| `schemas/` | JSON schemas used by the kernel and verification flows |
| `tests/conformance/` | Conformance profile, checklist, and verification tests |
| `reference_packs/` | Example policy/reference bundles used by tests and examples |
| `deploy/helm-chart/` | Helm chart for running the kernel in Kubernetes |

## Documentation

Public OSS docs are sourced from this repository and canonically published through `helm.docs.mindburn.org`. The owned docs set for sync is declared in `docs/public-docs.manifest.json`.

- [Quickstart](docs/QUICKSTART.md)
- [Console](docs/CONSOLE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Conformance](docs/CONFORMANCE.md)
- [Verification](docs/VERIFICATION.md)
- [Publishing](docs/PUBLISHING.md)
- [Compatibility](docs/COMPATIBILITY.md)
- [SDK Index](docs/sdks/00_INDEX.md)
- [Security Model](docs/EXECUTION_SECURITY_MODEL.md)
- [OWASP Mapping](docs/OWASP_MCP_THREAT_MAPPING.md)
- [NIST AI Agent Critical Infrastructure Alignment](docs/compliance/nist-ai-agent-critical-infrastructure.md)
- [NIST AI RMF to ISO 42001 Crosswalk](docs/compliance/nist-ai-rmf-iso-42001-crosswalk.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
