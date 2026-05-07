# HELM

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/mindburn-labs/helm-oss/badge)](https://scorecard.dev/viewer/?uri=github.com/mindburn-labs/helm-oss)
[![OpenSSF Best Practices](https://img.shields.io/badge/OpenSSF-Best%20Practices-informational)](BEST_PRACTICES.md)
[![Release checksums](https://img.shields.io/badge/release-checksums-success)](docs/VERIFICATION.md)
[![SLSA Level 3](https://img.shields.io/badge/SLSA-Level%203-blue)](docs/PUBLISHING.md)
[![SBOM CycloneDX](https://img.shields.io/badge/SBOM-CycloneDX%201.5-orange)](docs/PUBLISHING.md)

HELM is an open-source execution kernel for governed AI tool calling. It sits
on the execution boundary, applies fail-closed policy checks before dispatch,
records signed receipts for allow and deny decisions, and exports evidence
bundles that can be verified offline.

Current public release: `v0.4.0` from 2026-04-25. The canonical public docs
entry point is <https://helm.docs.mindburn.org/oss>.

## Project Status

- Public repository: `Mindburn-Labs/helm-oss`
- License: Apache-2.0
- Default branch: `main`
- Supported security line: `0.4.x`; `0.3.x` is best effort
- Public release assets: CLI binaries, checksums, SBOM, release attestation,
  `evidence-pack.tar`, `helm.mcpb`, and sample policy material
- Known OSS-readiness follow-ups are tracked in
  [docs/OSS_READINESS_AUDIT.md](docs/OSS_READINESS_AUDIT.md)

## Quick Start

Install the published macOS CLI:

```bash
brew install mindburn-labs/tap/helm
helm --version
```

Start a local boundary and optional Console:

```bash
helm serve --policy ./release.high_risk.v3.toml
helm serve --policy ./release.high_risk.v3.toml --console
helm boundary status
```

Govern MCP tools or an OpenAI-compatible client:

```bash
helm mcp wrap --server-id local-tools --upstream-command "node server.js"
helm proxy --upstream https://api.openai.com/v1
```

Inspect and verify evidence:

```bash
helm sandbox preflight --runtime wazero
helm receipts tail --agent agent.titan.exec
helm verify evidence-pack.tar
```

`helm serve --policy` starts the local boundary on `127.0.0.1:7714` by
default and stores receipts durably in SQLite unless `DATABASE_URL` is set.
`helm verify evidence-pack.tar` runs offline by default. Add `--online` only
when the public proof endpoint and credentials for that release are available.

Build from source:

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

## Public Interfaces

This repository is intentionally scoped to the OSS kernel:

- `core/` contains the Go kernel, CLI, HTTP API, proxy, evidence export, and
  verification logic.
- `apps/console/` contains the single self-hostable HELM OSS Console frontend.
- `packages/design-system-core/` contains the React/token design-system source
  used by the Console. It is source-available in this repo; it was not present
  in the public npm registry when this audit was created.
- `protocols/`, `schemas/`, and `api/openapi/` define the wire contracts and
  generated SDK inputs.
- `sdk/` contains public SDK sources for Go, Python, TypeScript, Rust, and
  Java.
- `examples/` contains runnable integration examples.

The repository does not ship the managed Mindburn hosted service, billing,
private operational tooling, proprietary connector programs, or generated HTML
report surfaces.

## SDKs And Packages

| Surface | Path | Public install or current status |
| --- | --- | --- |
| CLI | `core/` | `brew install mindburn-labs/tap/helm`; release binaries are attached to GitHub Releases |
| Go SDK | `sdk/go` | `go get github.com/Mindburn-Labs/helm-oss/sdk/go@main`; tagged module versions are tracked as an OSS readiness follow-up |
| Python SDK | `sdk/python` | `pip install helm-sdk` |
| TypeScript SDK | `sdk/ts` | `npm install @mindburn/helm` |
| Rust SDK | `sdk/rust` | `cargo add helm-sdk` |
| Java SDK | `sdk/java` | Maven workflow coordinate: `com.github.Mindburn-Labs:helm-sdk`; JitPack resolves the release as `com.github.mindburn-labs:helm-oss:0.4.0` |
| Design system core | `packages/design-system-core` | Workspace package source; public npm registry publication is not yet verified |

The HTTP client/types layer is generated from
[`api/openapi/helm.openapi.yaml`](api/openapi/helm.openapi.yaml). Protobuf
message bindings come from [`protocols/proto/`](protocols/proto/) where a
language SDK ships them.

## Repository Map

| Path | Purpose |
| --- | --- |
| `core/` | Go implementation of the kernel, CLI, HTTP API, proxy, and verification paths |
| `apps/console/` | Self-hostable HELM OSS Console frontend |
| `packages/design-system-core/` | HELM React/token design-system source |
| `api/openapi/` | OpenAPI contract used by generated SDK types |
| `protocols/` | Protocol specifications and schema sources |
| `schemas/` | JSON schemas used by kernel and verification flows |
| `sdk/` | Public SDK source packages |
| `tests/conformance/` | Conformance profile, checklist, and verification tests |
| `reference_packs/` | Example policy/reference bundles used by tests and examples |
| `deploy/helm-chart/` | Helm chart for running the kernel in Kubernetes |

## Documentation

Public OSS docs are sourced from this repository and canonically published
through `helm.docs.mindburn.org`. The owned docs set for sync is declared in
`docs/public-docs.manifest.json`.

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

## Security, Contributing, And Governance

- Report vulnerabilities through [SECURITY.md](SECURITY.md). Do not open
  public issues for security-sensitive reports.
- Contribution setup and validation expectations are in
  [CONTRIBUTING.md](CONTRIBUTING.md).
- Project governance, maintainer roles, and decision rules are in
  [GOVERNANCE.md](GOVERNANCE.md) and [MAINTAINERS.md](MAINTAINERS.md).
- Community behavior expectations are in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Support channels are listed in [SUPPORT.md](SUPPORT.md).
- Near-term open-source readiness work is summarized in [ROADMAP.md](ROADMAP.md)
  and tracked in [docs/OSS_READINESS_AUDIT.md](docs/OSS_READINESS_AUDIT.md).

## Release Verification

For `v0.4.0`, verify downloads with `SHA256SUMS.txt`, `sbom.json`,
`release-attestation.json`, the platform binary assets, and offline
`evidence-pack.tar` verification. Cosign bundle verification applies only when
`*.cosign.bundle` files are attached to a release.

See [docs/VERIFICATION.md](docs/VERIFICATION.md) and
[docs/PUBLISHING.md](docs/PUBLISHING.md) for the full release verification
path.

## License

Apache-2.0. See [LICENSE](LICENSE).
