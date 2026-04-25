# HELM

HELM is an open-source execution kernel for governed AI tool calling. It sits on the execution boundary, applies fail-closed policy checks before dispatch, records signed receipts for allow and deny decisions, and exports evidence bundles that can be verified offline.

This repository is intentionally scoped to the OSS kernel:

- `core/` contains the Go kernel, CLI, HTTP API, proxy, evidence export, and verification logic.
- `protocols/`, `schemas/`, and `api/openapi/` define the wire contracts and generated SDK inputs.
- `sdk/` ships maintained public SDKs for Go, Python, TypeScript, Rust, and Java.
- `examples/` contains a small set of runnable integration examples.

## Quick Start

Build from source:

```bash
git clone https://github.com/Mindburn-Labs/helm-oss.git
cd helm-oss
make build
```

Run the local proof loop:

```bash
./bin/helm onboard --yes
./bin/helm demo organization --template starter --provider mock
./bin/helm export --evidence ./data/evidence --out evidence.tar
./bin/helm verify --bundle evidence.tar
```

Run the retained validation targets:

```bash
make test
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
- OpenAI-compatible proxy surface
- MCP server and bundle generation commands
- Evidence export and verification commands
- Public SDKs in `sdk/go`, `sdk/python`, `sdk/ts`, `sdk/rust`, and `sdk/java`

This repository does not ship hosted control-plane features, private operational tooling, browser UI, static UI, embedded UI, or HTML report surfaces.

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
| `api/openapi/` | OpenAPI contract used by the generated SDKs |
| `protocols/` | Protocol specifications and schema sources |
| `schemas/` | JSON schemas used by the kernel and verification flows |
| `tests/conformance/` | Conformance profile, checklist, and verification tests |
| `reference_packs/` | Example policy/reference bundles used by tests and examples |
| `deploy/helm-chart/` | Helm chart for running the kernel in Kubernetes |

## Documentation

Public OSS docs are sourced from this repository and canonically published through `docs.mindburn.org`. The owned docs set for sync is declared in `docs/public-docs.manifest.json`.

- [Quickstart](docs/QUICKSTART.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Conformance](docs/CONFORMANCE.md)
- [Verification](docs/VERIFICATION.md)
- [Publishing](docs/PUBLISHING.md)
- [Compatibility](docs/COMPATIBILITY.md)
- [SDK Index](docs/sdks/00_INDEX.md)
- [Security Model](docs/EXECUTION_SECURITY_MODEL.md)
- [OWASP Mapping](docs/OWASP_MCP_THREAT_MAPPING.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
