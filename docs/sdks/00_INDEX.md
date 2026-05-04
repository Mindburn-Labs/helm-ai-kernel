# SDK Index

HELM OSS retains public SDK surfaces for teams that want typed clients instead of raw HTTP calls. Use SDKs for application integration, CLI-adjacent automation, verifier helpers, and generated examples.

| Language | Path | Package |
| --- | --- | --- |
| Go | `sdk/go` | Go module under this repository |
| Python | `sdk/python` | `helm-sdk` |
| TypeScript | `sdk/ts` | `@mindburn/helm` |
| Rust | `sdk/rust` | `helm-sdk` |
| Java | `sdk/java` | `com.github.Mindburn-Labs:helm-sdk` |

Each SDK directory owns its README, package metadata, local test command, usage example, and release-note baseline. HTTP client and type material are generated from `api/openapi/helm.openapi.yaml` where that spec is available. Protobuf bindings are generated from `protocols/proto/` where present.

## Selection Guide

- Use TypeScript for Next.js apps, docs examples, and CI verifier scripting.
- Use Python for notebooks, research harnesses, and quick integration checks.
- Use Go or Rust for long-running infrastructure components.
- Use Java when HELM is integrated into JVM services or enterprise test harnesses.

## Quality Bar

Every SDK example should show the server URL, auth or policy assumptions, one allowed request, one denied request, and receipt or verifier behavior. Do not publish SDK claims that are not backed by generated types, tests, or example output.
