---
title: Developer Journey
last_reviewed: 2026-07-01
---

# Developer Journey

Use this page after the [Quickstart](QUICKSTART.md). Pick the path that matches
how your agent runs.

## Choose A Path

| If you want to... | Read |
| --- | --- |
| Protect Codex | [Codex integration](INTEGRATIONS/codex.md) |
| Protect Claude Code | [Claude Code integration](INTEGRATIONS/claude-code.md) |
| Scan an agent before enforcement | [Agent Risk Scan](reference/agent-risk-scan.md) |
| Govern MCP tools | [Govern MCP tools](guides/govern-mcp-tools.md) |
| Keep an OpenAI-compatible client | [Use the OpenAI-compatible proxy](guides/use-openai-compatible-proxy.md) |
| Verify receipts and EvidencePacks | [Export and verify EvidencePacks](guides/export-verify-evidencepacks.md) |
| Generate typed clients | [SDKs](sdks/00_INDEX.md) |
| Inspect every CLI command | [CLI reference](reference/cli.md) |
| Inspect every HTTP route | [HTTP API reference](reference/http-api.md) |

## Install

Published macOS CLI:

```bash
brew tap mindburn-labs/tap
brew trust mindburn-labs/tap
brew install helm-ai-kernel
helm-ai-kernel --version
```

Source build:

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
make build
./bin/helm-ai-kernel --version
```

Docker:

```bash
docker build -t ghcr.io/mindburn-labs/helm-ai-kernel:local .
docker compose up -d
```

After the tag-driven release and published registry verification complete,
Java SDK consumers can use the source-target Maven coordinate
`io.github.mindburnlabs:helm-sdk:0.7.2`:

```xml
<dependency>
  <groupId>io.github.mindburnlabs</groupId>
  <artifactId>helm-sdk</artifactId>
  <version>0.7.2</version>
</dependency>
```

Current source release target: `v0.7.2`.
The expected release URL is
`https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.7.2`. Do not
treat its assets as present until the normal release workflow attaches and
verifies them, including `v0.7.2.openvex.json` and `v0.7.2.json`.

After the source subdirectory tag is published and verified, Go SDK consumers
can pin `github.com/Mindburn-Labs/helm-ai-kernel/sdk/go@v0.7.2`; the expected
tag is `sdk/go/v0.7.2`.

## Local Boundary

```bash
helm-ai-kernel serve --policy ./release.high_risk.v3.toml
```

Source builds use:

```bash
./bin/helm-ai-kernel serve --policy ./release.high_risk.v3.toml
```

The local policy boundary defaults to `127.0.0.1:7714`.

## Verify A Decision

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/<decision>.json
```

For EvidencePacks:

```bash
helm-ai-kernel verify evidence-pack.tar
```

## Troubleshooting

Run the doctor before deeper debugging:

```bash
helm-ai-kernel doctor --json
```

Then use [Troubleshooting](TROUBLESHOOTING.md) for ports, setup, policy, proxy,
receipt, and verification failures.

## Source Truth

- `Makefile`
- `Dockerfile`
- `docker-compose.yml`
- `core/cmd/helm-ai-kernel/*`
- `api/openapi/helm.openapi.yaml`
- `docs/reference/cli.md`
- `docs/reference/agent-risk-scan.md`
- `docs/reference/http-api.md`
- `sdk/go`, `sdk/python`, `sdk/ts`, `sdk/rust`, `sdk/java`
- `examples/`
- `tests/conformance/`
- `scripts/check_documentation_coverage.py`
- `scripts/check_documentation_truth.py`
