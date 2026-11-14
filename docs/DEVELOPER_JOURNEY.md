---
title: Developer Journey
last_reviewed: 2026-08-21
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
brew install mindburn-labs/tap/helm-ai-kernel
helm-ai-kernel --version
```

Current source build:

The source build uses Go 1.26.11, pinned by `go.work` and `mise.toml`. The
recipe explicitly trusts the checked-out mise configuration and installs the
pinned toolchain before building. If mise is unavailable, use a compatible
native Go toolchain instead.

```bash
git clone https://github.com/Mindburn-Labs/helm-ai-kernel.git
cd helm-ai-kernel
mise trust
mise install
mise exec -- make build
./bin/helm-ai-kernel --version
```

Docker:

```bash
docker build -t ghcr.io/mindburn-labs/helm-ai-kernel:local .
docker compose up -d
```

After the tag-driven release and published registry verification complete,
Java SDK consumers can use the source-target Maven coordinate
`io.github.mindburnlabs:helm-sdk:0.12.0`:

```xml
<dependency>
  <groupId>io.github.mindburnlabs</groupId>
  <artifactId>helm-sdk</artifactId>
  <version>0.12.0</version>
</dependency>
```

Current source release target: `v0.12.0`.
The expected release URL is
`https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.12.0`. Do not
treat its assets as present until the normal release workflow attaches and
verifies them, including `v0.12.0.openvex.json` and `v0.12.0.json`.

After the source subdirectory tag is published and verified, Go SDK consumers
can pin `github.com/Mindburn-Labs/helm-ai-kernel/sdk/go@v0.12.0`; the expected
tag is `sdk/go/v0.12.0`.

## Local Boundary

Run the connected HTTP walkthrough from the source checkout:

```bash
mise exec -- make first-use
```

It starts an authenticated local server under the
`examples/launch/policies/agent_tool_call_boundary.toml` policy, obtains an
`ALLOW` for `read-ticket` and a `DENY` for `dangerous-shell`, fetches their
`receipt.v5` records and checks them offline with `bin/receipt_verify` and the
server's exported `root.pub`. It also checks missing credentials, the wrong
tenant, a tampered receipt and an unrelated public key. No tools are dispatched.
See the [walkthrough](../examples/first-use/README.md) for its evidence files.

For a server you can continue calling, run this in a terminal at the repository
root. These commands use local SQLite state and a generated per-install admin
key:

```bash
env -u DATABASE_URL -u HELM_ADMIN_API_KEY \
  HELM_RUNTIME_TENANT_ID=local-demo \
  HELM_RUNTIME_PRINCIPAL_ID=local-demo-principal \
  ./bin/helm-ai-kernel serve \
    --policy examples/launch/policies/agent_tool_call_boundary.toml \
    --data-dir ./data/first-use --addr 127.0.0.1 --port 7714
```

The command binds `127.0.0.1:7714`. In a second terminal at the same
repository root, supply the generated credential and its configured scope:

```bash
export HELM_ADMIN_API_KEY="$(cat ./data/first-use/admin.key)"
curl --fail-with-body -sS http://127.0.0.1:7714/api/v1/evaluate \
  -H "Authorization: Bearer $HELM_ADMIN_API_KEY" \
  -H 'X-Helm-Tenant-ID: local-demo' \
  -H 'X-Helm-Principal-ID: local-demo-principal' \
  -H 'Content-Type: application/json' \
  -d '{"tool":"read-ticket","effect_level":"ticket:FIRST-USE","session_id":"first-use","args":{}}'
```

Expect `verdict: ALLOW` and a `receipt_id`. Replacing the tool with
`dangerous-shell` and the effect level with `system:shell` returns `DENY`.
Use the same headers to fetch `GET /api/v1/receipts/{receipt_id}`. Stop the
server with Ctrl-C when finished. Keep `data/first-use` private: it contains
local signing keys and credentials. The [HTTP reference](reference/http-api.md)
describes the authentication and tenant contracts.

## Verify A Decision

For an HTTP evaluation receipt saved from the route above:

```bash
cp ./data/first-use/root.pub ./root.pub
./bin/receipt_verify --receipt ./receipt.json --key-file ./root.pub --json
```

The standalone verifier performs no network access. Pin the public key from a
source you trust; the locally exported key identifies this local server only.
A public key copied from an untrusted receipt cannot establish signer trust.

For workstation hook decisions:

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/<decision>.json
```

This checks signature **integrity**; signer **trust** (`signer_trusted`) is a
separate verdict against an expected workstation public key — the local
`--data-dir` key by default, or an out-of-band `--trusted-public-key-file`
pin for copied receipts — see
[local signer and trusted verification](reference/workstation-governance.md#local-signer-and-trusted-verification).
Pre-v0.7.3 derivable-seed receipts remain untrusted.

For EvidencePacks:

```bash
helm-ai-kernel verify evidence-pack.tar
```

## Troubleshooting

Run the doctor before deeper debugging:

```bash
helm-ai-kernel doctor --format json
```

Then use [Troubleshooting](TROUBLESHOOTING.md) for ports, setup, policy, proxy,
receipt, and verification failures. Interactive TTY opens the operator TUI by
default; use `HELM_NO_TUI=1` or `TERM=dumb` for the text front door.

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
