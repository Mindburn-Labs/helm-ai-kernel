---
title: Developer Journey
last_reviewed: 2026-05-12
---

# Developer Journey

This page is the source-backed end-to-end path for evaluating HELM OSS. It ties install, runtime, SDKs, policy, receipts, verification, deployment, conformance, release artifacts, and troubleshooting to live repository surfaces.

```mermaid
flowchart LR
  Install["install or build helm"] --> Serve["helm serve --policy"]
  Serve --> Demo["local proof demo"]
  Serve --> Proxy["optional helm proxy"]
  Serve --> Receipts["receipts and boundary records"]
  Receipts --> Verify["offline verification"]
  Verify --> Gates["docs and conformance gates"]
```

## Source Truth

- `Makefile`, `Dockerfile`, `docker-compose.yml`
- `core/cmd/helm/*`
- `api/openapi/helm.openapi.yaml`
- `docs/reference/cli.md`
- `docs/reference/http-api.md`
- `docs/reference/execution-boundary.md`
- `sdk/go`, `sdk/python`, `sdk/ts`, `sdk/rust`, `sdk/java`
- `examples/`, `deploy/helm-chart/`, `tests/conformance/`
- `scripts/check_documentation_coverage.py`
- `scripts/check_documentation_truth.py`

## Install

Use one of these current paths:

```bash
brew install mindburnlabs/tap/helm
helm --version
```

```bash
git clone https://github.com/Mindburn-Labs/helm-oss.git
cd helm-oss
make build
./bin/helm --version
```

```bash
docker build -t ghcr.io/mindburn-labs/helm-oss:local .
docker compose up -d
```

Docker Compose exposes the service on its compose-configured port. The local source quickstart uses `helm serve` on `127.0.0.1:7714`.

## Local Boundary

```bash
./bin/helm serve --policy ./release.high_risk.v3.toml
```

Expected ready line:

```text
helm-edge-local - listening :7714 - ready
```

Open the self-hostable Console by adding `--console`:

```bash
make build-console
./bin/helm serve --policy ./release.high_risk.v3.toml --console
```

## First Proof

Run, verify, and tamper-check a local receipt:

```bash
curl http://127.0.0.1:7714/api/demo/run \
  -H 'content-type: application/json' \
  -d '{"action_id":"export_customer_list","policy_id":"agent_tool_call_boundary"}'
```

```bash
curl http://127.0.0.1:7714/api/demo/verify \
  -H 'content-type: application/json' \
  -d '{"receipt":{...},"expected_receipt_hash":"<receipt_hash>"}'
```

```bash
curl http://127.0.0.1:7714/api/demo/tamper \
  -H 'content-type: application/json' \
  -d '{"receipt":{...},"expected_receipt_hash":"<receipt_hash>","mutation":"flip_verdict"}'
```

## Optional OpenAI-Compatible Proxy

Use the proxy when the application already supports an OpenAI-compatible `base_url` or `baseURL`.

```bash
python3 scripts/launch/mock-openai-upstream.py --port 19090
./bin/helm proxy --upstream http://127.0.0.1:19090/v1 --port 9090 --receipts-dir ./helm-receipts
```

Configure the client base URL as:

```text
http://localhost:9090/v1
```

The example directories named `*_openai_baseurl` currently exercise HELM HTTP or SDK clients. They are not evidence that the OpenAI SDK examples are runnable unless their code imports the OpenAI SDK and reads the documented base URL variable.

## Receipts And Boundary Records

HELM OSS is useful only when both allowed and denied outcomes are recorded.

```bash
./bin/helm receipts tail --agent agent.demo.exec --server http://127.0.0.1:7714
curl 'http://127.0.0.1:7714/api/v1/receipts?limit=20'
./bin/helm boundary records --json
```

The CLI receipt tail requires `--agent`; the HTTP list route is the unfiltered inspection path.

## Policy Fixtures

**Launch Demo Suite:** You can evaluate a complete, end-to-end set of `ALLOW`,
`DENY`, and `ESCALATE` outcomes using the canonical launch suite in
`examples/launch/`. Run `make launch-smoke` to verify policy execution,
receipt proof generation, MCP quarantine behavior, and localhost-only proxy
behavior.

**SDK Examples:** Run `make sdk-examples-smoke` to build the Python and
TypeScript SDKs, start a local boundary, and validate ALLOW, DENY, MCP
fail-closed denial, signed receipt verification, sandbox preflight, and
EvidencePack verification.

Use allow and deny fixtures from `examples/policies/` when validating
policy-language behavior. The policy bundle command supports CEL, Rego, and
Cedar:

```bash
./bin/helm bundle build --language cel examples/policies/cel/example.cel
./bin/helm bundle build --language rego examples/policies/rego/example.rego
./bin/helm bundle build --language cedar --entities examples/policies/cedar/entities.json examples/policies/cedar/example.cedar
```

`helm bundle build` takes the policy source as the positional argument. It does not accept `--policy`; that flag belongs to `helm serve`.

## EvidencePack Verification

Run offline verification first:

```bash
./bin/helm verify evidence-pack.tar
./bin/helm verify evidence-pack.tar --json
```

Run online verification only after offline verification passes:

```bash
./bin/helm verify evidence-pack.tar --online
```

`--online` checks envelope or root metadata against `HELM_LEDGER_URL` or the public proof verifier. Online checks are additive and do not replace offline receipt and ProofGraph verification.

## SDKs

| Language | Public package status | Validation |
| --- | --- | --- |
| Python | `pip install helm-sdk` | `make test-sdk-py` |
| TypeScript / JavaScript | `npm install @mindburn/helm` | `make test-sdk-ts` |
| Rust | `cargo add helm-sdk` | `make test-sdk-rust` |
| Go | source/module path `github.com/Mindburn-Labs/helm-oss/sdk/go`; pin `@main` or a commit until tagged module releases are aligned | `cd sdk/go && go test ./...` |
| Java | source-available local Maven build under `sdk/java`; public package coordinate not verified | `make test-sdk-java` |

Use [SDK Index](sdks/00_INDEX.md) before publishing SDK install instructions.

## MCP

Use MCP when the integration is tool-oriented and the client expects an MCP server, client config, or MCP bundle:

```bash
./bin/helm mcp serve
./bin/helm mcp pack --client claude-desktop --out helm.mcpb
./bin/helm mcp install --client claude-code
```

Unknown MCP servers and tools start in quarantine. They must be inspected and approved before side effects are dispatched.

## Deployment

Use Docker Compose for local deployment checks:

```bash
docker compose up -d
docker compose ps
```

Use the Kubernetes Helm chart only with a Kubernetes Helm v3 binary:

```bash
helm lint deploy/helm-chart
helm install helm-oss deploy/helm-chart
```

If the `helm` command on your machine resolves to this HELM OSS binary, use `KUBE_HELM_CMD` or a pinned containerized chart runner instead.

## Release And Conformance Gates

Current public release: `v0.4.0`, published on 2026-04-25 at <https://github.com/Mindburn-Labs/helm-oss/releases/tag/v0.4.0>.

The release page includes Darwin/Linux/Windows binaries, `SHA256SUMS.txt`, `sbom.json`, `release-attestation.json` metadata, `evidence-pack.tar`, `release.high_risk.v3.toml`, `helm.mcpb`, and `helm.rb`. Do not claim Cosign bundle or OpenVEX verification for that release because those files are not attached to `v0.4.0`.

Run conformance and docs gates:

```bash
cd tests/conformance && go test ./...
cd ../..
make docs-coverage
make docs-truth
```

Run release checks when release docs or packaging behavior changes:

```bash
make test
make test-console
make test-platform
make test-all
make crucible
make launch-smoke
make launch-ready
make verify-fixtures
make release-assets
```

## Troubleshooting

| Symptom | Likely cause | First check |
| --- | --- | --- |
| `helm serve` starts but clients still bypass HELM | client base URL still points to upstream provider | log request host and set the client base URL to HELM |
| no receipts appear | wrong server, directory, or agent id | run `helm receipts tail --agent <id> --server http://127.0.0.1:7714` or query `/api/v1/receipts` |
| denied call retries forever | app treats policy denial as transient | handle `DENY` as a final authorization result |
| offline verification fails | EvidencePack is incomplete or modified | verify a complete pack and run `make verify-fixtures` |
| MCP call fails with OAuth scope error | token lacks required scope or resource indicator | inspect `HELM_OAUTH_RESOURCE` and `HELM_OAUTH_SCOPES` |
| chart deploy fails | wrong Helm binary or invalid values | use Kubernetes Helm v3 and run `helm lint deploy/helm-chart` |
