---
title: Quickstart
last_reviewed: 2026-05-12
---

# Quickstart

This is the shortest current HELM OSS path: build or install the CLI, start a local fail-closed execution boundary, run the built-in proof demo, inspect receipts, and run the docs truth gates.

```mermaid
flowchart LR
  Install["install or build helm"] --> Serve["helm serve :7714"]
  Serve --> Demo["demo run and verify"]
  Serve --> Receipts["signed receipts"]
  Receipts --> Verify["offline verification"]
```

## Source Truth

- `core/cmd/helm/server_cmd.go`
- `core/cmd/helm/demo_routes.go`
- `core/cmd/helm/proxy_cmd.go`
- `core/cmd/helm/receipts_cmd.go`
- `core/cmd/helm/verify_cmd.go`
- `api/openapi/helm.openapi.yaml`
- `release.high_risk.v3.toml`

## 1. Install Or Build

Use Homebrew for the published macOS CLI:

```bash
brew install mindburnlabs/tap/helm
helm --version
```

Use a source build when editing this repository:

```bash
git clone https://github.com/Mindburn-Labs/helm-oss.git
cd helm-oss
make build
./bin/helm --version
```

Use Docker when you want a clean local runtime:

```bash
docker build -t ghcr.io/mindburn-labs/helm-oss:local .
docker compose up -d
```

## 2. Start A Local Boundary

```bash
./bin/helm serve --policy ./release.high_risk.v3.toml
```

Expected ready line:

```text
helm-edge-local - listening :7714 - ready
```

If you installed with Homebrew, replace `./bin/helm` with `helm`.

Run the basic boundary checks in another shell:

```bash
./bin/helm boundary status --json
./bin/helm conform negative --json
./bin/helm mcp authorize-call --server-id new-server --tool-name file.delete --json
./bin/helm sandbox preflight --runtime wazero --json
```

The MCP authorization example should fail closed until the server identity, tool schema, scopes, and policy state are approved.

## 3. Run The Built-In Proof Demo

The local demo routes are implemented in the CLI server and exercise receipt verification without requiring a hosted service.

```bash
curl http://127.0.0.1:7714/api/demo/run \
  -H 'content-type: application/json' \
  -d '{"action_id":"export_customer_list","policy_id":"agent_tool_call_boundary"}'
```

Copy the returned `receipt` and `proof_refs.receipt_hash`, then verify it:

```bash
curl http://127.0.0.1:7714/api/demo/verify \
  -H 'content-type: application/json' \
  -d '{"receipt":{...},"expected_receipt_hash":"<receipt_hash>"}'
```

Tamper checks must fail:

```bash
curl http://127.0.0.1:7714/api/demo/tamper \
  -H 'content-type: application/json' \
  -d '{"receipt":{...},"expected_receipt_hash":"<receipt_hash>","mutation":"flip_verdict"}'
```

## 4. Optional OpenAI-Compatible Proxy

Start the proxy only when an existing client can set an OpenAI-style base URL:

```bash
python3 scripts/launch/mock-openai-upstream.py --port 19090
```

Then start the proxy against that local upstream:

```bash
./bin/helm proxy \
  --upstream http://127.0.0.1:19090/v1 \
  --port 9090 \
  --receipts-dir ./helm-receipts
```

Point the client at:

```text
http://localhost:9090/v1
```

The retained source examples under `examples/*_openai_baseurl/` are HELM HTTP/SDK examples, not verified OpenAI SDK examples. Use [OpenAI-Compatible Proxy Integration](INTEGRATIONS/openai_baseurl.md) for the proxy contract.

## 5. Inspect Receipts

The CLI receipt tail requires an agent id:

```bash
./bin/helm receipts tail --agent agent.demo.exec --server http://127.0.0.1:7714
```

For an unfiltered local list, use the HTTP API:

```bash
curl 'http://127.0.0.1:7714/api/v1/receipts?limit=20'
```

## 6. Verify Evidence

`helm verify` is offline-first and succeeds only when the EvidencePack contains the required roots, proof material, and receipts.

```bash
./bin/helm verify evidence-pack.tar
./bin/helm verify evidence-pack.tar --json
```

Use the `v0.5.0` release `evidence-pack.tar` or an operator-generated pack known to contain ProofGraph and receipt material. Do not treat the local onboarding demo export as verified unless it includes those records.

## 7. Validate The Checkout

```bash
make docs-coverage
make docs-truth
cd core && go test ./cmd/helm -run 'Test.*Route|Test.*OpenAPI|Test.*Receipt' -count=1
```

Run broader targets when you changed their surface:

```bash
make test-console
make test-design-system
make verify-fixtures
```

## Common Failures

| Symptom | Cause | Fix |
| --- | --- | --- |
| client call reaches the upstream provider directly | base URL still points to the provider | set the client base URL to HELM and log the request host |
| `helm receipts tail` exits with usage | missing required agent filter | pass `--agent <id>` or use `GET /api/v1/receipts` for an unfiltered list |
| denied request retries forever | client treats policy denial as transient | handle `DENY` as a final authorization result |
| `helm verify` fails | EvidencePack is incomplete or modified | use a complete pack and run `make verify-fixtures` |
| Docker path fails | local image or compose state is stale | rebuild the image and restart `docker compose` |
