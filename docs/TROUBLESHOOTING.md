---
title: TROUBLESHOOTING
last_reviewed: 2026-05-05
---

# Troubleshooting

## Audience

## Outcome

After this page you should know what this surface is for, which source files own the behavior, which public route or adjacent page to use next, and which validation command to run before changing the claim.

## Source Truth

- Public route: `helm-oss/troubleshooting`
- Source document: `helm-oss/docs/TROUBLESHOOTING.md`
- Public manifest: `helm-oss/docs/public-docs.manifest.json`
- Source inventory: `helm-oss/docs/source-inventory.manifest.json`
- Validation: `make docs-coverage`, `make docs-truth`, and `npm run coverage:inventory` from `docs-platform`

Do not expand this page with unsupported product, SDK, deployment, compliance, or integration claims unless the inventory manifest points to code, schemas, tests, examples, or an owner doc that proves the claim.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| The public page and source behavior disagree | Treat the source path in `Source Truth` as canonical, then update the docs and source-inventory row in the same change. |
| A link or route is missing from the docs website | Check `docs/public-docs.manifest.json`, `llms.txt`, search, and the per-page Markdown export before changing navigation. |
| A claim is not backed by code or tests | Remove the claim or add the missing code, example, schema, or validation command before publishing. |

## Diagram

This scheme maps the main sections of Troubleshooting in reading order.

```mermaid
flowchart LR
  Page["Troubleshooting"]
  A["First Diagnostic"]
  B["Auth Errors"]
  C["Egress / Network"]
  D["Timeouts"]
  E["Conformance Failures"]
  Page --> A
  A --> B
  B --> C
  C --> D
  D --> E
```

Common issues and solutions for HELM.

---

## First Diagnostic

Run `helm doctor --json` before deeper debugging when the CLI is installed but the runtime path is unclear. The doctor command checks local initialization, trust material, data directories, and common environment mistakes.

```bash
helm doctor --json
```

---

## Auth Errors

### `HELM_UNREACHABLE` in adapters

The adapter cannot reach the HELM server.

```bash
# Check HELM is running
curl http://127.0.0.1:7714/healthz

# Check the URL in your adapter config
export HELM_URL=http://127.0.0.1:7714
```

`helm server` still defaults to `127.0.0.1:8080`. The public quickstart uses `helm serve --policy ./release.high_risk.v3.toml`, which defaults to `127.0.0.1:7714`.
The separate `helm server` health endpoint uses `HELM_HEALTH_PORT` or `8081`;
`helm health` checks that health endpoint, not the main API port.

### `401 Unauthorized` from proxy

```bash
# Set your upstream API key
helm proxy --upstream https://api.openai.com/v1 --api-key $OPENAI_API_KEY

# Or via environment
export OPENAI_API_KEY=sk-...
helm proxy --upstream https://api.openai.com/v1
```

---

## Egress / Network

### Sandbox exec fails with "PREFLIGHT_DENIED"

The sandbox provider's egress policy is too restrictive or the provider is not configured.

```bash
# Check preflight details
helm sandbox exec --provider e2b --json -- echo test | jq .preflight

# Ensure provider credentials
export E2B_API_KEY=your-key
```

### MCP server unreachable over HTTP/SSE

```bash
# Start with explicit transport
helm mcp serve --transport http --port 9100

# Check firewall allows the port
curl http://localhost:9100/mcp
```

---

## Timeouts

### Proxy request timeout

```bash
# Increase wallclock limit (default: 120s)
helm proxy --upstream https://api.openai.com/v1 --max-wallclock 300s
```

### Sandbox execution timeout

```bash
# Increase timeout (default: 30s)
helm sandbox exec --provider opensandbox --timeout 60s -- long-running-command
```

---

## Conformance Failures

### `G0_JCS_CANONICALIZATION` fails

JCS canonicalization requires valid JSON. Check your tool arguments:

```bash
echo '{"b":2,"a":1}' | jq -S .   # sorted keys
```

### `G1_PROOFGRAPH` fails

ProofGraph requires at least one receipt in the evidence directory:

```bash
ls data/evidence/   # Should contain .json receipt files
```

### `G2A_EVIDENCE_PACK` fails

EvidencePack requires deterministic tar with epoch mtime:

```bash
# Export with HELM (ensures determinism)
helm export --evidence ./data/evidence --out evidence.tar

# Verify
helm verify evidence.tar
```

### `helm verify --online` fails but offline verification passes

`--online` requires a reachable public proof API and matching ledger metadata in the pack.

```bash
export HELM_LEDGER_URL=https://mindburn.org/api/proof/verify
helm verify evidence.tar --online
```

If the pack has no public anchor, use offline verification or regenerate the pack from a release asset with public proof metadata.

### `helm receipts tail` does not print events

Confirm the local boundary is running and that receipts are being emitted for the same agent id:

```bash
helm serve --policy ./release.high_risk.v3.toml
helm receipts tail --agent agent.titan.exec --server http://127.0.0.1:7714
```

---

## Common Errors

| Error                   | Cause                     | Fix                              |
| ----------------------- | ------------------------- | -------------------------------- |
| `ERR_TOOL_NOT_FOUND`    | Unknown tool URN          | Register tool in policy manifest |
| `ERR_SCHEMA_MISMATCH`   | Args don't match schema   | Check tool argument types        |
| `PROXY_ITERATION_LIMIT` | Too many tool call rounds | Increase `--max-iterations`      |
| `PROXY_WALLCLOCK_LIMIT` | Session too long          | Increase `--max-wallclock`       |
| `HELM_UNREACHABLE`      | Server down or wrong URL  | Check `helm health`              |
| `APPROVAL_REQUIRED`     | Human approval needed     | Complete approval ceremony       |
