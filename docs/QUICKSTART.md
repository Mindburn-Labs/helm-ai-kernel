---
title: HELM Quickstart — 5-Minute Proof Loop
---

# HELM Quickstart — 5-Minute Proof Loop

Goal: **prove HELM works without trusting us.** Every step is one command.

---

## Prerequisites

- Docker + Docker Compose
- Go 1.24+ (for building from source)
- `jq` (for JSON output)

---

## Step 1 — Start HELM

```bash
git clone https://github.com/Mindburn-Labs/helm-oss.git && cd helm-oss
docker compose up -d
```

Wait for health:
```bash
curl -s http://localhost:8080/healthz   # → OK
```

HELM is running with Postgres-backed ProofGraph, policy enforcement, and the OpenAI-compatible proxy.

---

## Step 2 — Trigger a Deny

Send a malformed tool call. HELM should fail-closed:

```bash
curl -s -X POST http://localhost:8080/mcp/v1/execute \
  -H 'Content-Type: application/json' \
  -d '{"method":"unknown_tool","params":{"bad_field":true}}' | jq '.error.reason_code'
```

**Expected:** `"DENY_TOOL_NOT_FOUND"` — denied with a deterministic reason code.

This is the PEP boundary in action. Unknown tool URNs, schema mismatches, and missing fields all produce `DENY` with a reason code. No fallthrough, no partial execution.

---

## Step 3 — Build from Source

```bash
make build
```

This produces `bin/helm`.

---

## Step 4 — View a Receipt

```bash
curl -s 'http://localhost:8080/api/v1/oss-local/decision-timeline?limit=1' | jq '.decisions[0]'
```

Each receipt contains:
- `id` / `hash` — stable receipt identifiers and content hash
- `lamport_clock` — causal ordering
- `principal` — who initiated
- `reason_code` — why it was allowed or denied

---

## Step 5 — Export EvidencePack

```bash
./bin/helm export --evidence ./data/evidence --out pack.tar.gz
```

The EvidencePack is a deterministic `.tar.gz`:
- Sorted file paths
- Epoch mtime (1970-01-01)
- Root uid/gid
- **Same content → same SHA-256, always**

---

## Step 6 — Offline Replay Verify

```bash
./bin/helm verify --bundle pack.tar.gz
```

**Expected:** `verification: PASS`

This runs with **no network access**. It verifies signatures, causal chain integrity, and policy compliance from the pack contents alone.

---

## Step 7 — Conformance L1 + L2

```bash
./bin/helm conform --level L2 --json | jq .
```

Conformance L1 (structural): JCS canonicalization, schema validation, PEP boundary, fail-closed.

Conformance L2 (temporal): Lamport ordering, checkpoint invariants, approval ceremony, WASI bounded compute.

---

## Step 8 — Run All Use Cases

```bash
make crucible
```

Runs UC-001 through UC-012. Each tests a specific enforcement property:

| UC | Tests |
|----|-------|
| UC-001 | PEP allows valid tool call |
| UC-002 | PEP denies schema mismatch |
| UC-003 | Approval ceremony timelock + challenge |
| UC-004 | WASI sandbox executes transform |
| UC-005 | WASI traps on gas/time/memory exhaustion |
| UC-006 | Idempotency (receipt-based dedup) |
| UC-007 | EvidencePack export CLI |
| UC-008 | Replay verify CLI |
| UC-009 | Output schema drift → hard error |
| UC-010 | Trust key rotation + replay |
| UC-011 | Island mode (build offline) |
| UC-012 | Conformance L1 + L2 gates |

---

## What Just Happened

1. HELM started with a Postgres-backed ProofGraph
2. Tool calls were intercepted, JCS-canonicalized, SHA-256 hashed, and receipted
3. A deny produced a deterministic reason code — no fallthrough
4. An EvidencePack was exported as a bit-identical archive
5. Offline verify proved the pack with zero network
6. Conformance L1 + L2 passed

Every step is reproducible. Every output is deterministic.

---

## Next

- [OpenAI proxy integration](../examples/python_openai_baseurl/main.py) — your app, one line change
- [Deploy your own](../deploy/README.md) — 3 minutes on DigitalOcean
- [Copy-paste demo](DEMO.md) — share these commands on HN/Reddit
- [Security model](SECURITY_MODEL.md) — TCB, threat model, crypto chain
