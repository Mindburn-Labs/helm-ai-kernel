---
title: HELM Demo — Copy-Paste Commands
---

# HELM Demo — Copy-Paste Commands

Share this page. Every command below produces verifiable output.

---

## Start

```bash
git clone https://github.com/Mindburn-Labs/helm-oss.git && cd helm-oss
docker compose up -d
curl -s http://localhost:8080/healthz
```
**Expected:** `OK`

---

## Trigger a Deny

```bash
curl -s http://localhost:8080/v1/tools/execute \
  -H 'Content-Type: application/json' \
  -d '{"tool":"unknown_tool","args":{"bad_field":true}}' | jq .
```
**Expected:**
```json
{
  "status": "DENIED",
  "reason_code": "ERR_TOOL_NOT_FOUND",
  "receipt_hash": "sha256:..."
}
```
HTTP status: `403 Forbidden`. Reason code is deterministic: always `ERR_TOOL_NOT_FOUND` for unknown tools.

---

## Trigger an Allow

```bash
make build
./bin/helm conform --level L1 --json | jq .
```
**Expected:**
```json
{
  "profile": "SMB",
  "pass": true,
  "gates": 3,
  "failed": 0
}
```

---

## Export EvidencePack

```bash
./bin/helm export --evidence ./data/evidence --out pack.tar.gz
ls -la pack.tar.gz
shasum -a 256 pack.tar.gz
```
**Expected:** file `pack.tar.gz` (deterministic). Same content → same SHA-256, every time.

---

## Offline Verify

```bash
./bin/helm verify --bundle pack.tar.gz
```
**Expected output line:** `verification: PASS` — no network required, air-gapped safe.

---

## Full Conformance L1 + L2

```bash
./bin/helm conform --level L2 --json | jq .
```
**Expected:**
```json
{
  "profile": "CORE",
  "pass": true,
  "gates": 9,
  "failed": 0
}
```

---

## Run All 12 Use Cases

```bash
make crucible
```
**Expected:**
```
  UC-001: PEP Allow ... ✅ PASS
  UC-002: PEP Fail-Closed ... ✅ PASS
  UC-003: Approval Ceremony ... ✅ PASS
  UC-004: WASM Transform ... ✅ PASS
  UC-005: WASM Exhaustion ... ✅ PASS
  UC-006: Idempotency ... ✅ PASS
  UC-007: Export CLI Build ... ✅ PASS
  UC-008: Replay CLI Build ... ✅ PASS
  UC-009: Output Drift ... ✅ PASS
  UC-010: Trust Rotation ... ✅ PASS
  UC-011: Island Mode ... ✅ PASS
  UC-012: Conformance Gates ... ✅ PASS

Results: 12 passed, 0 failed (of 12)
```

---

## ProofGraph Inspection

```bash
curl -s http://localhost:8080/api/v1/proofgraph | jq '.nodes | length'
```

---

## Links

- [README](../README.md) — architecture + comparison
- [QUICKSTART](QUICKSTART.md) — annotated walkthrough
- [Deploy](../deploy/README.md) — run on DigitalOcean in 3 minutes
