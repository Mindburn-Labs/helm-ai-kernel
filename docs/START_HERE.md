# Start Here

Go from zero to verified HELM in 5 minutes.

---

## Step 1 — Run HELM (30 seconds)

```bash
git clone https://github.com/Mindburn-Labs/helm-oss.git && cd helm-oss
docker compose up -d
curl -s http://localhost:8080/healthz   # → OK
```

## Step 2 — Trigger a Tool Call

### Option A: OpenAI proxy (1 line change)

```python
import openai
client = openai.OpenAI(base_url="http://localhost:8080/v1")
# Every tool call now gets a cryptographic receipt
```

### Option B: Build + use CLI

```bash
make build
./bin/helm doctor   # Check system health
```

## Step 3 — Run Conformance (UC-012)

```bash
# Run all 12 use cases including conformance L1/L2
make crucible

# Or run conformance directly
./bin/helm conform --profile L2 --json
```

Expected: 12/12 use cases pass, conformance L1+L2 verified.

## Step 4 — Proof Loop

```bash
# Export a deterministic EvidencePack
./bin/helm export --evidence ./data/evidence --out pack.tar

# Verify offline (air-gapped safe)
./bin/helm verify --bundle pack.tar
```

## Step 5 — See the ProofGraph

```bash
# Health + ProofGraph timeline
curl -s http://localhost:8080/api/v1/proofgraph | jq '.nodes | length'
```

---

## What Just Happened

1. **HELM started** as a kernel with Postgres-backed ProofGraph
2. **Tool calls** were intercepted, validated (JCS + SHA-256), and receipted
3. **Conformance** verified L1 (structural) and L2 (temporal + checkpoint)
4. **EvidencePack** was exported as a deterministic `.tar`
5. **Offline verify** proved the pack is valid with zero network access

Every step produced signed, append-only, replayable proof.

---

## Next Steps

- [README](https://github.com/Mindburn-Labs/helm-oss#readme) — architecture and comparison
- [Security Model](../docs/SECURITY_MODEL.md) — TCB, threat model, crypto chain
- [Deploy your own](../deploy/README.md) — 3-minute DigitalOcean deploy
- [SDK](../sdk/) — Python + TypeScript client libraries
- [Use Cases](../docs/use-cases/) — UC-001 through UC-012

---

## Having Issues?

```bash
./bin/helm doctor   # Diagnoses common problems
```

File an issue: [github.com/Mindburn-Labs/helm-oss/issues](https://github.com/Mindburn-Labs/helm-oss/issues)
