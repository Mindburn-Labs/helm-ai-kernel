---
title: START_HERE
---

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
./bin/helm conform --level L2 --json
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

## CLI Quick Reference

```bash
./bin/helm doctor      # Diagnose system health and common problems
./bin/helm certify     # Certify an evidence pack against 7 compliance frameworks
./bin/helm workforce   # Manage agent fleet (hire, list, suspend, terminate)
./bin/helm policy suggest  # Auto-generate policy rules from execution history
./bin/helm policy verify   # Static analysis of policy bundles
```

## Next Steps

- [README](https://github.com/Mindburn-Labs/helm-oss#readme) — architecture and comparison
- [Security Model](../docs/SECURITY_MODEL.md) — TCB, threat model, crypto chain, hybrid signing, memory governance
- [Threat Model](../docs/THREAT_MODEL.md) — supply chain attacks, memory poisoning, tool poisoning defenses
- [Resilience Patterns](../docs/RESILIENCE_PATTERNS.md) — circuit breakers, SLO engine, ensemble scanning, cost estimation
- [Observability](../docs/OBSERVABILITY.md) — OpenTelemetry spans, Prometheus metrics, Grafana dashboards
- [Policy Bundles](../docs/POLICY_BUNDLES.md) — suggestion engine, static verification, bundle composition
- [OWASP MCP Mapping](../docs/OWASP_MCP_THREAT_MAPPING.md) — MCP supply chain defenses, rug-pull and typosquatting detection
- [Identity Interop](../docs/INTEGRATIONS/IDENTITY_INTEROP.md) — W3C DID, AIP delegation, continuous delegation
- [Deploy your own](../deploy/README.md) — 3-minute DigitalOcean deploy
- [SDK](../sdk/) — Python + TypeScript client libraries
- [Use Cases](../docs/use-cases/) — UC-001 through UC-012

---

## Common Pain Points

| Problem | Solution |
|---------|----------|
| "How do I see what HELM is doing?" | Enable OpenTelemetry (`helm.yaml` → `observability.otel.enabled: true`) or check Prometheus at `:9090/metrics` |
| "How do I write policies?" | Start with `helm policy suggest` to generate rules from history, then verify with `helm policy verify` |
| "How do I manage multiple agents?" | Use `helm workforce list` to see all agents, `helm workforce suspend <id>` to pause one |
| "How do I prove compliance?" | Run `helm certify --framework <name>` to produce a certified evidence pack |
| "My tool calls are being denied" | Run `helm doctor` to check config, then review ProofGraph for the denial reason code |

---

## Having Issues?

```bash
./bin/helm doctor   # Diagnoses common problems
```

File an issue: [github.com/Mindburn-Labs/helm-oss/issues](https://github.com/Mindburn-Labs/helm-oss/issues)
