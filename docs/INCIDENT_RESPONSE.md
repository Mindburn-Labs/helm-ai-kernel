---
title: Incident Response Guide
---

# HELM Incident Response Guide

This guide covers how HELM's governance infrastructure supports incident detection, response, and post-incident analysis for AI agent operations.

## Temporal Guardian: Automated Escalation

The Temporal Guardian (`core/pkg/guardian/temporal.go`) provides automated incident detection and graduated response. It monitors agent effect frequency in a sliding window and escalates through 5 levels.

### Escalation Ladder

```
OBSERVE ──(10 eff/s for 5s)──> THROTTLE ──(50 eff/s for 3s)──> INTERRUPT
                                                                    |
FAIL_CLOSED <──(200 eff/s for 1s)── QUARANTINE <──(100 eff/s for 2s)┘
```

### Response Actions by Level

| Level | Agent Effects | Operator Action Required |
|---|---|---|
| OBSERVE | All pass | None — monitoring |
| THROTTLE | Rate-limited, excess delayed | None — auto-managed |
| INTERRUPT | Paused | Acknowledge to resume |
| QUARANTINE | Blocked entirely | Review and explicitly unblock |
| FAIL_CLOSED | Emergency halt | Root cause analysis required |

### Auto De-escalation

De-escalation occurs when:
1. Effect rate drops below the current level's threshold
2. The cooldown period for the current level has elapsed
3. No new violations during cooldown

Cooldown periods: THROTTLE 30s, INTERRUPT 60s, QUARANTINE 120s, FAIL_CLOSED 300s.

## Kill Switches

### Global Freeze

**Package:** `core/pkg/kernel/freeze.go`

The `FreezeController` halts ALL agent operations instantly:

```bash
helm freeze                    # Freeze all operations
helm unfreeze                  # Resume operations
```

When frozen, every `EvaluateDecision` call returns `VerdictDeny` with `ReasonSystemFrozen`. Uses `atomic.Bool` for lock-free hot-path reads — zero overhead when unfrozen.

### Per-Agent Kill

**Package:** `core/pkg/kernel/agent_kill.go`

Kill specific agents without affecting others:

```bash
helm kill <agent-id> --reason "Anomalous behavior detected"
helm revive <agent-id>
helm killed                    # List all killed agents
```

Every kill/revive action produces a receipted `AgentKillReceipt` with SHA-256 content hash, stored in the ProofGraph as `AGENT_KILL` or `AGENT_REVIVE` nodes.

## Evidence Preservation

### During Incidents

HELM automatically preserves evidence during incidents:

1. **ProofGraph** — Every decision (including denials) is recorded as a signed node with causal ordering
2. **EvidencePack** — Deterministic tar archives of governance decisions, tool transcripts, network logs, and policy decisions
3. **Audit Trail** — SHA-256 hash-chained tamper-evident log of all actions
4. **Nondeterminism Receipts** — LLM outputs and external API calls are bounded and receipted

### Post-Incident Analysis

1. **Export evidence pack:** Contains all decisions, receipts, and proof graph nodes for the incident window
2. **Verify offline:** Evidence packs can be independently verified without access to the HELM server
3. **Replay ProofGraph:** Walk the causal DAG to reconstruct the exact sequence of events
4. **SLO review:** Check error budget burn rate and SLO compliance during the incident

## Compliance Reporting

After incident resolution, HELM can generate compliance evidence for:

- **SOX** — Decision audit trail with tamper-evident chain
- **HIPAA** — Data access logs with policy enforcement proof
- **GDPR** — Data processing decisions with consent verification
- **SEC** — Trade-related decision receipts with timing proof
- **MiCA/DORA** — Crypto-asset operation governance evidence
- **FCA** — Financial services conduct evidence

Each regulatory framework has dedicated evidence export in `core/pkg/compliance/`.
