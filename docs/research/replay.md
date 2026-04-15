---
title: Deterministic Replay — HELM's Forensic Primitive for AI Agents
---

# Deterministic Replay — HELM's Forensic Primitive for AI Agents

**Thesis**: The single most common failure mode in agentic AI systems is that when something goes wrong, nobody can reproduce what happened. HELM solves this with deterministic replay — reconstructing any past agent session from its EvidencePack and re-executing the governed decisions bit-identically. No competing governance toolkit provides this today.

## Why this matters

The 2025 empirical study of agent developer challenges (arXiv [2510.25423](https://arxiv.org/html/2510.25423v1)) identified **reproducibility** as the #1 developer pain point in production agent systems. The 2025 AI Agent Index (arXiv [2602.17753](https://arxiv.org/abs/2602.17753)) found the same pattern at enterprise scale: developers can't debug, auditors can't verify, regulators can't inspect.

The root cause isn't LLMs being nondeterministic. It's that the *governance* layer — the layer that decides what a tool call is allowed to do — is usually stateless middleware that doesn't capture the causal chain that produced a decision. Fix the governance layer and you get replay, even if the LLM itself is non-deterministic.

## What "deterministic replay" means in HELM

A HELM session is fully reconstructable from three artifacts:

1. **EvidencePack** (`core/pkg/evidencepack/`) — JCS-canonical manifest + SHA-256-hashed blobs + TAR archive. Contains every decision record, every receipt, and every policy bundle hash used during the session.
2. **ProofGraph** (`core/pkg/proofgraph/`) — causal DAG with Lamport-ordered nodes (INTENT → EFFECT chains). Each node references its parents, so the full causal tree is a traversal of the graph.
3. **Kernel snapshot** (`core/pkg/kernel/`) — deterministic reducer state, PRNG seed, concurrency artifacts. The kernel captures every source of nondeterminism (clock, random, scheduler order) so a replay sees the same state evolution.

Given those three, `helm replay` re-runs every decision in original Lamport order, re-evaluates policy at each step, and compares the replayed verdict to the stored verdict. Any divergence is a **BUG** — it means something in the system is nondeterministic that shouldn't be. The non-determinism-detection is itself a feature: the CI chaos drill (`.github/workflows/chaos-drill.yml`) includes `kernel-nondeterminism-detected` as a failing-invariant scenario.

## Current implementation

- **Driver**: `core/pkg/replay/engine.go` + `harness.go` + `manifest.go` (+ 14 supporting files).
- **CLI**: `helm replay --evidence=<dir> --json` (`core/cmd/helm/replay_cmd.go`) returns exit 0 on match, 1 on divergence, 2 on runtime error.
- **Comparison**: `core/pkg/replay/compare.go` diffs replayed state against stored state at each Lamport step.
- **VCR tape bridge**: `core/pkg/replay/tape_bridge.go` translates between the tape format used by network-recorded fixtures and the ProofGraph format used by replay.
- **Visualizer**: `core/pkg/replay/visualizer.go` renders a divergence trace as a human-readable report.

## Three use cases

### 1. Debug
Developer ships an agent feature. A user reports "the bot refused to do X." Developer runs `helm replay --session=<id>` and gets the exact Lamport-ordered chain of decisions that led to the refusal, with the policy bundle hash that was active at each step. No re-running the agent, no reproducing environment state — the replay is the trace.

### 2. Audit
Auditor needs to verify that no GDPR-violating action was executed in the last 90 days. Auditor receives an EvidencePack, runs `helm verify` (signature + tamper check), then `helm replay` to re-evaluate the session against the current policy bundle. If the replay produces a verdict that disagrees with what was executed, the auditor has mechanical evidence of a divergence — either a bug or tampering, either way actionable.

### 3. Dispute resolution
Two organizations disagree about whether an agent action was authorized by a delegation. Each holds the same EvidencePack. Each runs `helm replay` against it. If they get the same verdict, the dispute is settled mechanically. If different verdicts, one of them is running a modified HELM binary and the disagreement is the proof.

## Why AGT cannot replay

Microsoft's Agent Governance Toolkit (April 2026, v3.1.0) has no replay primitive. Its `VectorClockManager` and `CausalAttributor` appear in package exports but have no visible implementation, no tests, and no CLI. Its audit log is append-only JSONL with no signature or canonical encoding — you can read what was logged, you cannot re-execute it.

Building replay on AGT's architecture would require:
1. Replacing the rolling JSONL audit log with a canonical hash-chained format.
2. Capturing kernel-level nondeterminism sources (AGT's Python middleware has no kernel layer).
3. Moving from a single-layer stateless `PolicyEvaluator` to a layered signed-bundle model with hash-bound replay.
4. Adding a deterministic reducer (AGT doesn't have one).

That's a rewrite off Python middleware, not an incremental feature. HELM's architectural choice to put governance underneath rather than beside the agent is what enables replay — and is one of the two biggest structural moats vs AGT (the other being the fail-closed firewall).

## Determinism boundary

HELM is explicit about what it replays deterministically and what it does not:

| In scope (deterministic replay guaranteed) | Out of scope |
|---|---|
| Guardian gate evaluation order + outcomes | LLM completion text (non-deterministic by nature) |
| Policy bundle evaluation (CEL + WASM) | External API response bodies (recorded, replayed from tape) |
| Effect permit issuance + binding | Wall-clock precision beyond Lamport ordering |
| ProofGraph node appending + causal parents | OS-level thread scheduling (reducer absorbs this) |
| Crypto operations (Ed25519 signatures, SHA-256 hashes) | Network latency |
| Budget/cost accumulation | Tool-process internal state (HELM doesn't see inside tools) |

LLMs are probabilistic. Networks have jitter. Tools have their own state. HELM's contract is: given the observations the kernel captured, the governance decisions are reproducible bit-identically. The LLM prompt is an observation; its completion is an observation recorded in a receipt. Replay does not re-query the LLM.

## Known gaps and future work

- **Cross-OS determinism matrix** (Phase 4 continuation): replay is tested on Linux; explicit CI matrix covering macOS + Windows is planned.
- **Session-ID-based lookup** (Phase 4 continuation): current CLI takes `--evidence=<dir>` + tape files; convenience flag `--session=<id>` is a usability enhancement.
- **Divergence diff UX** (Phase 4 continuation): raw diff is readable today; a structured human-oriented divergence report (which rule fired differently, which value differs) is work-in-progress.
- **ZK-proof of replay outcome** (Phase 5): "Prove I replayed and got the same result, without revealing the session contents." Builds on `core/pkg/crypto/zkp/` scaffolding.

## Operational recipes

### Replay the happy path

```bash
# Export a session to a pack
helm export --evidence ./data/evidence --out session.tar

# Verify signature + tamper (authoritative verifier)
helm verify --bundle session.tar

# Replay and assert identity
helm replay --evidence ./data/evidence --json > replay.json
jq '.matches' replay.json   # → true
```

### Force a divergence (for testing)

```bash
# Change the policy bundle between execution and replay
helm replay --evidence ./data/evidence --policy-bundle ./different-bundle.wasm --json > replay.json
jq '.divergence[]' replay.json   # → list of steps that differ
```

### Audit fleet-wide

```bash
# Replay every pack in a directory, fail if any diverges
for pack in /evidence/*.tar; do
  helm replay --evidence "$pack" --quiet || echo "DIVERGENCE: $pack"
done
```

## References

- Package source: [core/pkg/replay/](../../core/pkg/replay/)
- CLI: [core/cmd/helm/replay_cmd.go](../../core/cmd/helm/replay_cmd.go)
- EvidencePack format: [docs/BENCHMARKS.md](../BENCHMARKS.md) for latency, [protocols/spec/evidence-pack-v1.md](../../protocols/spec/evidence-pack-v1.md) for format
- ProofGraph: [core/pkg/proofgraph/](../../core/pkg/proofgraph/)
- Three-layer security model: [docs/EXECUTION_SECURITY_MODEL.md](../EXECUTION_SECURITY_MODEL.md)
- Competitive note (why AGT cannot do this): [docs/COMPETITIVE_ANALYSIS_AGENT_OS.md](../COMPETITIVE_ANALYSIS_AGENT_OS.md)
- Determinism whitepaper (broader context): [docs/research/determinism-whitepaper.md](./determinism-whitepaper.md)
- Developer pain points → replay mapping: [docs/developer-guide/pain-points-solved.md](../developer-guide/pain-points-solved.md)

---

*Phase 4 research deliverable. Last updated 2026-04-15.*
