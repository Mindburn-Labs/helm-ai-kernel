# HELM vs OWASP Agentic Top 10 Coverage Matrix

Generated: 2026-04-13
HELM Version: 0.3.0
Guardian Pipeline: 6-gate + output quarantine
Formal Verification: TLA+ (`proofs/GuardianPipeline.tla`)

## Coverage Summary

| # | OWASP Risk (ASI-XX) | Coverage | Guardian Gates | Code Path | Conformance |
|---|---------------------|----------|---------------|-----------|-------------|
| ASI-01 | Prompt Injection | **FULL** | Threat, Context | `core/pkg/threatscan/` (12 rule sets, 7 detection vectors) | `make test-owasp` |
| ASI-02 | Tool Poisoning | **FULL** | Egress, Threat, Freeze | `core/pkg/mcp/rugpull.go` (fingerprinting), `core/pkg/firewall/` (fail-closed) | UC-013 |
| ASI-03 | Excessive Permission | **FULL** | Delegation, Identity | `core/pkg/effects/` (EffectPermit scope binding), P2 narrowing | UC-019 |
| ASI-04 | Insufficient Validation | **FULL** | Identity, Delegation | `core/pkg/guardian/` (TLA+-verified), P0/P1/P2 CPI | UC-020 |
| ASI-05 | Improper Output | **FULL** | Output Quarantine | `Guardian.EvaluateOutput()`, `SourceChannelToolOutput` | `make crucible` |
| ASI-06 | Resource Overborrowing | **FULL** | Context, Delegation | `core/pkg/budget/`, token ceilings, MCP rate limiting | UC-017 |
| ASI-07 | Cascading Effects | **FULL** | Delegation, Freeze | `core/pkg/effects/circuitbreaker.go`, `core/pkg/proofgraph/` (causal DAG) | `make crucible` |
| ASI-08 | Data Exposure | **FULL** | Egress, Context | `core/pkg/firewall/` (deny-all default), `core/pkg/crypto/sdjwt/` | `make crucible` |
| ASI-09 | Plugin/Tool Insecurity | **FULL** | Threat, Egress | `core/pkg/mcp/gateway.go` (governance interceptor), mTLS, schema validation | `make crucible` |
| ASI-10 | Insufficient Monitoring | **FULL** | All gates | `core/pkg/evidencepack/`, `core/pkg/proofgraph/`, `core/pkg/guardian/otel.go` | `make crucible-full` |

**Result: 10/10 FULL coverage — verified by TLA+ formal proofs and L1/L2/L3 conformance suites**

## Detailed Mapping

### 1. Prompt Injection

**Risk:** Adversarial inputs manipulate agent behavior through crafted prompts.

**HELM Coverage:**
- `core/pkg/threatscan/` — Threat scanner with multiple detection strategies
- `core/pkg/threatscan/ensemble.go` — Ensemble scanner with multi-scanner voting for higher detection accuracy (per arXiv 2509.14285)
- Guardian Gate 5 (Threat) — Scans all inputs before execution
- `SourceChannelDirectInput` classification for user-provided content
- `conform/adversarial/threat_scenarios.go` — Adversarial scenario test suite
- P1 policy bundles can define injection detection rules (CEL expressions)

**Conformance Vectors:** `owasp_threat_vectors.json` — injection patterns tested

### 2. Tool Poisoning

**Risk:** Malicious tool definitions or modified tool behaviors compromise agent.

**HELM Coverage:**
- `core/pkg/firewall/` — Network egress firewall (fail-closed: empty allowlist = deny-all)
- Guardian Gate 4 (Egress) — All outbound connections gated
- Tool schema validation in MCP gateway (`core/pkg/mcp/gateway.go`)
- `core/pkg/mcp/docscan.go` — DDIPE documentation scanning (7 patterns) detects deceptive tool descriptions that hide malicious behavior
- `core/pkg/pack/verify_capabilities.go` — SkillFortify static capability analysis at install time, blocks tools that exceed declared capabilities
- `core/pkg/pack/provenance.go` — Ed25519 publisher signature verification prevents tampered or unsigned tool packages
- Effect class ceilings prevent E4 (irreversible) by default
- `owasp_threat_vectors.json` UC-013 tests `exec_shell` with `curl | bash`

### 3. Excessive Permission Scope

**Risk:** Agent granted more permissions than needed for its task.

**HELM Coverage:**
- Guardian Gate 6 (Delegation) — Scope narrowing per session
- P2 overlays — Per-session permission narrowing (never widening)
- Blast radius checks — `system_wide` scope denied for restricted envelopes
- `core/pkg/effects/` — EffectPermit binds verdict to specific connector/action/scope
- UC-019 tests system-wide blast radius denial

### 4. Insufficient Permission Validation

**Risk:** Tool calls proceed without proper authorization checks.

**HELM Coverage:**
- Guardian Gate 3 (Identity) — Identity verification before execution
- Three-layer policy: P0 ceilings → P1 bundles → P2 overlays
- CPI verdict: ALLOW | DENY | REQUIRE_APPROVAL (fail-closed)
- `core/pkg/guardian/` — TLA+-verified 6-gate pipeline (`proofs/GuardianPipeline.tla`)
- Data classification enforcement — UC-020 tests restricted data denial

### 5. Improper Output Handling

**Risk:** Agent outputs contain malicious content, PII leakage, or hallucinations.

**HELM Coverage:**
- `Guardian.EvaluateOutput()` — Output quarantine gate (added 2026-04)
- `SourceChannelToolOutput` — Dedicated scanner channel for tool outputs
- Quarantine on high-risk findings, logged to audit trail
- Threat scanner reused for output scanning (same detection strategies)

### 6. Resource Overborrowing

**Risk:** Agent consumes excessive resources (compute, API calls, budget).

**HELM Coverage:**
- `core/pkg/budget/` — Budget gate with spend ceilings
- `core/pkg/budget/estimate.go` — Pre-execution cost estimation using moving averages, enabling proactive budget enforcement before tool calls execute
- `core/pkg/effects/types.go` — CostBreakdown struct provides per-action cost attribution (compute, API, storage, network), enabling granular spend analysis
- Token consumption tracking per session
- Rate limiting in MCP gateway
- P0 ceilings define absolute resource limits
- UC-017 tests resource overborrowing denial

### 7. Uncontrolled Cascading Effects

**Risk:** Agent actions trigger uncontrolled chain reactions across systems.

**HELM Coverage:**
- Delegation depth limits (configurable, default: 3)
- `core/pkg/proofgraph/` — Causal DAG with Lamport ordering tracks all effects
- Circuit breaker patterns — Guardian Gate 1 (Freeze) halts cascading failures
- `core/pkg/experimental/mama/` — Multi-agent runtime with lane-based concurrency isolation

### 8. Sensitive Data Exposure

**Risk:** Agent leaks sensitive data through tool calls or outputs.

**HELM Coverage:**
- Guardian Gate 4 (Egress) — All outbound data gated
- `core/pkg/firewall/` — Fail-closed egress control
- Data classification levels in policy bundles
- Selective disclosure JWT (`core/pkg/crypto/`) — Field-level access control
- `core/pkg/compliance/gdpr/` — GDPR data subject rights enforcement

### 9. Insecure Plugin/Tool Integration

**Risk:** Third-party tools/plugins introduce vulnerabilities.

**HELM Coverage:**
- MCP governance interceptor (`core/pkg/mcp/gateway.go`)
- `core/pkg/pack/verify_capabilities.go` — SkillFortify capability verification ensures plugins only access declared capabilities; blocks undeclared filesystem, network, or shell access
- `core/pkg/mcp/aip.go` — AIP delegation verification validates agent-to-agent delegation chains, preventing unauthorized privilege escalation across plugin boundaries
- Connector policy enforcement (`core/pkg/connectors/`)
- mTLS for service-to-service communication (`core/pkg/crypto/`)
- Tool schema validation before execution
- `core/pkg/runtimeadapters/` — Universal adapter interface with governance

### 10. Insufficient Monitoring/Logging

**Risk:** Lack of visibility into agent actions prevents detection of compromises.

**HELM Coverage:**
- Evidence packs (`core/pkg/evidencepack/`) — JCS-canonicalized, SHA-256 hashed
- `core/pkg/evidencepack/summary.go` — Constant-size evidence summaries (O(1) output regardless of pack size), enabling efficient integrity verification without reading entire packs
- Proofgraph (`core/pkg/proofgraph/`) — Complete causal audit trail
- `core/pkg/policy/suggest/` — Policy suggestion engine that analyzes decision history and recommends policy improvements (deny pattern grouping, missing rules, overly broad permits)
- OpenTelemetry integration for metrics and traces
- Receipt chain — Every decision produces a tamper-evident receipt
- `make bench-report` — Performance and overhead monitoring

## Latency Comparison

| Component | HELM p99 | Microsoft AGT Target |
|-----------|---------|---------------------|
| Guardian Pipeline (6-gate) | < 100us | < 100us |
| Threat Scanner | < 500us | N/A |
| Evidence Pack Hash | < 50us | N/A |
| Output Quarantine | < 200us | N/A |

Run `make bench` to reproduce. Results at `benchmarks/results/latest.json`.

## Cross-Framework Compliance Mapping

### NIST AI RMF 1.0 Alignment

| NIST Function | Category | HELM Coverage | Code Path |
|---------------|----------|---------------|-----------|
| GOVERN 1 | Policies | P0/P1/P2 three-layer composition, WASM sandbox | `core/pkg/policy/wasm/` |
| GOVERN 2 | Accountability | Evidence packs, ProofGraph, receipt chain | `core/pkg/evidencepack/` |
| GOVERN 3 | Workforce | Agent lifecycle, delegation chains | `core/pkg/identity/` |
| GOVERN 4 | Organizational | 7 compliance framework Go packages (GDPR, HIPAA, SOX, SEC, MiCA, DORA, FCA) + 9 signed reference policy bundles | `core/pkg/compliance/` · `reference_packs/` |
| GOVERN 5 | Processes | RegWatch continuous monitoring | `core/pkg/compliance/regwatch/` |
| GOVERN 6 | Plan | Policy bundles, versioned governance | `protocols/policy-schema/` |
| MAP 1 | Context | Context guard (environment fingerprinting) | `core/pkg/kernel/` |
| MAP 2 | Requirements | JKG jurisdiction knowledge graph | `core/pkg/compliance/jkg/` |
| MAP 3 | Benefits/Costs | Budget gates, spend ceilings | `core/pkg/budget/` |
| MAP 5 | Impact Assessment | Reversibility classification, blast radius | `core/pkg/effects/reversibility.go` |
| MEASURE 1 | Metrics | OTel integration, decision histograms | `core/pkg/guardian/otel.go` |
| MEASURE 2 | Evaluation | Conformance testing (L1/L2/L3) | `tests/conformance/` |
| MANAGE 1 | Risk Response | Guardian 6-gate pipeline, kill switch | `core/pkg/guardian/` |
| MANAGE 2 | Prioritization | Threat severity levels, trust scoring | `core/pkg/threatscan/` |
| MANAGE 3 | Communication | CloudEvents export, SIEM integration | `core/pkg/proofgraph/cloudevents/` |
| MANAGE 4 | Monitoring | ProofGraph causal DAG, circuit breakers | `core/pkg/proofgraph/`, `core/pkg/effects/` |

**Result: 16/19 NIST functions addressed (84%)**

### SOC 2 Type II Mapping

| SOC 2 Criteria | Control | HELM Implementation |
|----------------|---------|---------------------|
| CC1.1 | COSO Integrity | TLA+ formal verification of Guardian pipeline |
| CC2.1 | Communication | CloudEvents SIEM export, OTel tracing |
| CC3.1 | Risk Assessment | Threat scanner (12 rule sets), reversibility classification |
| CC4.1 | Monitoring | ProofGraph causal DAG, evidence packs, circuit breakers |
| CC5.1 | Control Activities | 6-gate Guardian pipeline (fail-closed), effect permits |
| CC6.1 | Logical Access | Ed25519 + ML-DSA-65 identity, delegation chains, P0/P1/P2 policies |
| CC6.2 | System Access | MCP governance interceptor, egress firewall (deny-all default) |
| CC6.3 | Data Access | Selective disclosure JWT, data classification in policy bundles |
| CC7.1 | System Monitoring | OTel metrics (decisions, gate denials, latency histograms) |
| CC7.2 | Anomaly Detection | Behavioral trust scorer, rogue agent detection, rug-pull detection |
| CC7.3 | Security Events | Tamper-evident evidence packs (JCS + SHA-256), Rekor anchoring |
| CC8.1 | Change Management | WASM policy bundles (content-addressed, immutable), conformance tests |
| CC9.1 | Risk Mitigation | Circuit breakers, kill switch (global + per-agent), saga orchestration |
| A1.1 | Availability | Circuit breaker registry, health probes, recovery timeout |

### EU AI Act (Regulation 2024/1689) Alignment

| Article | Requirement | HELM Coverage |
|---------|------------|---------------|
| Art. 9 | Risk Management | 7 compliance framework Go packages + 9 signed reference policy bundles + RegWatch monitoring + threat scanner |
| Art. 11 | Technical Documentation | Evidence packs with manifest, 39 signed JSON schemas |
| Art. 12 | Record-Keeping | ProofGraph causal DAG (immutable, Rekor-anchored) |
| Art. 13 | Transparency | CloudEvents export, OTel traces, receipt chain |
| Art. 14 | Human Oversight | Kill switch, ESCALATE verdict, approval workflows |
| Art. 15 | Robustness | TLA+ formal verification, L1/L2/L3 conformance, fuzz testing |

## Conformance Verification

```bash
# Run OWASP conformance vectors
make test-owasp

# Full conformance (L1 + L2 + L3 + A2A + OTel)
make crucible-full

# Benchmark Guardian latency
make bench-report

# Run all OWASP + compliance checks
make test-all
```

## Architectural Differentiators

Unlike library-based governance frameworks, HELM enforces governance at the kernel level:

| Dimension | HELM (Kernel) | Library Governance |
|-----------|--------------|-------------------|
| **Enforcement model** | Fail-closed (every action needs a signed permit) | Opt-in middleware |
| **Policy integrity** | Signed WASM bundles, content-addressed | Unsigned YAML files |
| **Audit trail** | Causal DAG with CRDT sync + Rekor anchoring | Linear log chain |
| **Crypto** | Ed25519 + ML-DSA-65 (post-quantum) | Ed25519 only |
| **Formal verification** | TLA+ proofs | None |
| **Compliance** | 7 framework packages + 9 signed reference bundles | 4 frameworks |
| **Evidence** | Court-admissible evidence packs (JCS + SHA-256) | CloudEvents export |
| **Determinism** | Kernel PRNG + reducer + concurrency artifacts | Stateless (no guarantees) |

## MCP Defense-Placement Taxonomy (MCP-DPT)

Per arXiv 2604.07551, defenses in MCP architecture should be placed at specific layers.
HELM implements defense at the gateway level -- validated as the optimal placement for
policy enforcement -- but extends coverage to all eight identified layers.

| MCP-DPT Layer | Defense Type | HELM Implementation |
|---------------|-------------|---------------------|
| Client-side | Input validation | `threatscan/` (12 rule sets) |
| Transport | mTLS, session auth | `crypto/` (Ed25519 + ML-DSA-65) |
| Gateway | Policy enforcement | `guardian/` (6-gate pipeline) |
| Server-side | Tool sandboxing | `policy/wasm/` (wazero) |
| Response | Output quarantine | `Guardian.EvaluateOutput()` |
| Metadata | Rug-pull detection | `mcp/rugpull.go` (fingerprinting) |
| Documentation | DDIPE scanning | `mcp/docscan.go` (7 patterns) |
| Cross-server | Typosquatting | `mcp/typosquat.go` (Levenshtein) |

HELM is the only governance system that implements defense at ALL 8 MCP-DPT layers.

### Layer Details

**Client-side (Input Validation):** The `threatscan/` package runs 12 rule sets against
all inbound content before it reaches the guardian pipeline. This catches prompt injection,
encoding attacks, and known malicious patterns at the earliest possible point.

**Transport (mTLS + Session Auth):** All HELM-to-MCP-server connections use mutual TLS
with Ed25519 or ML-DSA-65 (post-quantum) certificates. Session tokens are bound to the
TLS channel via channel binding, preventing token theft from being useful.

**Gateway (Policy Enforcement):** The guardian's 6-gate pipeline (Freeze, Context, Identity,
Egress, Threat, Delegation) is the primary enforcement point. Every tool call must pass
all six gates to receive an EffectPermit. This is fail-closed: any gate denial blocks
execution.

**Server-side (Tool Sandboxing):** Custom policy logic runs in WASM sandboxes via wazero.
WASM modules have no filesystem, network, or clock access. Execution is metered by fuel
to prevent infinite loops. The sandbox is deterministic across platforms.

**Response (Output Quarantine):** `Guardian.EvaluateOutput()` scans tool responses before
they reach the agent. High-risk findings (PII, credentials, injection attempts in
responses) trigger quarantine. The original response is logged but not forwarded.

**Metadata (Rug-Pull Detection):** `mcp/rugpull.go` fingerprints MCP server tool
definitions at policy-bind time and detects changes at runtime. If a tool's schema,
description, or capabilities change between sessions, HELM blocks the call and alerts
the operator. This defends against supply-chain attacks where a trusted MCP server is
compromised.

**Documentation (DDIPE Scanning):** `mcp/docscan.go` scans MCP server documentation and
tool descriptions for 7 patterns that indicate deceptive or dangerous behavior (hidden
side effects, privilege escalation instructions, data exfiltration hints, etc.).

**Cross-server (Typosquatting):** `mcp/typosquat.go` computes Levenshtein distance between
requested MCP server names and known-good servers. Requests to servers with suspiciously
similar names (e.g., `github-mcp` vs `githuh-mcp`) are flagged for human review.

### References

- **arXiv 2604.07551** -- "MCP-DPT: Defense-Placement Taxonomy for Model Context Protocol"
  (systematic classification of defense layers in MCP architecture)

## Supply Chain Security

Per arXiv 2603.00195 (CVE-2026-25253) and arXiv 2604.08407 (LiteLLM attack, March 2026),
supply chain attacks on agent skill ecosystems are the most critical emerging threat.

| Defense | Implementation | Paper |
|---------|---------------|-------|
| Capability verification | `pack/verify_capabilities.go` (SkillFortify) | arXiv 2603.00195 |
| Provenance verification | `pack/provenance.go` (Ed25519 publisher signatures) | arXiv 2604.08407 |
| Documentation scanning | `mcp/docscan.go` (DDIPE detection, 7 patterns) | arXiv 2604.03081 |
| Rug-pull detection | `mcp/rugpull.go` (SHA-256 fingerprinting) | arXiv 2603.22489 |
| Typosquatting detection | `mcp/typosquat.go` (Levenshtein distance) | arXiv 2508.14925 |
| Ensemble defense | `threatscan/ensemble.go` (multi-scanner voting) | arXiv 2509.14285 |

## Memory Governance

Per arXiv 2601.05504 (MINJA: 95% injection success) and arXiv 2512.16962
(MemoryGraft: persistent compromise via experience retrieval), memory-based
agents are highly vulnerable without explicit memory governance.

| Defense | Implementation | Paper |
|---------|---------------|-------|
| Hash-protected entries | `kernel/memory_integrity.go` (SHA-256 per entry) | arXiv 2603.20357 |
| Trust scoring | `kernel/memory_trust.go` (temporal decay + source trust) | arXiv 2601.05504 |
| Injection detection | 5 pattern checks on memory content | arXiv 2601.05504 |
