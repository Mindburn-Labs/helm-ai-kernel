---
title: THREAT_MODEL
---

# Threat Model

> **Canonical architecture**: see [ARCHITECTURE.md](ARCHITECTURE.md) for the
> system-level trust model.

## Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│                    UNTRUSTED                        │
│  LLM Provider · User Prompts · Connector Outputs    │
└───────────────────────┬─────────────────────────────┘
                        │
                  ┌─────▼─────┐
                  │ HELM      │  ← PEP boundary (schema + hash)
                  │ Kernel    │  ← Guardian (policy engine)
                  │           │  ← SafeExecutor (signed receipts)
                  └─────┬─────┘
                        │
┌───────────────────────▼─────────────────────────────┐
│                    TRUSTED                          │
│  Signed Receipt Store · ProofGraph DAG · Trust Reg  │
└─────────────────────────────────────────────────────┘
```

## Threat Categories

### T1: Unauthorized Tool Execution

**Attack:** Model generates a tool call not sanctioned by the current policy.

**Defense:** Guardian policy engine maintains an explicit allowlist. Undeclared tools are blocked before reaching the executor. Default-deny.

**Residual risk:** None — this is a hard block.

### T2: Argument Tampering

**Attack:** Malicious input crafts tool arguments that bypass validation or alter semantics.

**Defense:**

1. Schema validation against pinned JSON Schema (fail-closed)
2. JCS canonicalization (RFC 8785) eliminates encoding ambiguity
3. SHA-256 hash of canonical args (`ArgsHash`) bound into signed receipt

**Residual risk:** Schema must be correct. HELM enforces the schema, not its semantic correctness.

### T3: Output Spoofing

**Attack:** Malicious connector returns data that doesn't match the declared output schema.

**Defense:** Output validation against pinned schema. Contract drift produces `ERR_CONNECTOR_CONTRACT_DRIFT` and halts execution.

**Residual risk:** Connector could return semantically wrong but schema-valid data.

### T4: Resource Exhaustion (WASI)

**Attack:** Uploaded WASM module consumes unbounded CPU, memory, or time.

**Defense:**

- Gas metering: hard budget per invocation
- Wall-clock timeout: configurable per-tool
- Memory cap: WASM linear memory bounded
- Deterministic trap codes on budget exhaustion

**Residual risk:** None for compute resources. Side-channels at the host OS level are out of scope.

### T5: Receipt Forgery

**Attack:** Attacker creates fake receipts to claim executions that didn't happen.

**Defense:** Ed25519 signatures on canonical payloads. Verification requires the signer's public key.

**Residual risk:** Key compromise. Mitigated by Trust Registry key rotation.

### T6: Replay Attacks

**Attack:** Attacker replays a valid receipt to re-execute an effect.

**Defense:**

- Lamport clock monotonicity per session
- Causal `PrevHash` chain (each receipt signs over previous receipt's signature)
- Idempotency cache in executor

**Residual risk:** None within a single session. Cross-session replay mitigated by session scoping.

### T7: Approval Bypass

**Attack:** Model or operator bypasses human approval for high-risk operations.

**Defense:**

- Timelock: approval window must elapse before execution
- Deliberate confirmation: approver must produce a hash derived from the original intent
- Domain separation: approval keys are distinct from execution keys
- Challenge/response ceremony for disputes

**Residual risk:** Social engineering of the human approver is out of scope.

### T8: Trust Registry Manipulation

**Attack:** Attacker adds a rogue key or revokes a legitimate one.

**Defense:** Event-sourced trust registry. Every key lifecycle event (add/revoke/rotate) is a signed, immutable event with Lamport ordering. Registry state is replayable from genesis.

**Residual risk:** Compromise of the registry admin key. Mitigated by ceremony-based key management.

### T9: Proxy Sidecar Attacks

**Attack vectors:**

1. **MITM between client and proxy:** Attacker intercepts traffic between the app and the local HELM proxy, injecting tool calls or modifying responses.

2. **Budget bypass:** Attacker circumvents budget enforcement by directly hitting the upstream API, bypassing the proxy entirely.

3. **Receipt store tampering:** Attacker modifies the JSONL receipt store on disk to cover traces or inject fake receipts.

4. **Session fixation:** Attacker reuses a session-scoped Lamport counter to replay receipts from a previous session.

5. **SSE stream poisoning:** In streaming mode, attacker injects partial tool_call fragments into the SSE stream to trigger unintended executions.

**Defense:**

1. Proxy binds to localhost only; TLS is recommended for remote deployments.
2. Budget enforcement is advisory in OSS sidecar mode. For hard enforcement, use `--island-mode` or deploy as a network gateway.
3. Receipts are Ed25519-signed. Tampered receipts fail `helm pack verify`. ProofGraph DAG nodes have causal chain integrity (prevHash linking).
4. Session-scoped Lamport clocks with atomic increments. Cross-session replay detected by `helm replay --verify`.
5. Streaming responses are buffered and validated before governance checks. Partial tool_calls are held until the complete SSE stream is received.

**Residual risk:**

- Local attacker with filesystem access can bypass the sidecar. This is inherent to sidecar architectures and mitigated by island mode for high-security environments.
- SSE streaming governance is eventual (validated after full buffering), not inline.

### T10: Inter-Agent Trust Violations

**Attack vectors:**

1. **Trust key forgery:** Attacker crafts a fake trust key entry to impersonate an authorized agent or service.

2. **Version downgrade:** Attacker forces negotiation to a weaker schema version to exploit known vulnerabilities in older protocol versions.

3. **Proof capsule forgery:** Attacker provides fabricated condensed receipts with fake Merkle inclusion proofs to claim executions that never occurred.

4. **Session replay:** Attacker captures a valid receipt chain and replays it from a different context.

5. **Policy bundle tampering:** Attacker modifies a policy bundle to weaken governance constraints without detection.

**Defense:**

1. Trust keys are managed via the event-sourced Trust Registry. Unknown keys produce `TRUST_KEY_UNKNOWN`.
2. Schema version negotiation is explicit with denial on mismatch. No silent downgrade.
3. Proof condensation Merkle proofs are verified against attested checkpoint roots. Invalid inclusion proofs are rejected.
4. Receipt chains include PrevHash binding and Lamport ordering. Replayed receipts fail causal verification.
5. Policy bundles are content-addressed (SHA-256). Hash verification on load detects any modification.

**Residual risk:**

- Inter-agent trust requires both parties to share a common Trust Registry or cross-verified key set.
- Full cross-organization trust negotiation is outside current OSS scope.

---

## OWASP MCP Alignment

HELM's threat model maps to the OWASP MCP agentic threat taxonomy.
See [OWASP_MCP_THREAT_MAPPING.md](OWASP_MCP_THREAT_MAPPING.md) for
the complete threat-to-defense matrix covering all three layers of
HELM's [Execution Security Model](EXECUTION_SECURITY_MODEL.md).

---

### T11: Tool Poisoning

**Attack:** Malicious tool descriptions in MCP server responses trick the agent
into calling dangerous tools or passing attacker-controlled arguments.

**Defense (Layer A — Surface Containment):**

- Capability manifests explicitly declare permitted tools. Poisoned tool
  descriptions for undeclared tools never reach the executor.
- Connector allowlists restrict which MCP servers are reachable.

**Defense (Layer B — Dispatch Enforcement):**

- Schema PEP validates all tool arguments against pinned schemas.
  Injected payloads that violate schema are rejected.
- Unknown tools produce `DENY_TOOL_NOT_FOUND`.

**Residual risk:** If a declared tool's description is poisoned at the MCP
server, HELM blocks schema-violating args but cannot detect semantic
manipulation within valid schemas.

### T12: Parameter Injection

**Attack:** Crafted tool arguments embed hidden commands, extra fields,
or exploit downstream system parsers through carefully constructed payloads.

**Defense (Layer B — Dispatch Enforcement):**

- JCS canonicalization (RFC 8785) normalizes all arguments, eliminating
  encoding-based injection vectors.
- Schema validation rejects unknown/extra fields (deny on unknown).
- SHA-256 hash of canonical args bound into signed receipt ensures
  post-hoc detection of any manipulation.

**Residual risk:** Arguments that are valid per schema but semantically
malicious. HELM enforces structural safety, not semantic intent.

### T13: Capability Escalation

**Attack:** Agent or delegated sub-agent attempts to gain higher privileges
than granted — accessing tools outside its profile, bypassing read-only
restrictions, or expanding its delegation scope.

**Defense (Layer A — Surface Containment):**

- Side-effect class profiles enforce read-only / write-limited boundaries.
- Domain-scoped tool bundles isolate capability domains.

**Defense (Layer B — Dispatch Enforcement):**

- Delegation sessions enforce `capabilities ⊆ delegator's policy`.
  Any out-of-scope request produces `DELEGATION_SCOPE_VIOLATION`.
- P0 ceilings are non-overridable — no policy layer can escalate past them.
- Identity isolation violations produce `IDENTITY_ISOLATION_VIOLATION`.

**Residual risk:** None within the delegation model — escalation is a
hard block. Social engineering of the delegator is out of scope.

### T14: MCP Supply Chain Attacks

> *arXiv 2603.00195, 2604.03081, 2604.08407*

**Attack:** Adversary publishes a malicious MCP tool or compromises an existing one. The attack surface includes typosquatted tool names, poisoned documentation, and tools whose behavior changes after installation (rug-pulls).

**Defense:**

- **SkillFortify** (`pack/verify_capabilities.go`): Static capability verification rejects packs whose declared capabilities do not match actual tool behavior.
- **Dependency provenance** (`pack/provenance.go`): Publisher signature chain verification back to a trusted root. Unsigned or incorrectly signed packs are blocked.
- **DDIPE scanning** (`mcp/docscan.go`): Documentation is analyzed for embedded instructions, hidden directives, and social engineering patterns before the agent processes it.
- **Typosquatting detection** (`mcp/typosquat.go`): Levenshtein distance comparison against known-good tool registries. Near-match tool names trigger warnings.
- **Rug-pull detection** (`mcp/rugpull.go`): Tool fingerprinting detects behavioral drift between installation and runtime. Schema or behavior changes trigger re-verification.

**Residual risk:** Semantic attacks that remain within valid schemas and produce plausible-looking but incorrect output. Mitigated by ensemble scanning and behavioral trust scoring.

### T15: Agent Memory Poisoning

> *arXiv 2603.20357, 2601.05504*

**Attack:** Adversary injects false context into an agent's long-term memory (via tool outputs, conversation history, or cross-session persistence) to influence future decisions without the operator's knowledge.

**Defense:**

- **Memory integrity** (`kernel/memory_integrity.go`): SHA-256 hash verification on every memory read. Modifications outside the governed write path produce `MEMORY_INTEGRITY_VIOLATION`.
- **Memory trust scoring** (`kernel/memory_trust.go`): Temporal decay reduces the influence of older memories. Injection detection identifies entries planted by untrusted sources and downgrades their trust score. Low-trust memories are excluded from agent decision-making.
- **Ensemble scanning** (`threatscan/ensemble.go`): Multi-scanner voting detects injection patterns in memory content before it is persisted.

**Residual risk:** Gradual poisoning that stays within statistical norms of legitimate memory writes. Mitigated by temporal decay and periodic memory audits.

### T16: MCP Tool Poisoning via Documentation

> *arXiv 2508.14925*

**Attack:** Malicious MCP server returns tool descriptions containing hidden instructions that manipulate the agent's behavior — causing it to exfiltrate data, call unintended tools, or bypass safety constraints through the tool description itself rather than through tool arguments.

**Defense (Layer A):**

- **DDIPE doc scanning** (`mcp/docscan.go`): All tool documentation is scanned before being exposed to the agent. Detects embedded instructions, prompt injection patterns, and social engineering.
- **MCPTox benchmark** (`mcp/mcptox_test.go`): Continuous adversarial testing validates 0% attack success rate (ASR) against known tool poisoning payloads.

**Defense (Layer B):**

- **Federated trust scoring** (`mcp/trust.go`): Cross-organization reputation scoring for MCP servers. Servers with low trust scores have their tool descriptions flagged for manual review.

**Residual risk:** Novel social engineering patterns not covered by current detection heuristics. Mitigated by ensemble scanning and MCPTox continuous testing.

---

## Out of Scope

- Content safety / prompt injection within the text domain
- Vulnerabilities in upstream LLM providers
- Host OS / hardware side channels
- Network-level attacks (TLS is assumed)
- Social engineering of human approvers
