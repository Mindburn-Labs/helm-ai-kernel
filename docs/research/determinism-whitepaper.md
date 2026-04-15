# Separating Governance Determinism from LLM Nondeterminism

## Abstract

LLMs are inherently nondeterministic (arXiv 2601.06118). Even with temperature=0,
GPU floating-point precision effects produce different outputs across runs.
HELM addresses this by making the governance layer deterministic while accepting
LLM nondeterminism as a given. This separation is architecturally unique and has
concrete implications for auditability, compliance, and reproducible security.

## The Nondeterminism Problem

### Source 1: LLM Token Generation

Per arXiv 2601.06118, LLMs produce nondeterministic results on GPUs even when
configured for determinism. The root cause is finite precision effects in
floating-point matrix multiplication. Different GPU architectures, driver versions,
and even batch sizes change the order of floating-point accumulation, which changes
rounding, which changes token probabilities, which changes output tokens.

This is not a software bug. It is a fundamental property of IEEE 754 arithmetic
on parallel hardware. No amount of "deterministic mode" flags eliminates it entirely.

### Source 2: Multi-Agent Amplification

Per arXiv 2603.09127, even deterministic systems can amplify tiny perturbations
into divergent decisions in multi-agent settings. When multiple agents interact,
small differences in one agent's output propagate through the system. A single
different token in Agent A's response may cause Agent B to choose a different tool,
which causes Agent C to escalate instead of approve.

This amplification effect means that governance systems that rely on reproducing
exact LLM outputs for audit are fundamentally broken. The outputs will differ
across runs, and the differences will compound.

### Source 3: Environmental Variance

Beyond GPU nondeterminism, real deployments introduce additional variance:
- Network latency affects timeout behavior
- Clock skew affects timestamp-based decisions
- Memory pressure affects garbage collection timing
- Load balancing affects which replica handles a request

Any governance system that conflates its own decision logic with these external
sources of nondeterminism cannot provide reproducible audits.

## HELM's Approach: Deterministic Governance Envelope

HELM isolates governance from nondeterminism by enforcing a strict boundary:
the LLM produces requests; HELM evaluates them deterministically.

### 1. PRNG Logging

All randomness sources within the kernel are seeded and logged. The kernel never
calls `rand.Read()` or `time.Now()` directly. Instead, it uses a seeded PRNG
whose state is captured in the ProofGraph. During replay, the same seed produces
the same random bytes.

Implementation: `core/pkg/kernel/` -- PRNG seed is a ProofGraph node attribute.

### 2. Concurrency Artifacts

Scheduler influence is captured in dependency graphs. When multiple goroutines
contribute to a governance decision, their relative ordering is recorded as
concurrency artifacts. During replay, these artifacts constrain the reducer to
produce the same result regardless of actual goroutine scheduling.

Implementation: `core/pkg/kernel/` -- concurrency artifacts are first-class
ProofGraph edges.

### 3. Deterministic Reducer

The kernel's reducer guarantees: same inputs, same output, regardless of arrival
order. When multiple policy evaluations run in parallel (e.g., P0, P1, and P2
layers), their results may arrive in any order. The reducer sorts them by a
deterministic key before combining, ensuring the final verdict is identical
across runs.

Implementation: `core/pkg/kernel/` -- reducer with conflict policies and
deterministic merge.

### 4. Lamport Ordering

Causal consistency without wall-clock dependency. Every ProofGraph node carries a
Lamport timestamp that establishes happened-before relationships. This ordering
is independent of wall clocks, network latency, or system load. Two HELM
instances processing the same governance trace will produce the same causal
ordering even if their wall clocks disagree by hours.

Implementation: `core/pkg/proofgraph/` -- Lamport clocks on all node types.

### 5. JCS Canonicalization

All serializable structures use JCS (RFC 8785) + SHA-256. This eliminates the
class of nondeterminism caused by JSON serialization order, floating-point
representation, or Unicode normalization. Two HELM instances on different
platforms (Linux amd64 vs. Darwin arm64) produce byte-identical hashes for the
same governance data.

Implementation: `core/pkg/evidencepack/` -- JCS canonical manifest.

## What This Means in Practice

- The LLM may produce different tool call requests across runs
- But HELM's governance decision for each request is identical given the same policy
- The ProofGraph is deterministically reproducible from its seed
- Evidence packs are byte-identical for the same governance trace
- Policy evaluation latency is deterministic (no network calls, no I/O waits)

### Example

Consider an agent that asks: "Read file `/etc/passwd`"

Run 1: The LLM generates the tool call with `path="/etc/passwd"`.
Run 2: The LLM generates the tool call with `path="/etc/passwd"` (same) or
might frame it differently (e.g., `file="/etc/passwd"`).

In both cases, HELM's guardian pipeline evaluates the request against the same
policy. If the policy denies filesystem reads to `/etc/`, the verdict is DENY
in both runs. The evidence pack records the same policy version, the same gate
sequence, the same denial reason. An auditor replaying the governance trace
offline gets the same DENY verdict.

The LLM's nondeterminism is irrelevant to the governance outcome. The governance
layer is a pure function of (request, policy, state).

## Comparison with Stateless Governance

| Property | HELM (Deterministic Kernel) | Stateless Middleware |
|----------|---------------------------|---------------------|
| Replay fidelity | Byte-identical | Approximate (log-based) |
| Cross-platform hashes | Identical (JCS) | Platform-dependent |
| Concurrency handling | Captured + reproduced | Ignored |
| Clock dependency | None (Lamport) | Wall-clock timestamps |
| Randomness | Seeded + logged | Uncontrolled |
| Audit verdict | Provably identical | "Probably similar" |

## Implications for Auditing

Auditors can replay governance decisions offline and verify they would have produced
the same verdict. This is impossible with stateless governance systems.

Specifically, an auditor can:

1. **Obtain the evidence pack** -- a self-contained archive with all inputs, policy
   state, and governance trace.
2. **Run `helm replay`** -- which re-evaluates every governance decision using the
   captured PRNG seed, concurrency artifacts, and Lamport ordering.
3. **Verify byte-identical output** -- the replayed evidence pack hash matches the
   original. If it does not, the evidence has been tampered with.

This three-step process requires no access to the original HELM instance, no network
connectivity, and no trust in the operator. The evidence pack is self-verifying.

### Regulatory Significance

For regulated industries (financial services, healthcare, government), the ability
to prove that governance decisions are reproducible is not optional. EU AI Act
Article 12 requires "record-keeping" that enables "tracing back" of AI system
behavior. HELM's deterministic kernel is the only open-source implementation that
satisfies this requirement with cryptographic proof rather than best-effort logging.

## Limitations

HELM's determinism guarantees apply to the governance layer only. The following
remain nondeterministic by design:

- **LLM outputs** -- Token generation is inherently nondeterministic on GPUs.
- **External tool responses** -- A database query may return different results
  at different times.
- **Network timing** -- Latency between the agent and HELM proxy varies.

HELM does not attempt to make these deterministic. Instead, it captures them as
inputs to the governance function and ensures the function itself is pure.

## References

- **arXiv 2601.06118** -- "Token Probabilities Reveal Non-Determinism in LLMs on GPUs"
  (empirical measurement of GPU-induced nondeterminism in LLM inference)
- **arXiv 2603.09127** -- "Collective AI Amplifies Individual Non-Determinism"
  (multi-agent amplification of small perturbations into divergent outcomes)
- **arXiv 2601.09749** -- "R-LAM: Reproducibility-Constrained Action Models"
  (framework for constraining agent actions to reproducible subsets)
- **arXiv 2601.00481** -- "MAESTRO: Multi-Agent Evaluation Suite for Testing
  Reproducible Outcomes" (evaluation methodology for multi-agent reproducibility)
- **RFC 8785** -- "JSON Canonicalization Scheme (JCS)" (deterministic JSON
  serialization for cross-platform hash consistency)
