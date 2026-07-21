---
title: HELM Invariants
last_reviewed: 2026-07-21
---

# HELM Invariants

The properties this kernel does not trade away, each one pinned to the artifact
that proves it.

## How this document works

**Ids are permanent.** An invariant is `INV-NNN`. Numbers are never renumbered
and never reused. When an invariant stops being the right rule it keeps its id,
gains a `RETIRED` marker, and points at whatever superseded it. A reader who
finds `INV-007` in a two-year-old commit message must land on the same idea it
described then, even if the answer today is "that became `INV-019`".

**Every invariant carries a `verify:` hint.** The hint names the test, gate, or
artifact that proves the claim. An invariant nobody can check is a wish, not an
invariant — and a wish written in this format is worse than no entry at all,
because it borrows the authority of the ones that are real.

**Hint form is load-bearing.** A `verify:` line either cites references in
backticks — repo paths, Go test names, `make` targets — or it is free prose. The
gate resolves the backticked references and refuses anything dangling. It does
not touch the prose, and it prints every prose hint under a heading saying so.
Some obligations are genuinely human-owned; the honest move is to mark them,
not to dress them as automation. An invariant may carry one line of each.

**Amending this file requires a marker.** A commit that adds, edits, or retires
an invariant must carry `CONCEPT-CHANGE(INV-NNN)` in its message naming every id
it touched. Editing the surrounding prose is not a concept change and needs no
marker. This is what stops the constitution from drifting one convenient
sentence at a time.

**Gates.**

```bash
make inv-check      # hints resolve; ids unique; checker self-tests first
make concept-gate   # amendments carry a CONCEPT-CHANGE marker
```

`make inv-check` runs synthetic negative controls before it reads this file and
fails itself if any control comes back wrong. A checker that has stopped
discriminating would report a green constitution it never inspected, which is
strictly worse than having no checker at all.

The numbered-invariant pattern follows razzant/claudexor (MIT).

---

## Determinism and canonicalization

### INV-001 — Every hashed structure is JCS-canonical first

Anything whose hash is signed, compared, or stored goes through JCS (RFC 8785)
before SHA-256. Two hosts that disagree about key order or number formatting
would produce two hashes for one fact, and every downstream proof would inherit
the disagreement. Canonicalization is what makes an EvidencePack verify
identically on a machine that never saw the run.

verify: `core/pkg/canonicalize/jcs.go` · tests `TestCanonicalHash_Stability`, `TestJCS_RecursiveSorting`, `FuzzJCS`

### INV-002 — ProofGraph ordering and node hashes are wall-clock independent

Lamport values increase monotonically, and a node's hash excludes its timestamp.
Causal order is a property of the graph, not of whichever clock happened to
observe it, so replaying the same run on a different host reproduces the same
node identities.

verify: `core/pkg/proofgraph/node.go`, `core/pkg/proofgraph/graph.go` · tests `TestNodeHash_TimestampExcluded`, `TestGraph_LamportMonotonicity`, `TestDAGValidation_TamperedNode`

### INV-003 — EvidencePack roots are deterministic and inclusion is tamper-evident

The Merkle root over pack entries is a function of the entries alone, and an
inclusion path stops verifying the moment any sibling is altered. A pack that
hashed differently on re-computation would prove nothing; one whose proofs
survived tampering would prove the wrong thing.

verify: `core/pkg/evidencepack/merkle.go` · tests `TestComputeEntriesMerkleRoot_Deterministic`, `TestInclusionPath_RoundTripEveryEntry`, `TestInclusionPath_TamperedSiblingFails`

---

## Fail-closed enforcement

### INV-004 — Egress enforcement is fail-closed

An empty allowlist is deny-all, not allow-all. A nil policy is deny-all. An
explicit deny always beats an allow. The failure mode of a misconfigured
firewall must be a blocked request, never an unrecorded one.

verify: `core/pkg/firewall/egress.go` · tests `TestEgressChecker_EmptyPolicyDenyAll`, `TestEgressChecker_NilPolicyDenyAll`, `TestEgressChecker_DeniedTakesPrecedence`

### INV-005 — A policy runtime that cannot evaluate denies

An unloadable module, a missing entrypoint, a cancelled evaluation: each answers
DENY. "Could not decide" and "decided to allow" are different facts and the
kernel never collapses them.

verify: `core/pkg/policy/wasm` · tests `TestRuntime_Evaluate_FailClosed`, `TestExecutor_MissingEntrypoint`, `TestExecutor_ContextCancellation`

### INV-006 — An unclassified effect is irreversible until proven otherwise

An effect type the reversibility table has never seen is treated as
irreversible, so it inherits the strictest approval requirement rather than the
laxest. The safe default for an unknown is the expensive one.

verify: `core/pkg/effects/reversibility.go` · test `TestUnknownEffectTypeDefaultsToIrreversible`

### INV-007 — A verdict the gateway cannot verify is not a verdict

Kernel outage, malformed response, wrong trust root, stale policy epoch: the
gateway fails closed on each. A signature it cannot check is treated as one that
failed, never as one it may skip.

verify: `core/pkg/boundary/extauthz/verifier.go` · tests `TestGatewayResponseFailsClosedOnKernelOutageOrUnverifiableVerdict`, `TestMalformedRequestOrResponseFailsClosedEvenWhenSigned`, `TestTrustRootBindingRejectsWrongRoot`

---

## Authorization binding

### INV-008 — An EffectPermit authorizes one connector, one action, one scope

A permit is bound to the verdict that issued it and to the exact effect it
describes. It cannot be replayed against a different connector, widened to a
different action, or reused after consumption. Authorization that travels is
not authorization.

verify: `core/pkg/effects/types.go` · tests `TestPermitLedgerRejectsDirectBindingMismatchAndReplayKeys`, `TestEvaluateAndConsumeRequiresDurablePermitConsumer`

### INV-009 — DENY and ESCALATE carry no permit material

A non-allowing verdict cannot ship anything a connector could mistake for
authority. The absence of a permit is the enforcement; a "denied" response
carrying permit fields would be one deserialization bug away from an allow.

verify: `core/pkg/boundary/extauthz/verifier.go` · test `TestDenyAndEscalateCannotCarryPermitMaterial`

### INV-010 — A permit cannot outlive the verdict that authorized it

Permit expiry is bounded by verdict expiry, and an expired permit fails before
dispatch rather than at the connector. The window in which an effect may execute
is the window in which someone actually authorized it.

verify: `core/pkg/boundary/extauthz/verifier.go` · tests `TestPermitExpiryCannotOutliveVerdict`, `TestExpiredPermitFailsBeforeDispatch`, `TestAllowRequiresExplicitVerifierContextAndBoundedTTL`

### INV-011 — A credential binds to exactly one principal

The first binding of a credential hash to a principal is permanent. The same
principal may re-present it; a different principal presenting it is an isolation
violation and is receipted as one. This is the agent-impersonation path, and it
is closed by construction rather than by review.

verify: `core/pkg/identity/isolation.go` · tests `TestIsolationChecker_DifferentPrincipalReuse`, `TestIsolationChecker_SamePrincipalIdempotent`, `TestIsolationChecker_ViolationHistory`

### INV-012 — Signature algorithms do not cross-verify

A signature produced under one algorithm is rejected by the verifier for
another, an empty key ring cannot sign at all, and a revoked key cannot verify.
Algorithm agility is a migration property, never a downgrade path.

quantum_posture: this entry records an existing algorithm-separation and
revocation property of the key ring. It pins no algorithm and asserts no
post-quantum claim; migration follows kernel-wide signing policy.

verify: `core/pkg/crypto/keyring.go` · tests `TestExt_MLDSASignatureRejectedByEd25519`, `TestExt_Ed25519SignatureRejectedByMLDSA`, `TestKeyRing_EmptySignFails`, `TestExt_KeyRingVerifyDecisionRevokedKey`

---

## Live-tree delivery

### INV-013 — Apply policy is decided in exactly one place

`Eligibility` is the only function that answers "may this patch touch a live
tree". Every caller — CLI, control API, scheduler, future UI — routes through it
and acts on the Decision it returns. A caller that re-implements "looks approved
to me" creates a second policy with no receipt, and the first time the two
disagree is a mutation nobody authorized.

verify: `core/pkg/patchdelivery/gate.go` · tests `TestEligibilityTriStateMatrix`, `TestEligibilityStructuralRefusals`, `TestEligibilityRequiresALifecycle`

### INV-014 — An override may clear an unknown, never a proven-false

Deliverability is tri-state. UNKNOWN blocks fail-closed and an operator may
accept that risk. PROVEN-undeliverable is checked before any override is even
evaluated, because it is a fact about the patch rather than a policy judgment,
and no authority makes a conflicting patch apply.

verify: `core/pkg/patchdelivery/verifier.go` · tests `TestEligibilityTriStateMatrix`, `TestFinalVerifyTriState`

### INV-015 — An override binds to the exact patch bytes it accepted

The override carries the SHA-256 of the patch the operator looked at. Change one
byte and the override no longer authorizes it, because it no longer describes
it. This is INV-008 in miniature: the reviewed thing and the applied thing must
be provably identical.

verify: `core/pkg/patchdelivery/gate.go` · test `TestOverrideBindingRejectsAMutatedPatch`

### INV-016 — Override authority has scope only on a run awaiting a decision

An override answers a question that was actually asked. On a run nobody has
reviewed there is no risk decision to accept, so the override is refused and the
run needs a reviewer. A run that merely hit a broken verifier cannot be waved
through on authority that was never meant for it.

verify: `core/pkg/patchdelivery/gate.go` · tests `TestOverrideScopeRefusedWhenRunIsNotNeedsDecision`, `TestOverrideRejectsUnknownAction`

### INV-017 — Every live-tree mutation path is registered with a complete fence

Each code path that can write to a user's repository on behalf of an agent run
is named in the registry and declares the enforcement in front of it. An
unregistered path — or one registered with an empty fence — fails the build. The
point is to make "which code can write to a live tree" an answerable question
instead of an archaeology exercise.

verify: `core/pkg/patchdelivery/mutation.go` · tests `TestMutationPathsAreRegistered`, `TestRegisterAndPathsAreOrdered`

### INV-018 — A refused apply leaves the live tree byte-identical

Apply is all-or-nothing and re-asserts the target preimage immediately before
writing. A tree that moved underneath the patch is a refusal, not a merge. When
a partial write cannot be withdrawn the result says so plainly rather than
reporting a clean tree the operator does not have.

verify: `core/pkg/patchdelivery/mutation.go` · tests `TestApplyProtectedRefusedForwardApplyLeavesTreeClean`, `TestApplyProtectedRefusesConcurrentEditWithoutDestroyingIt`, `TestApplyProtectedAppliesAllOrNothing`

### INV-019 — Verification never mutates the live tree, and silence is not a pass

The pre-apply verify runs against an isolated copy and leaves the operator's
tree untouched. "No gates were configured" is reported as its own state and
never as "gates passed" — an unasked question has no answer.

verify: `core/pkg/patchdelivery/verifier.go` · tests `TestFinalVerifyLeavesLiveTreeUntouched`, `TestNoGatesConfiguredIsNotReportedAsPassed`

### INV-020 — Diff capture is byte-faithful

Work product is captured raw. CRLF survives, binary survives, and the bytes that
were reviewed are the bytes that get applied. A diff that cannot round-trip
byte-for-byte is not evidence of anything.

verify: `core/pkg/worktree/worktree.go` · tests `TestCaptureDiffPreservesCRLF`, `TestCaptureDiffPreservesBinary`, `TestApplyProtectedPreservesCRLFAndBinary`

---

## Agent process envelope

### INV-021 — The provider credential scrub is cross-provider

A run routed to one model provider is stripped of every provider's credentials
and base-URL redirects, not just the routed vendor's. Otherwise a multi-provider
CLI can be steered by a config file or a fallback path onto an inherited key,
and the run gets billed to and attributed to a principal HELM never selected.
The caller's own extra-env channel is scrubbed on the same rule, because a fence
that holds everywhere except the convenient door is not a fence.

verify: `core/pkg/harness/env.go` · tests `TestScrubProviderEnvRemovesEveryProviderCredential`, `TestComposeEnvFencesTheUnselectedProvider`, `TestComposeEnvScrubsExtraEnv`

### INV-022 — Exactly one terminal event per run, on every exit path

Clean exit, non-zero exit, spawn failure, context cancellation: each produces one
completion and no more. A run that emits two terminals double-counts, and one
that emits none leaves a supervisor waiting on a process that is already gone.
Killing a run reaps the whole process tree; dropped output is counted rather than
silently discarded.

verify: `core/pkg/harness/process.go` · tests `TestExactlyOneCompletedOnSpawnFailure`, `TestExactlyOneCompletedOnContextCancel`, `TestKillTreeReapsGrandchildren`, `TestDroppedLinesAreCountedNotDiscarded`

### INV-023 — An unenforceable read-only claim is refused, not assumed

If the vendor build cannot be shown to honour the read-only flags HELM passes it,
the run is refused rather than started on the assumption that it will behave. A
probe that cannot answer fails closed. Scoped HOME lives outside the work tree so
vendor state cannot leak into the diff.

verify: `core/pkg/harness/claude.go` · tests `TestClaudeReadonlyProbeRefusesUnenforceableBuild`, `TestClaudeReadonlyProbeFailsClosedWhenHelpFails`, `TestScopedHomeIsOutsideTree`

### INV-024 — An adapter governs only the calls actually routed through it

HELM enforces on the path that reaches it. A configured MCP server or a hooked
tool class governs the calls it receives and nothing else — not arbitrary client,
browser, IDE, or desktop actions that never cross the boundary.

verify: `core/pkg/runtimeadapters` · adapter interface and its implementations
verify: review question on any new adapter — name the call path HELM intercepts and the ones it does not. Coverage asserted without that path is a claim about configuration, not about enforcement, and belongs in neither docs nor a deck.

---

## Repository-level enforcement

### INV-025 — The gates that prove these invariants are themselves gated

TCB import isolation, the boundary manifest, and this constitution are checked by
tooling that runs in the same pipeline as the code it guards. The invariant
checker self-tests against synthetic bad input before every real scan and fails
itself when it stops discriminating, because a gate that silently degrades into
a no-op is indistinguishable from a passing one right up until it matters.

verify: `tools/tcbcheck/main.go`, `tools/invcheck/main.go` · `make inv-check`, `make concept-gate`, `make verify-boundary`
