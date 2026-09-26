---
title: HELM Invariants
last_reviewed: 2026-09-24
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

**This file is generated.** [`controls.yaml`](controls.yaml) is the control
registry (binding rule R1). It holds the text of every invariant together with
its owner, entry points, protected operations, bypass assumptions and tests,
plus the controls that are not invariants. Edit the registry and run
`make controls`, which rewrites this file and `coverage-map.json`. The marker
rule above still applies to the invariant text.

**Gates.**

```bash
make inv-check        # hints resolve; ids unique; checker self-tests first
make concept-gate     # amendments carry a CONCEPT-CHANGE marker
make controls-check   # registry valid; enforced paths reachable and tested; files current
```

`make inv-check` runs synthetic negative controls before it reads this file and
fails itself if any control comes back wrong. A checker that has stopped
discriminating would report a green constitution it never inspected, which is
strictly worse than having no checker at all.

The numbered-invariant pattern follows razzant/claudexor (MIT).

---

## Enforcement status

Generated from [`controls.yaml`](controls.yaml) by `make controls`; do not edit
this section or the invariant text below by hand. `make controls-check` fails
when this file or `coverage-map.json` differs from the registry. A runtime
entry is `enforced` only when every entry point is reachable from a shipped
binary (`scripts/ci/deadcode-roots.txt`), its allowed, forbidden and removal
tests run and pass, and deleting the control makes its removal tests fail. A
`build` entry is held by CI gates that block pull requests. Everything else
is `observed-only` or `unmanaged`, with the reason.

73 controls: 33 enforced (1 of them by CI gates), 28 observed-only, 12 unmanaged (11 of them retired invariants).

| Id | Control | Status | Why it is not enforced |
| --- | --- | --- | --- |
| INV-001 | Every hashed structure is JCS-canonical first | enforced | — |
| INV-002 | ProofGraph ordering and node hashes are wall-clock independent | enforced | — |
| INV-003 | EvidencePack roots are deterministic and inclusion is tamper-evident | enforced | — |
| INV-004 | Egress enforcement is fail-closed | enforced | — |
| INV-005 | A policy runtime that cannot evaluate denies | enforced | — |
| INV-006 | An unclassified effect is irreversible until proven otherwise | observed-only | The reversibility classifier is unreachable from core/cmd/helm-ai-kernel: ReversibilityClassifier.Classify and DefaultForType are in scripts/ci/deadcode-allowlist.txt. No shipped path classifies an effect, so the default governs nothing at runtime. |
| INV-007 | A verdict the gateway cannot verify is not a verdict | observed-only | The verifier is a library that no shipped binary calls: VerifyResponse and EvaluateGatewayResponse are in scripts/ci/deadcode-allowlist.txt. The gateway that would run it is not in this repository, so the tests prove the library, not a production path. |
| INV-008 | An EffectPermit authorizes one connector, one action, one scope | observed-only | The verifier is a library that no shipped binary calls: PermitLedger.ConsumePermit and EvaluateAndConsumeGatewayResponse are in scripts/ci/deadcode-allowlist.txt. The gateway that would run it is not in this repository, so the tests prove the library, not a production path. |
| INV-009 | DENY and ESCALATE carry no permit material | observed-only | The verifier is a library that no shipped binary calls: VerifyResponse is in scripts/ci/deadcode-allowlist.txt. The gateway that would run it is not in this repository, so the tests prove the library, not a production path. |
| INV-010 | A permit cannot outlive the verdict that authorized it | observed-only | The verifier is a library that no shipped binary calls: VerifyResponse is in scripts/ci/deadcode-allowlist.txt. The gateway that would run it is not in this repository, so the tests prove the library, not a production path. |
| INV-011 | A credential binds to exactly one principal | enforced | — |
| INV-012 | Signature algorithms do not cross-verify | observed-only | The key ring is unreachable from core/cmd/helm-ai-kernel: every KeyRing method is in scripts/ci/deadcode-allowlist.txt, so no shipped signing or verification path goes through it. |
| INV-013 | Apply policy is decided in exactly one place | retired | Retired 2026-09-24 (HELM-756): the implementation was deleted without ever having a production caller. Its rule survives as INV-008. |
| INV-014 | An override may clear an unknown, never a proven-false | retired | Retired 2026-09-24 (HELM-756): the implementation was deleted without ever having a production caller. Its rule survives as INV-005. |
| INV-015 | An override binds to the exact patch bytes it accepted | retired | Retired 2026-09-24 (HELM-756): the implementation was deleted without ever having a production caller. Its rule survives as INV-008. |
| INV-016 | Override authority has scope only on a run awaiting a decision | retired | Retired 2026-09-24 (HELM-756): the implementation was deleted without ever having a production caller. Its rule survives as INV-010. |
| INV-017 | Every live-tree mutation path is registered with a complete fence | retired | Retired 2026-09-24 (HELM-756): the implementation was deleted without ever having a production caller. Its rule survives as INV-024. |
| INV-018 | A refused apply leaves the live tree byte-identical | retired | Retired 2026-09-24 (HELM-756): the implementation was deleted without ever having a production caller. Its rule survives as INV-009. |
| INV-019 | Verification never mutates the live tree, and silence is not a pass | retired | Retired 2026-09-24 (HELM-756): the implementation was deleted without ever having a production caller. Its rule survives as INV-025. |
| INV-020 | Diff capture is byte-faithful | retired | Retired 2026-09-24 (HELM-756): the implementation was deleted without ever having a production caller. Its rule survives as INV-008 and INV-001. |
| INV-021 | The provider credential scrub is cross-provider | retired | Retired 2026-09-24 (HELM-756): the implementation was deleted without ever having a production caller. Its rule survives as INV-011. |
| INV-022 | Exactly one terminal event per run, on every exit path | retired | Retired 2026-09-24 (HELM-756): the implementation was deleted without ever having a production caller. Its rule survives as INV-024. |
| INV-023 | An unenforceable read-only claim is refused, not assumed | retired | Retired 2026-09-24 (HELM-756): the implementation was deleted without ever having a production caller. Its rule survives as INV-024. |
| INV-024 | An adapter governs only the calls actually routed through it | unmanaged | A limit on what may be claimed, not a runtime control. No code can check that an adapter's documentation names the paths it does not intercept; the review question in its verify: line is human-owned. |
| INV-025 | The gates that prove these invariants are themselves gated | enforced (build) | — |
| CTL-001 | Guardian default-deny | enforced | — |
| CTL-002 | Route auth tiers | enforced | — |
| CTL-003 | FORCE RLS on Postgres tenant tables | enforced | — |
| CTL-004 | Global freeze | enforced | — |
| CTL-005 | Scoped emergency-stop fence | enforced | — |
| CTL-006 | Fence-scope binding | enforced | — |
| CTL-007 | Tenant and principal come from the token | observed-only | Not held. Tenant and principal arrive as X-Helm-Tenant-ID and X-Helm-Principal-ID headers beside a shared bearer key. The kernel checks them against the configured pair or a principal-binding row, but does not derive them from the credential. Only the approval workload routes take tenant and workspace from a verified JWT, and CTL-006 binds the configured scope while the emergency-stop fence is on. |
| CTL-008 | Approval grant is consumed once | enforced | — |
| CTL-009 | Evidence bundle verification | enforced | — |
| CTL-010 | MCP tool-call mediation | enforced | — |
| CTL-011 | Guardian budget draw-down | observed-only | No shipped path injects a budget tracker: Guardian.SetBudgetTracker has no production caller and WithBudgetTracker is in scripts/ci/deadcode-allowlist.txt, so the draw-down gate is skipped at runtime. Nothing reports a budget enforcer: GET /api/v1/budget/status, which answered a hard-coded active one, and `budget verify`, which printed a constant PASS, were removed (HELM-780). `budget set` records ceilings that nothing enforces. |
| CTL-012 | Decision receipts are signed and tampering fails | enforced | — |
| CTL-013 | API rate limiting | enforced | — |
| CTL-014 | Dispatch admission is idempotent | enforced | — |
| CTL-015 | Effect reservation before dispatch | observed-only | Unreachable from core/cmd/helm-ai-kernel: NewEffectReservationAdmitter and EffectReservationAdmitter.Admit are in scripts/ci/deadcode-allowlist.txt, as is the generic api.IdempotencyMiddleware. The Postgres tests prove the library only. |
| CTL-016 | Spend proxy quotes before dispatch | enforced | — |
| CTL-017 | Boundary Enforcement Profile attestation | observed-only | The kernel attests; systemd and nftables enforce. The shipped binary observes posture at service start and on demand, and deploy/appliance/helm-boundary-attest.service turns a failed attestation into a blocked gateway start. |
| CTL-018 | Tainted-data egress deny | enforced | — |
| CTL-019 | Guardian threat-scan gate | enforced | — |
| CTL-020 | Context-fingerprint gate | enforced | — |
| CTL-021 | ZeroID and SPIFFE envelopes are refused | enforced | — |
| CTL-022 | The request body carries no security authority | enforced | — |
| CTL-023 | Untenanted stores serve only the configured tenant | enforced | — |
| CTL-024 | Policy reconciliation fails closed | enforced | — |
| CTL-025 | MCP authorize-call quarantine firewall | enforced | — |
| CTL-026 | Non-loopback listeners require auth | observed-only | Reachable and tested, but deleting the check makes the listener start and block, so the refusal tests hang rather than fail. A removal proof needs a test that asserts the refusal without serving; none exists yet. |
| CTL-027 | Offline update-bundle verification | enforced | — |
| CTL-028 | External host receipt-chain verification | enforced | — |
| CTL-029 | Operator TUI typed ceremony | enforced | — |
| CTL-030 | MCP HTTP OAuth | observed-only | Reachable from core/cmd/helm-ai-kernel and tested, but no removal proof deletes the control yet, so R1 does not count it as enforced. Found by the HELM-746 claim sweep. |
| CTL-031 | Proxy withholds ungovernable tool responses | observed-only | Reachable from core/cmd/helm-ai-kernel and tested, but no removal proof deletes the control yet, so R1 does not count it as enforced. Found by the HELM-746 claim sweep. |
| CTL-032 | Savings-pack verification needs a pinned issuer | observed-only | Reachable from core/cmd/helm-ai-kernel and tested, but no removal proof deletes the control yet, so R1 does not count it as enforced. Found by the HELM-746 claim sweep. |
| CTL-033 | Launchpad local-container preflight and egress allowlist | observed-only | Reachable from core/cmd/helm-ai-kernel and tested, but no removal proof deletes the control yet, so R1 does not count it as enforced. Found by the HELM-746 claim sweep. |
| CTL-034 | Delegation-session gate | observed-only | Production wires an empty in-memory delegation store that nothing writes, so every delegation_session_id denies. The documented checks (session capabilities within the delegator's policy, scope and principal) never run against a real session. |
| CTL-035 | Local coding-agent hook shell guard | observed-only | The client decides which calls reach the hook, and classifying command text cannot be sound; the docs label this integration observed-only. It denies a narrow set of destructive patterns and syntax it cannot evaluate statically. |
| CTL-036 | Workstation enforce wrapper | observed-only | Only a refusal test exists; no allowed-case or removal test shows the wrapper exits 126 on DENY and runs the command on ALLOW. |
| CTL-037 | Workstation decision-receipt verification | observed-only | Tested, but no removal proof deletes the check yet, so R1 does not count it as enforced. |
| CTL-038 | Kubernetes transparent egress for Launchpad | observed-only | Held by an iptables REDIRECT and tools/launchpad/egressproxy, both outside the core module and the shipped binary; this gate neither reaches nor runs them. |
| CTL-039 | Release publication gates | observed-only | Held by the release workflow at publication time. A build-plane entry here must be a gate that blocks pull requests, which these are not. |
| CTL-040 | Effect close | observed-only | EffectCloser.Close is in scripts/ci/deadcode-allowlist.txt: no shipped path closes an effect. |
| CTL-041 | Connector release authority | observed-only | The writer, PostgresReleaseAuthorityAdminStore.Append, is in scripts/ci/deadcode-allowlist.txt, so no shipped path records a release authority for the reader to enforce. |
| CTL-042 | Guardian governance options not installed | observed-only | The capability registry, task capability tokens, rollback plans, session risk memory and privilege resolver are Guardian options that no shipped binary installs: each With* option is in scripts/ci/deadcode-allowlist.txt. |
| CTL-043 | Unwired adapters | observed-only | BrowserSplitAdapter, SentinelConnector, VaultakStateBridge and AIPVerifier are libraries that no shipped binary mounts or calls; their methods are in scripts/ci/deadcode-allowlist.txt. |
| CTL-044 | WASI sandbox containment | observed-only | The shipped server refuses every WASI pack run because it has no PackVerifier, and WASISandbox.Run and SandboxBroker.Execute are in scripts/ci/deadcode-allowlist.txt. Sandbox grants and preflight are records only. |
| CTL-045 | Connector contract pinning | observed-only | ValidateAndCanonicalizeToolOutput is in scripts/ci/deadcode-allowlist.txt, and the preview TON Acton connector that also reports drift is not linked into core/cmd/helm-ai-kernel. |
| CTL-046 | Mandates only narrow on delegation | observed-only | Library only. No shipped binary imports core/pkg/kernel/authority/authorityrows (a declared library root in scripts/ci/dead-packages-allowlist.txt), and admission does not read the authority rows yet. The HELM-751 admission transaction is the first caller. Until it lands, the Postgres tests prove the library. |
| CTL-047 | Production egress is deny-all | enforced | — |
| CTL-048 | Kernel credentials never reach the model provider | enforced | — |

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

A rule that does not compile, an evaluation error, a non-boolean result, an
evaluation that exceeds its cost limit, an action with no policy: each answers
DENY. "Could not decide" and "decided to allow" are different facts and the
kernel never collapses them.

The owner is the CEL `decide` that the Guardian calls on every evaluation
(HELM-750). The rule was previously pinned to the WASM host
`core/pkg/policy/wasm`, which never had a production caller and was removed in
HELM-756.

verify: `core/pkg/kernel/authority/authority.go` · tests `TestDecideFailsClosed`, `TestCompileErrorsDenyOnlyTheirAction`, `TestDecideCostLimitDenies`, `TestCompileNilGraphDeniesEverything`, `TestPropertyUnknownActionDenies`

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

RETIRED section, 2026-09-24 (HELM-756). INV-013 to INV-020 were held by
`core/pkg/patchdelivery` and `core/pkg/worktree`. Neither package ever had a
production caller, a CLI command, a route, or a receipt, and both are deleted.
Under the target architecture (rev 3.4, §7.1–7.2) agents work inside a bought
sandbox, and a change reaches a repository only as an effect admitted through
the gateway. No kernel code writes to a user's live working tree, so the
behaviour these invariants governed is out of scope here. The authorization
half of the rules continues under the successors each entry names. The
decision and its evidence are recorded in
[the wave-1 retirement inventory](docs/retirement/wave-1-inventory.md).

### INV-013 — Apply policy is decided in exactly one place

`Eligibility` is the only function that answers "may this patch touch a live
tree". Every caller — CLI, control API, scheduler, future UI — routes through it
and acts on the Decision it returns. A caller that re-implements "looks approved
to me" creates a second policy with no receipt, and the first time the two
disagree is a mutation nobody authorized.

RETIRED 2026-09-24 (HELM-756): the implementation was deleted without ever
having a production caller. The single decision point for repository writes is
now admission: a write is an effect, and INV-008 binds its permit to one
connector, one action and one scope.

verify: `docs/retirement/wave-1-inventory.md` · retirement record; no code in this tree holds the rule

### INV-014 — An override may clear an unknown, never a proven-false

Deliverability is tri-state. UNKNOWN blocks fail-closed and an operator may
accept that risk. PROVEN-undeliverable is checked before any override is even
evaluated, because it is a fact about the patch rather than a policy judgment,
and no authority makes a conflicting patch apply.

RETIRED 2026-09-24 (HELM-756): the implementation was deleted without ever
having a production caller. Unknown-is-blocking survives as INV-005, which
answers DENY whenever a decision cannot be made.

verify: `docs/retirement/wave-1-inventory.md` · retirement record; no code in this tree holds the rule

### INV-015 — An override binds to the exact patch bytes it accepted

The override carries the SHA-256 of the patch the operator looked at. Change one
byte and the override no longer authorizes it, because it no longer describes
it. This is INV-008 in miniature: the reviewed thing and the applied thing must
be provably identical.

RETIRED 2026-09-24 (HELM-756): the implementation was deleted without ever
having a production caller. Content binding survives as INV-008, of which this
rule was a miniature.

verify: `docs/retirement/wave-1-inventory.md` · retirement record; no code in this tree holds the rule

### INV-016 — Override authority has scope only on a run awaiting a decision

An override answers a question that was actually asked. On a run nobody has
reviewed there is no risk decision to accept, so the override is refused and the
run needs a reviewer. A run that merely hit a broken verifier cannot be waved
through on authority that was never meant for it.

RETIRED 2026-09-24 (HELM-756): the implementation was deleted without ever
having a production caller. Scoping authority to a decision that was actually
asked survives as INV-010, which bounds a permit by the verdict that authorized
it.

verify: `docs/retirement/wave-1-inventory.md` · retirement record; no code in this tree holds the rule

### INV-017 — Every live-tree mutation path is registered with a complete fence

Each code path that can write to a user's repository on behalf of an agent run
is named in the registry and declares the enforcement in front of it. An
unregistered path — or one registered with an empty fence — fails the build. The
point is to make "which code can write to a live tree" an answerable question
instead of an archaeology exercise.

RETIRED 2026-09-24 (HELM-756): the implementation was deleted without ever
having a production caller. The requirement to name every governed path survives
as INV-024: HELM governs only the calls routed through it, and says so.

verify: `docs/retirement/wave-1-inventory.md` · retirement record; no code in this tree holds the rule

### INV-018 — A refused apply leaves the live tree byte-identical

Apply is all-or-nothing and re-asserts the target preimage immediately before
writing. A tree that moved underneath the patch is a refusal, not a merge. When
a partial write cannot be withdrawn the result says so plainly rather than
reporting a clean tree the operator does not have.

RETIRED 2026-09-24 (HELM-756): the implementation was deleted without ever
having a production caller. With no kernel write path to a live tree there is
nothing to leave byte-identical. A refused effect is not dispatched at all
(INV-009).

verify: `docs/retirement/wave-1-inventory.md` · retirement record; no code in this tree holds the rule

### INV-019 — Verification never mutates the live tree, and silence is not a pass

The pre-apply verify runs against an isolated copy and leaves the operator's
tree untouched. "No gates were configured" is reported as its own state and
never as "gates passed" — an unasked question has no answer.

RETIRED 2026-09-24 (HELM-756): the implementation was deleted without ever
having a production caller. The rule that silence is not a pass survives as
INV-025, which forbids a gate from degrading into a no-op that still reports
success.

verify: `docs/retirement/wave-1-inventory.md` · retirement record; no code in this tree holds the rule

### INV-020 — Diff capture is byte-faithful

Work product is captured raw. CRLF survives, binary survives, and the bytes that
were reviewed are the bytes that get applied. A diff that cannot round-trip
byte-for-byte is not evidence of anything.

RETIRED 2026-09-24 (HELM-756): the implementation was deleted without ever
having a production caller. Byte-faithful binding of the reviewed thing to the
executed thing survives as INV-008 and INV-001.

verify: `docs/retirement/wave-1-inventory.md` · retirement record; no code in this tree holds the rule

---

## Agent process envelope

INV-021 to INV-023 are RETIRED, 2026-09-24 (HELM-756). They were held by
`core/pkg/harness`, which spawned vendor coding-agent CLIs as child processes.
It never had a production caller and is deleted. In the target architecture
(rev 3.4, §7.1–7.2) a runner inside the sandbox image speaks the episode
protocol, and the sandbox holds no credentials at all. Two requirements outlive
the package: no provider credential reaches an agent run, and each run ends in
exactly one terminal event (`done` or `failed`). Both must acquire a tested
owner in the episode runner and the control registry (architecture §14.4)
before any release claims them. Until then nothing in this repository enforces
them, and no document may say otherwise. INV-024 stays in force.

### INV-021 — The provider credential scrub is cross-provider

A run routed to one model provider is stripped of every provider's credentials
and base-URL redirects, not just the routed vendor's. Otherwise a multi-provider
CLI can be steered by a config file or a fallback path onto an inherited key,
and the run gets billed to and attributed to a principal HELM never selected.
The caller's own extra-env channel is scrubbed on the same rule, because a fence
that holds everywhere except the convenient door is not a fence.

RETIRED 2026-09-24 (HELM-756): the implementation was deleted without ever
having a production caller. Credential custody moves to the sandbox and model
gateway (§7.2, §8): the run receives no provider credential at all, which is
stronger than scrubbing. INV-011 continues to bind each credential to one
principal.

verify: `docs/retirement/wave-1-inventory.md` · retirement record; no code in this tree holds the rule

### INV-022 — Exactly one terminal event per run, on every exit path

Clean exit, non-zero exit, spawn failure, context cancellation: each produces one
completion and no more. A run that emits two terminals double-counts, and one
that emits none leaves a supervisor waiting on a process that is already gone.
Killing a run reaps the whole process tree; dropped output is counted rather than
silently discarded.

RETIRED 2026-09-24 (HELM-756): the implementation was deleted without ever
having a production caller. The episode protocol (§7.1, contract 9) must carry
this rule with a tested owner. Meanwhile INV-024 limits what may be claimed:
HELM supervises no agent process, so no run-lifecycle guarantee may be claimed.

verify: `docs/retirement/wave-1-inventory.md` · retirement record; no code in this tree holds the rule

### INV-023 — An unenforceable read-only claim is refused, not assumed

If the vendor build cannot be shown to honour the read-only flags HELM passes it,
the run is refused rather than started on the assumption that it will behave. A
probe that cannot answer fails closed. Scoped HOME lives outside the work tree so
vendor state cannot leak into the diff.

A vendor that has no read-only posture to probe is refused at the capability
declaration instead: it does not advertise `AccessReadonly`, and its `Run`
refuses the profile unconditionally. That is the stronger form of the same rule,
because a constant comparison has no failure mode that admits the run.

RETIRED 2026-09-24 (HELM-756): the implementation was deleted without ever
having a production caller. Survives as INV-024: HELM may claim coverage only
for the path it actually intercepts, and a read-only label nobody enforces is a
claim about configuration.

verify: `docs/retirement/wave-1-inventory.md` · retirement record; no code in this tree holds the rule

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
