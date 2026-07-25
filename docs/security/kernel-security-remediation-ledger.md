# Kernel Security Remediation Ledger

Source scan: `/Users/ivan/Code/Mindburn-Labs/.codex-security-scan/security_scan_report.portfolio_plus_addendum.md`

Scope rule: strict kernel findings whose IDs start with `HELM_AI_KERNEL-` or `helm-ai-kernel-FILE-`.

Status values:

- `already-fixed-with-regression`: covered by remediation checkpoints before this ledger.
- `remaining`: still requires implementation in the completion pass.
- `fixed`: implemented during the completion pass after this ledger was created.

Current branch baseline: `codex/kernel-security-remediation` at `ee2cfd6d`, before syncing the branch with the two missing `origin/main` commits.

| Finding ID | Status | Remediation surface |
|---|---|---|
| HELM_AI_KERNEL-SUBAGENT-0098 | already-fixed-with-regression | Runtime evaluate API auth and principal binding |
| HELM_AI_KERNEL-SUBAGENT-0084 | already-fixed-with-regression | Legacy Launchpad API auth |
| helm-ai-kernel-FILE-0784-A | already-fixed-with-regression | External host evidence trust roots |
| helm-ai-kernel-FILE-0669-A | already-fixed-with-regression | G1 conformance receipt signatures |
| helm-ai-kernel-FILE-0665-A | already-fixed-with-regression | KernelBridge unknown-tool fail-closed behavior |
| helm-ai-kernel-FILE-0657-A | already-fixed-with-regression | Channel gateway webhook signatures |
| helm-ai-kernel-FILE-0636-A | already-fixed-with-regression | Browser side-effect classification |
| helm-ai-kernel-FILE-0635-A | already-fixed-with-regression | Skill bundle trusted signature proofs |
| helm-ai-kernel-FILE-0634-A | already-fixed-with-regression | Connector release trusted signature proofs |
| helm-ai-kernel-FILE-0610-A | already-fixed-with-regression | JWKS HTTPS enforcement |
| helm-ai-kernel-FILE-0598-A | already-fixed-with-regression | AIP delegation signature checks |
| helm-ai-kernel-FILE-0590-A | already-fixed-with-regression | MCP delegation scope validation |
| helm-ai-kernel-FILE-0584-A | already-fixed-with-regression | PDP attestation admission checks |
| helm-ai-kernel-FILE-0551-A | already-fixed-with-regression | Attestation metadata signature binding |
| helm-ai-kernel-FILE-0549-B | already-fixed-with-regression | Admission profile requirement enforcement |
| helm-ai-kernel-FILE-0549-A | already-fixed-with-regression | Unsigned attestation denial |
| helm-ai-kernel-FILE-0545-A | already-fixed-with-regression | Unsupported perimeter controls fail closed |
| helm-ai-kernel-FILE-0543-A | already-fixed-with-regression | Artifact envelope signature binding |
| helm-ai-kernel-FILE-0514-A | already-fixed-with-regression | TelemetryPDP observe-only shadow mode |
| helm-ai-kernel-FILE-0432-A | already-fixed-with-regression | ZK receipt mock seal verification |
| HELM_AI_KERNEL-SUBAGENT-0100 | already-fixed-with-regression | Standalone Launchpad API auth |
| HELM_AI_KERNEL-SUBAGENT-0097 | already-fixed-with-regression | Control-plane policy bundle signature enforcement |
| HELM_AI_KERNEL-SUBAGENT-0091 | already-fixed-with-regression | GitHub EffectPermit scope enforcement |
| HELM_AI_KERNEL-SUBAGENT-0089 | already-fixed-with-regression | Control-plane policy update trust roots |
| HELM_AI_KERNEL-SUBAGENT-0087 | fixed | Claude-managed sandbox per-session filesystem isolation |
| HELM_AI_KERNEL-SUBAGENT-0086 | fixed | Claude-managed sandbox environment scrubbing |
| HELM_AI_KERNEL-SUBAGENT-0085 | already-fixed-with-regression | Guardian effect-digest intent binding |
| HELM_AI_KERNEL-SUBAGENT-0083 | already-fixed-with-regression | Privileged access signed receipt schema |
| HELM_AI_KERNEL-SUBAGENT-0080 | already-fixed-with-regression | TUF metadata signature verification |
| HELM_AI_KERNEL-SUBAGENT-0079 | already-fixed-with-regression | Rekor checkpoint signature verification |
| HELM_AI_KERNEL-SUBAGENT-0078 | fixed | Workstation receipt trust roots and signer defaults |
| HELM_AI_KERNEL-SUBAGENT-0036 | fixed | Workstation enforce operate-mode execution guard |
| HELM_AI_KERNEL-SUBAGENT-0030 | fixed | Signed trust registry mutations |
| HELM_AI_KERNEL-SUBAGENT-0029 | already-fixed-with-regression | Kernel Launchpad API auth |
| HELM_AI_KERNEL-SUBAGENT-0028 | already-fixed-with-regression | Autonomy control admin auth |
| HELM_AI_KERNEL-SUBAGENT-0022 | fixed | Launchpad mount-name containment |
| HELM_AI_KERNEL-SUBAGENT-0001 | fixed | Proxy DENY containment |
| HELM_AI_KERNEL-SUBAGENT-0092 | already-fixed-with-regression | Helm smoke helper image and kubeconfig hardening |
| HELM_AI_KERNEL-SUBAGENT-0099 | already-fixed-with-regression | Certify archive extraction bounds |
| helm-ai-kernel-FILE-0788-A | already-fixed-with-regression | Pinned TLA tools download verification |
| helm-ai-kernel-FILE-0640-A | already-fixed-with-regression | DOM trap evidence from real browser runs |
| helm-ai-kernel-FILE-0632-A | already-fixed-with-regression | AIGP evidence derived from node evidence |
| helm-ai-kernel-FILE-0602-A | already-fixed-with-regression | MCP audit receipt redaction |
| helm-ai-kernel-FILE-0594-A | already-fixed-with-regression | Launchpad cloud readiness probes |
| helm-ai-kernel-FILE-0586-A | already-fixed-with-regression | Signal health evidence from metrics |
| helm-ai-kernel-FILE-0575-A | already-fixed-with-regression | Sumo exporter TLS enforcement |
| helm-ai-kernel-FILE-0573-A | already-fixed-with-regression | Splunk exporter TLS enforcement |
| helm-ai-kernel-FILE-0571-A | already-fixed-with-regression | Loki exporter TLS enforcement |
| helm-ai-kernel-FILE-0569-A | already-fixed-with-regression | Elastic exporter TLS enforcement |
| helm-ai-kernel-FILE-0567-A | already-fixed-with-regression | Datadog exporter TLS enforcement |
| helm-ai-kernel-FILE-0492-A | already-fixed-with-regression | Polymarket order amount validation |
| helm-ai-kernel-FILE-0482-A | already-fixed-with-regression | Skill promotion evaluator evidence checks |
| helm-ai-kernel-FILE-0410-A | already-fixed-with-regression | mTLS SPIFFE peer identity binding |
| helm-ai-kernel-FILE-0390-A | already-fixed-with-regression | File audit hash-chain verification |
| helm-ai-kernel-FILE-0389-A | fixed | TON wallet secret detection |
| helm-ai-kernel-FILE-0378-A | fixed | AP2 payment signed payload binding |
| HELM_AI_KERNEL-SUBAGENT-0096 | already-fixed-with-regression | Helm Postgres TLS production guard |
| HELM_AI_KERNEL-SUBAGENT-0095 | already-fixed-with-regression | Helm Postgres Secret references |
| HELM_AI_KERNEL-SUBAGENT-0094 | already-fixed-with-regression | Guardian context provenance binding |
| HELM_AI_KERNEL-SUBAGENT-0093 | already-fixed-with-regression | Docker smoke local credential exposure |
| HELM_AI_KERNEL-SUBAGENT-0088 | already-fixed-with-regression | Runtime tenant identity binding |
| HELM_AI_KERNEL-SUBAGENT-0081 | fixed | Module attestation commit hash validation |
| HELM_AI_KERNEL-SUBAGENT-0037 | fixed | Workstation decision signing seed argv removal |
| HELM_AI_KERNEL-SUBAGENT-0035 | fixed | Workstation import signing seed argv removal |
| HELM_AI_KERNEL-SUBAGENT-0034 | fixed | Workstation receipt signing seed argv removal |
| HELM_AI_KERNEL-SUBAGENT-0033 | fixed | Shadow scan secret redaction |
| HELM_AI_KERNEL-SUBAGENT-0032 | fixed | Console login password argv removal |
| HELM_AI_KERNEL-SUBAGENT-0027 | fixed | Authority evaluation schema top-level binding |
| HELM_AI_KERNEL-SUBAGENT-0026 | fixed | Release cosign identity anchoring |
| HELM_AI_KERNEL-SUBAGENT-0025 | already-fixed-with-regression | MCP firewall canonical verdicts |
| HELM_AI_KERNEL-SUBAGENT-0023 | already-fixed-with-regression | Sandbox broker bearer-token validation |
| HELM_AI_KERNEL-SUBAGENT-0021 | fixed | Acton connector permit and grant binding |
| HELM_AI_KERNEL-SUBAGENT-0020 | already-fixed-with-regression | E2B HTTPS preflight enforcement |
| HELM_AI_KERNEL-SUBAGENT-0019 | already-fixed-with-regression | Daytona HTTPS preflight enforcement |
| HELM_AI_KERNEL-SUBAGENT-0018 | fixed | Claude-managed shim dispatcher policy |
| HELM_AI_KERNEL-SUBAGENT-0017 | already-fixed-with-regression | Inbound channel strict signature metadata |
| HELM_AI_KERNEL-SUBAGENT-0016 | fixed | Execute-payment schema payee and amount constraints |
| HELM_AI_KERNEL-SUBAGENT-0015 | already-fixed-with-regression | Helm external Postgres Secret handling |
| HELM_AI_KERNEL-SUBAGENT-0014 | fixed | TEE secret proxy plaintext storage |
| HELM_AI_KERNEL-SUBAGENT-0013 | fixed | EvidencePack trusted signature root enforcement |
| HELM_AI_KERNEL-SUBAGENT-0012 | fixed | Scoped MCP approval expiry and tool binding |
| HELM_AI_KERNEL-SUBAGENT-0011 | fixed | Reference-pack policy hash binding |
| HELM_AI_KERNEL-SUBAGENT-0010 | fixed | Python publish workflow dispatch input validation |
| HELM_AI_KERNEL-SUBAGENT-0009 | fixed | npm publish workflow dispatch input validation |
| HELM_AI_KERNEL-SUBAGENT-0008 | fixed | Maven publish workflow dispatch input validation |
| HELM_AI_KERNEL-SUBAGENT-0007 | fixed | Clean-install workflow dispatch input validation |
| HELM_AI_KERNEL-SUBAGENT-0006 | fixed | Crates publish workflow dispatch input validation |
| HELM_AI_KERNEL-SUBAGENT-0005 | fixed | Managed-agent receipt signer default |
| HELM_AI_KERNEL-SUBAGENT-0003 | fixed | Policy-reader RBAC Secret scope |
| HELM_AI_KERNEL-SUBAGENT-0002 | already-fixed-with-regression | Proxy receipt causal chain continuity |
| HELM_AI_KERNEL-SUBAGENT-0090 | already-fixed-with-regression | Pack verify authenticity fail-closed behavior |
| HELM_AI_KERNEL-SUBAGENT-0082 | already-fixed-with-regression | Python SDK path segment validation |
| HELM_AI_KERNEL-SUBAGENT-0024 | already-fixed-with-regression | WASI pack trust verifier |
| HELM_AI_KERNEL-SUBAGENT-0031 | already-fixed-with-regression | Doctor diagnostic seed redaction |
| HELM_AI_KERNEL-SUBAGENT-0004 | already-fixed-with-regression | Sandbox filesystem path containment |

## 2026-07-25 red-team pass — trust-root and enforcement findings

Source: internal red-team engagement against `main` @ `258afa85`. Distinct from
the earlier portfolio scan above: every finding below was reproduced as an
executable proof-of-concept against the unmodified tree before any fix, and each
carries a regression test that fails on the pre-fix code.

Severity key: **T0** breaks the trust root on its own · **T1** weakens signature
scope, caching, or dual control · **T2** perimeter · **T3** CI and test integrity.

| ID | Sev | Finding | Anchor | Status |
|---|---|---|---|---|
| F-01 | T0 | `NewEd25519Signer` takes a key *identifier* and generates a fresh random keypair, discarding all configured key material. `--sign`, `SYSTEM_BOOT_KEY` and `EVIDENCE_SIGNING_KEY` established no trust root; keys rotated on every restart; the supposed secret was written into every receipt's `KeyID` in cleartext. | `core/pkg/crypto/signer.go:43` | fixed |
| F-02 | T0 | Default `dev-local` trust profile resolved the verification key from `seal.signer.public_key` — a field inside the pack being verified. Any keypair could sign its own EvidencePack and obtain `PASS: n/n checks passed`. | `core/pkg/evidence/seal.go:1157` | fixed |
| F-03 | T0 | Offline verifier's chain-of-custody checks do not check chain of custody. `checkChainIntegrity` passes on "proofgraph.json parses as JSON"; `checkLamportMonotonicity` passes on "N receipt files present"; `checkPolicyDecisionHashes` passes on non-empty strings. Truncated, reordered and forked chains all verify. | `core/pkg/verifier/verifier.go:802,830,854` | remaining |
| F-04 | T0 | `ZeroIDInterceptor` overwrote the authenticated principal with a caller-supplied `spiffe_uri` after checking only the URI prefix, and labelled the result `zeroid_verified`. `trustedKeys` was stored and never read. First interceptor in every Guardian's default chain. **PoC: a tenant-A low-privilege agent became `spiffe://tenant-b.example/admin` before the PDP.** | `core/pkg/guardian/zeroid.go:51` | fixed |
| F-05 | T1 | Receipt signature covers 8 of ~80 fields. `Verdict`, `Timestamp`, `PolicyHash`, `MerkleRoot`, `KeyID`, `PublicKeySet`, `WitnessSignatures` and transparency-log anchoring are all unsigned and rewritable without breaking the signature. | `core/pkg/crypto/canonical.go:153` | remaining |
| F-06 | T1 | Signing preimages are `:`-joined with no escaping (`SigSeparator = ":"`), so field-boundary shifts produce identical preimages and one signature verifies two distinct records. IDs in this codebase routinely contain `:`. | `core/pkg/crypto/canonical.go:43,153` | remaining |
| F-07 | T1 | `Verify` keyed a process-global result cache on unframed `sha256(pubKeyHex ‖ sigHex ‖ data)` and consulted it *before* decoding or length-checking inputs. **PoC: after one genuine verification, a 65-byte signature over a different message returned `true`; `ed25519.Verify` never ran.** Same class in `Ed25519Verifier.Verify` (`H(message ‖ signature)`), where a 63-byte signature over a tampered message verified. | `core/pkg/crypto/signer.go:80`, `core/pkg/crypto/verifier.go:38` | fixed |
| F-08 | T1 | Approver identity for the 2-of-2 quorum is a plain `actor` string in the request body, deduped by string equality. One admin token satisfies a 2-of-2 quorum by posting `/approve` twice with different names. No requester-vs-approver distinctness. WebAuthn variant only checks the assertion is non-empty. | `core/cmd/helm-ai-kernel/contract_routes.go:1232`, `core/pkg/boundary/surface_registry.go:517` | remaining |
| F-09 | T1 | Executor idempotency short-circuit returns a signed receipt before `validateGating` runs, so an unsigned `DecisionRecord` carrying only a known `decision.ID` yields a success return. | `core/pkg/executor/executor.go:112` | remaining |
| F-10 | T1 | Single-entry inclusion proofs are self-attesting: the proof is checked against a root carried inside the same document, with no signature and no external root parameter. An empty `merkle_path` makes any leaf its own root. | `core/pkg/evidencepack/inclusionproof.go:149` | remaining |
| F-11 | T2 | 14 of 21 handlers in `subsystems.go` are neither auth-wrapped nor present in the route contract registry, including `POST /api/v1/memory/promote` (unauthenticated governed-memory promotion, no body limit), `GET /api/v1/memory/list` (raw `namespace` from query, no tenant scoping), the economic ledger endpoints, and `GET /api/v1/boundary/check?url=` (egress-policy oracle). | `core/cmd/helm-ai-kernel/subsystems.go` | remaining |
| F-12 | T2 | Rate-limit bucket key is built from raw `X-Helm-Tenant-ID`/`X-Helm-Principal-ID`/`X-Helm-Actor-ID` headers — rotate to evade, or pin a victim's key to exhaust their bucket. | `core/pkg/api/middleware.go:266` | remaining |
| F-13 | T2 | Public `/__helm/config.json` returns the `tenant_id` and `principal_id` that the tenant-scoped routes expect. | `core/cmd/helm-ai-kernel/local_first_run_routes.go:105` | remaining |
| F-14 | T3 | `.golangci.yml` is never executed (`make lint` runs only `go vet` + `gofmt -l`, no workflow invokes it) and sets `tests: false`. gosec, semgrep and trivy are absent; `govulncheck` and secret scanning are advisory-only and nightly. | `Makefile:124`, `.golangci.yml` | remaining |
| F-15 | T3 | Dependabot version PRs disabled across all 8 ecosystems while Renovate auto-merges all minor+patch with no review — unreviewed supply-chain ingress. | `.github/dependabot.yml`, `renovate.json` | remaining |
| F-16 | T3 | `tests/parity_test.go` compares four identical hard-coded literals and cannot fail; it validates nothing about cross-language canonicalization. | `tests/parity_test.go:15` | remaining |
| F-17 | T3 | `TestEvidencePackSingleSource` walked the filesystem without skipping dot-directories, so any developer with a `.claude/worktrees/` checkout got a spuriously red suite (16 "duplicate" definitions). A test that fails for environmental reasons trains people to ignore red. | `core/pkg/contracts/evidence_pack_single_source_test.go` | fixed |
| F-18 | T3 | Two tests asserted vulnerable behaviour as correct: `zeroid_test.go` asserted the F-04 principal rebinding, and the verifier fixtures asserted that a self-attested pack verifies. Both now assert the inverse or opt in explicitly. | `core/pkg/guardian/zeroid_test.go:38`, `core/pkg/verifier/verifier_test.go` | fixed |

### Notes

- **F-04 removed capability deliberately.** `ZeroIDInterceptor` never verified
  anything, so it is now fail-closed: a presented ZeroID envelope is denied with
  a signed decision rather than trusted. Making ZeroID real requires a specified
  token format, signature verification against a trust root obtained outside the
  request, and issuer/audience/expiry/revocation checks — none of which existed.
- **F-02 escape hatch.** `HELM_ALLOW_SELF_ATTESTED_EVIDENCE=1` preserves the
  local dev and demo loop. It must never be set where provenance matters.
- **F-01 blast radius.** `NewEd25519Signer` is retained for ephemeral dev use and
  now fails closed under `HELM_PRODUCTION`. Persistent signers use
  `NewEd25519SignerFromSeed` / `NewEd25519SignerFromEncodedSeed`.
- All five T0/T1 core defects reproduce identically in `helm-ai-enterprise`
  (`crypto/signer.go:43`, `guardian/zeroid.go:51`, `evidence/seal.go:1116`,
  `verifier/verifier.go:757`, `crypto/signer.go:91`) and must be propagated.

### 2026-07-25 addendum — schema defects surfaced by implementing F-03

Implementing a real chain-of-custody walk exposed three defects that the
placeholder checks had been hiding. They are the reason the check was a stub:
you cannot verify a chain whose hash function is unspecified.

| ID | Sev | Finding | Status |
|---|---|---|---|
| F-19 | T1 | **No canonical chain-hash derivation.** Three producers link receipts three different ways: `store.buildNextCausalReceipt` uses `contracts.ReceiptChainHash` (JCS over the receipt); `mcp-proof` uses `"sha256:" + sha256` of the pretty-printed receipt file as written (`cmd/helm-ai-kernel/mcp_proof_cmd.go:396-402`); `demo`/`financedemo` chain on a `hash` field the receipt declares about itself (`cmd/helm-ai-kernel/demo_cmd.go:285-288`). A third-party verifier cannot check a chain without knowing which convention a pack used. | mitigated |
| F-20 | T1 | **Self-declared receipt hashes have no specified preimage.** For the demo/financedemo shape, `hash` is asserted by the producer and cannot be recomputed by any verifier. For those receipts the walk proves the chain is well-formed, not that each node's contents are bound to its identity. | remaining |
| F-21 | T1 | **Launchpad and conform packs emit no chain at all.** Receipts carry `lamport_clock` values implying an order but no `prev_hash` linking them (`core/pkg/launchpad/receipts`). These packs assert no chain of custody, which is materially weaker than the product's claim. | remaining |

**Mitigation shipped for F-19:** each receipt is given a candidate identity set —
`ReceiptChainHash`, `"sha256:"+sha256(file bytes)`, and any declared `hash` — and
a link is accepted if the successor's `prev_hash` matches any of them, with the
`sha256:` prefix normalised. The first two are recomputed by the verifier, so
tampering still breaks linkage. F-20 is the residual gap.

**Behaviour for F-21:** a pack where no receipt carries a `prev_hash` is reported
as `"N receipts carry no prev_hash — this pack asserts no chain of custody, so
none was verified"` rather than PASS-with-chain. This cannot be used to bypass
the walk: stripping every `prev_hash` changes what the pack claims and the report
says so. A missing or empty receipts directory still fails outright.

**Correct fix for F-19/F-20/F-21** (not attempted here — it is a format change):
specify one canonical receipt envelope and one chain-hash preimage, emit it from
every producer, and make the declared hash recomputable.

### 2026-07-25 — waves 3 and 4

| ID | Finding | Status | Note |
|---|---|---|---|
| F-08 | One credential satisfied a multi-party quorum via an asserted `actor` string | fixed | A quorum > 1 is now **refused** rather than faked: there is no verified approver identity on this path (the WebAuthn variant only checks the assertion is non-empty). Requester ≠ approver is enforced. Single-approver ceremonies, denial and revocation are unaffected. The real implementation is `boundary/approvalverify.VerifyQuorum`; routing the HTTP path through it is the remaining work. |
| F-09 | Executor idempotency short-circuit ran before `validateGating` | fixed | Three-line reorder. An unsigned `DecisionRecord` carrying only a known decision ID no longer yields a signed receipt. |
| F-11 | 12 handlers in `subsystems.go` neither auth-wrapped nor declared public | fixed | All wrapped in `protectRuntimeHandler(RouteAuthAdmin, …)`; body limits added to the two mutating POST paths. `TestSubsystemRoutesAreAuthenticatedOrExplicitlyPublic` now fails on any new unguarded route, with `TestScanRoutesDetectsAnUnguardedRoute` as its negative control. |
| F-12 | Rate-limit bucket key derived from attacker-chosen headers | fixed | The bucket is now bound to the peer address as well as the asserted actor, so rotating `X-Helm-Actor-ID` cannot mint fresh buckets and one caller cannot exhaust another's allowance. |
| F-13 | Public `/__helm/config.json` published the tenant gate's expected values | fixed | `tenant_id`/`principal_id` are disclosed only to loopback callers, checked against the real peer address rather than a forwarding header. |
| F-14 | `.golangci.yml` never executed; gosec absent | partial | `make lint-security` now runs golangci-lint with gosec over the TCB packages. **Not wired into CI**: it reports 14 findings, several of them gosec false positives (e.g. G101 on the `ContextCredentialHash` map-key constant). Triage then promote to blocking. |

**Third instance of a test asserting the vulnerability.** `TestApprovalTransitionEnforcesQuorumAndTimelock`
asserted that two `TransitionApproval` calls naming "user:alice" and "user:bob"
satisfied a 2-of-2 quorum — the F-08 bypass, encoded as expected behaviour. It
now asserts the refusal. Counting `zeroid_test.go` and the verifier seal
fixtures, three separate suites were protecting a defect from being fixed.

### Still open after this pass

F-05/F-06 (receipt signature covers 8 of ~80 fields; unescaped `:` preimages —
needs the versioned v5 JCS envelope), F-10 (self-attesting inclusion proofs),
F-15 (Dependabot disabled while Renovate auto-merges), F-16 (vacuous
`tests/parity_test.go`), F-20/F-21, live black-box pentest, and propagation of
all of the above into `helm-ai-enterprise`.

### F-16 — `tests/parity_test.go` removed

The file claimed to prove cross-language canonicalization parity across the Go,
Python, TS, Rust and Java SDKs. It did not:

- `goHash`, `pyHash`, `tsHash` and `rsHash` were four identical hard-coded
  literals compared to each other, so the assertion could never fail.
- `encoding/json` and `os/exec` were imported without being used, and
  `malformedPayload` was declared without being used — all compile errors in Go.
- It sat in `package tests` at `tests/` root, which has no `go.mod`, so it
  belonged to no module and nothing ever built it.

It was therefore a test that could not compile, was never run, and would have
proven nothing if it had. Deleted rather than repaired: a real parity test has
to execute all five SDK canonicalizers over a shared vector set and compare the
digests they actually produce, which is a separate piece of work. Removing the
file makes the absence of that coverage visible instead of simulated.

### 2026-07-25 — F-05/F-06 v5 envelope: implemented, not yet activated

`core/pkg/crypto/canonical_v5.go` adds `ReceiptPreimageV5` (JCS over the whole
receipt minus its signature), `ReceiptPreimageV4` (the legacy eight-field
string, retained for verification only) and `VerifyReceiptSignature`, which
tries v5 then v4 and reports which matched.

Two properties are proven by test: a JCS object cannot suffer the v4
field-boundary collision (`TestF06_FieldBoundaryShiftNoLongerCollides`, which
first asserts the v4 collision still reproduces so it cannot pass vacuously),
and the signature is excluded from its own preimage.

**`SignReceipt` still emits v4.** Switching it over is blocked on the receipt
store: `receiptColumns` (`core/pkg/store/receipt_store.go:98`) has **no column
for `key_id`, `public_key_set`, `signature_profile`, `signature_algorithm` or
`correlation_id`**. Those fields are empty after a load, so a signature covering
them cannot match a persisted receipt. Attempting the switch turned five CLI
tests red for exactly this reason.

Signing only the subset that survives the store would silently reintroduce F-05
for everything dropped, so the ordering is: **schema migration first, then flip
the signer**. A second, smaller dependency: `anchorReceiptTransparency` mutates
the receipt after signing, so `transparency`, `log_id` and `leaf_index` are
excluded from the envelope — matching the carve-out `contracts.ReceiptChainHash`
already makes for the same reason.

**Fourth test found asserting a vulnerability as intended behaviour:**
`TestDemoVerifyRejectsUnsignedEnvelopeMutation` requires `signature_valid ==
true` after mutating `Metadata` — i.e. it asserts that most of the receipt is
outside the signature. It is left as-is because the signer still emits v4;
it must be inverted in the same change that flips the signer.

### 2026-07-25 — F-10 and F-15

| ID | Finding | Status |
|---|---|---|
| F-10 | Inclusion proofs were verified against a root carried inside the same document | fixed |
| F-15 | Renovate auto-merged all minor+patch while Dependabot was disabled | fixed |

**F-10.** `VerifyInclusionProof` checked the audit path against
`proof.Binding.EntriesMerkleRoot`, a field inside the proof, with
`computeBindingHash` covering that root too — so every input came from the same
attacker-supplied document. An empty `merkle_path` makes the derived root equal
the leaf, so any entry could declare itself its own root and verify.

Added `VerifyInclusionProofAgainstRoot(proof, expectedRoot)`, which is the only
form that establishes membership: the caller supplies the root from the pack's
`00_INDEX.json`, a signed seal, or a transparency log. `VerifyInclusionProof` is
retained for internal-consistency checks, now rejects the degenerate empty-path
case, and its doc comment states plainly that a nil error does not mean the
entry belongs to any pack.

`helm-ai-kernel verify --entry --proof` gained `--entries-merkle-root`. Without
it the command no longer prints `VERIFIED`; it reports `self_attested` and
explains that the root was read from the proof itself.
`TestF10_ForgedProofIsInternallyConsistent` is the negative control — it proves
the forged fixture really does self-check, so the rejections above are firing for
the right reason.

**F-15.** `renovate.json` auto-merged every minor and patch update while
`.github/dependabot.yml` set `open-pull-requests-limit: 0` for all eight
ecosystems, making Renovate the only dependency path into the repo with no human
in the loop. Auto-merge is now limited to patch, TCB packages (x/crypto, x/net,
circl, filippo.io, cel-go, open-policy-agent) never auto-merge at any update
type, and vulnerability alerts are raised for review rather than merged.

### Remaining after this session

- **v5 activation** — blocked on the receipt-store schema. `ensureColumn` in
  `core/pkg/store/receipt_store_sqlite.go` is the additive-migration pattern to
  follow; five columns are needed (`key_id`, `public_key_set`,
  `signature_profile`, `signature_algorithm`, `correlation_id`) across both the
  SQLite and Postgres backends, in the schema, `receiptColumns`, the scan, and
  the insert. Then flip `SignReceipt` to `ReceiptPreimageV5` and invert
  `TestDemoVerifyRejectsUnsignedEnvelopeMutation`.
- **F-14 promotion** — triage the 14 `make lint-security` findings (several are
  gosec false positives) and make the target blocking in CI.
- **F-20** — self-declared receipt `hash` values have no specified preimage.
- **F-21** — launchpad and conform packs emit receipts with no `prev_hash`.
- **Live black-box pentest** against a `0.0.0.0` instance.
- **Enterprise** — bump `tools/helm-ai-kernel.lock` past the kernel security
  branch once it merges, then `make sync-oss-kernel && make verify-boundary`.

Flaky under full-suite load, unrelated to these changes: `TestLivenessAutoExpiry`
(`pkg/governance`) and `TestDockerRunnerValidateAndRun` (`pkg/sandbox/docker`).
Both pass in isolation.
