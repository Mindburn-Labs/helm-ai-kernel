# HELM Conformance Guide

> How to prove a HELM-compatible implementation is conformant.

## 1. Conformance Levels

These are the **spec levels** an implementation claims. They are the values
recorded as `conformance_level` in `compatibility-registry.json` and referenced
by the compatibility tiers in §8.

| Level                   | Requirement                                      |
| ----------------------- | ------------------------------------------------ |
| **Level 1: Core**       | Pass all ALLOW/DENY/ESCALATE verdict vectors     |
| **Level 2: Receipts**   | Generate receipts matching receipt invariants    |
| **Level 3: ProofGraph** | Maintain hash chain with monotonic Lamport clock |
| **Level 4: Full**       | All above + fail-closed behavior + reason codes  |

> **Do not confuse these with the CLI's `--level` flag.** `helm-ai-kernel
> conform --level` is a *gate-set shortcut* over the Go reference's own
> conformance gates and accepts only `L1` and `L2` — see §3.1. Passing
> `--level 4` exits 2 with `unknown level "4" (valid: L1, L2)`. The two
> numbering schemes are unrelated; there is no CLI flag that asserts a spec
> level from this table.

## 2. Test Vector Structure

Test vectors are in `protocols/conformance/v1/test-vectors.json`.

Each vector specifies:

- `input`: Effect, principal, and context to submit
- `expected`: Verdict, reason code, receipt presence, intent presence
- `pdp_behavior` (optional): How the PDP should respond for this test

## 3. Running Conformance Tests

### 3.1 Against the Go Reference

Unit-level gate tests:

```bash
cd core && go test ./pkg/conform/... -tags conformance
```

The gate runner is the `conform` subcommand of the kernel binary. Build it
first — a `helm-ai-kernel` already on `PATH` may be an older release:

```bash
make build   # writes ./bin/helm-ai-kernel
```

`conform` has three subcommands and, with none of them, runs the gate engine:

| Invocation                      | Behaviour                                                             |
| ------------------------------- | --------------------------------------------------------------------- |
| `conform [flags]`               | Runs the conformance gate engine over the current working tree        |
| `conform vectors [--json]`      | Prints the built-in negative execution-boundary vectors               |
| `conform negative [--json]`     | Same vectors, with receipt/dispatch expectations                      |
| `conform managed-agents ...`    | Managed-agent live evidence packs (see `conform_managed_agents.go`)   |

There is **no `conform run` subcommand**. `run` is parsed as a positional
argument, which stops Go flag parsing — every flag after it is silently
ignored and the command exits 2.

Flags accepted by `conform` (source: `core/cmd/helm-ai-kernel/conform.go`):

| Flag                    | Meaning                                                                     |
| ----------------------- | --------------------------------------------------------------------------- |
| `--profile`             | `SMB`, `CORE`, `ENTERPRISE`, `REGULATED_FINANCE`, `REGULATED_HEALTH`, `AGENTIC_WEB_ROUTER` |
| `--level`               | Gate-set shortcut, `L1` or `L2` only — **not** the §1 spec levels            |
| `--gate`                | Run only the named gate(s); repeatable                                      |
| `--jurisdiction`        | Jurisdiction code (e.g. `US`, `EU`, `APAC`)                                 |
| `--output`              | EvidencePack output directory (default `artifacts/conformance`)             |
| `--json`                | Emit the report as JSON on stdout                                           |
| `--signed`              | Also write `conform_report.json` + `.sha256` + `.sig`                       |
| `--vector`              | Run one **external-failure** vector JSON (schema below)                     |
| `--validation-manifest` | Write the signed external-failure HCV validation manifest                   |
| `--evidencepack`        | EvidencePack bound into that manifest (required with `--validation-manifest`) |
| `--kernel-commit`       | Kernel commit SHA recorded in that manifest                                 |

Either `--profile` or `--level` is required. Exit codes: `0` all gates pass,
`1` a gate failed, `2` runtime or usage error.

The invocation the release gate itself uses (`make conformance-release-report`):

```bash
./bin/helm-ai-kernel conform \
  --profile SMB \
  --gate G0 \
  --signed \
  --output artifacts/conformance
```

`--vector` loads a single external-failure vector, which is a **different
schema** from `test-vectors.json` — it is one object, not a suite, with the
fields `id`, `vector_id`, `hpr_id`, `failure_mode`, `expected_verdict`,
`expected_reason_code`, `must_emit_receipt`, `must_not_dispatch`,
`must_bind_evidence`, `expected` (`verdict`, `reason_code`,
`receipt_required`, `evidencepack_required`) and `negative_assertions`.

### 3.2 Against an External Implementation

> **Status: not implemented — target.** No shipped command drives
> `test-vectors.json` against a remote PDP/EffectBoundary. The kernel CLI has
> no `--vectors` and no `--endpoint` flag on `conform`, and no code in this
> repository reads `protocols/conformance/v1/test-vectors.json` — it is a
> data-only fixture published for implementers.

Until an endpoint-driven runner ships, external implementations self-certify:
load `test-vectors.json` in your own harness, submit each vector's `input` to
your PDP/EffectBoundary, and assert its `expected` block plus the invariants in
§4–§6. Publish the result per §8.2.

The reference behaviour your harness must reproduce for the fail-closed cases
is printed by the kernel and needs no server:

```bash
./bin/helm-ai-kernel conform negative --json
```

### 3.3 Against a Language SDK

The SDKs do not ship separate conformance suites; their contract tests run
through the root `Makefile`:

```bash
make test-sdk-py             # sdk/python — pytest
make test-sdk-ts             # sdk/ts     — vitest + tsc build
make test-sdk-java           # sdk/java   — mvn test
make test-sdk-rust           # sdk/rust   — cargo test
make test-sdk-go-standalone  # sdk/go     — go test ./... with GOWORK=off
```

Generated-code drift against `protocols/` is a separate gate:

```bash
make sdk-gen-check
make sdk-manifest-verify
```

## 4. Receipt Invariants

Every receipt produced by a conformant implementation MUST satisfy:

1. `receipt_id` is non-empty and unique
2. `verdict` matches the returned verdict
3. `timestamp` is monotonically increasing within a session
4. `signature` is verifiable with the signer's public key
5. `payload_hash` is SHA-256 of the canonical (JCS) JSON payload
6. `reason_code` is a registered code from `reason-codes-v1.json`
7. `lamport` is strictly increasing within a ProofGraph

## 5. Hash Chain Invariants

1. Each node hash includes the hashes of parent nodes
2. Lamport values are strictly increasing
3. Removing any node breaks chain verification
4. Node hashes are computed using JCS (JSON Canonicalization Scheme)

## 6. Fail-Closed Invariant

If the PDP is unreachable:

- The EffectBoundary MUST return `DENY`
- Reason code MUST be `PDP_ERROR`
- A receipt MUST still be generated

This is the **non-negotiable kernel invariant**.

## 7. Certification Badge

Implementations passing Level 4 conformance may display:

```
[![HELM Conformant](https://helm.mindburn.run/badges/conformant-v1.svg)](https://helm.mindburn.run/conformance)
```

## 8. Compatibility Tiers

Beyond conformance levels, HELM defines **compatibility tiers** for ecosystem
participants (runtimes, frameworks, clients):

| Tier           | Requirements                                                                     | Verification                                                                       |
| -------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Compatible** | Passes core verdict vectors (Level 1–2). Self-certified.                         | Self-reported; not independently verified.                                         |
| **Verified**   | Passes all Level 4 conformance vectors against published fixtures. CI-exercised. | Verified via published CI workflow. Artifacts published to compatibility registry. |
| **Sovereign**  | Verified + full TLA+ invariant alignment + independent verifier passes.          | Third-party audit confirms invariant coverage. Eligible for HELM Sovereign badge.  |

### 8.1 Required Fixture Sets by Tier

| Fixture Set                     | Compatible | Verified | Sovereign |
| ------------------------------- | ---------- | -------- | --------- |
| `vectors` (ALLOW/DENY/ESCALATE) | ✅         | ✅       | ✅        |
| `receipt_invariants`            | —          | ✅       | ✅        |
| `hash_chain_vectors`            | —          | ✅       | ✅        |
| `golden_receipts`               | —          | ✅       | ✅        |
| `lifecycle_fixtures`            | —          | ✅       | ✅        |
| `jurisdiction_fixtures`         | —          | —        | ✅        |
| `evidence_bundle_fixture`       | —          | —        | ✅        |

### 8.2 Claiming a Tier

1. Run conformance vectors against your implementation.
2. Publish results to `compatibility-registry.json` (or submit PR).
3. CI artifact must include: tier, date, HELM spec version, vector version, pass/fail summary.

## 9. Lifecycle Fixtures

Conformant implementations MUST handle the effect lifecycle state machine:

- **Happy path**: SUBMITTED → APPROVED → EXECUTING → COMPLETED
- **Deny path**: SUBMITTED → DENIED
- **Escalation path**: SUBMITTED → ESCALATED → APPROVED or DENIED

See `lifecycle_fixtures` in `test-vectors.json` for exact transition definitions.
