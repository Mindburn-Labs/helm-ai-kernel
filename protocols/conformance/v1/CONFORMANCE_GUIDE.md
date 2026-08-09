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
> conform --level` is a gate-set shortcut over the Go reference's own
> conformance gates and accepts only `L1` and `L2` — see §3.1. `--level 4`
> exits 2 with `unknown level "4" (valid: L1, L2)`. The two numbering schemes
> are unrelated, and no CLI flag asserts a spec level from the table above.

## 2. Test Vector Structure

Test vectors are in `protocols/conformance/v1/test-vectors.json`
(`test_suite: helm-conformance-v1`, `version: 1.1.0`, 61 vectors).

No code in this repository reads this file — there is no loader, and no build
or test gate consumes it. It is a data-only fixture published for implementers,
and its schema is defined by the JSON itself rather than by a Go struct.

Every vector carries:

- `id`: Stable vector identifier (e.g. `ALLOW-001`)
- `description`: Human-readable statement of what the vector proves
- `input`: Effect, principal, and context to submit
- `expected`: Assertions on the result — most commonly `verdict`,
  `reason_code`, `receipt_present`, `intent_present`, and `active_packs`.
  Multi-effect vectors instead use plural forms (`verdicts`, `receipts_present`,
  `reason_codes`) plus chain assertions such as
  `lamport_strictly_increasing`, `proofgraph_hash_matches`, and `replay_fails`.

Some vectors add an optional driver key:

- `pdp_behavior` (3 vectors): How the PDP should respond for this test
- `budget_behavior` (1 vector): Budget state the harness must establish
- `output_override` (1 vector): Output the harness must substitute

Beyond `vectors`, the file carries the fixture sets required by §8.1:
`receipt_invariants`, `hash_chain_vectors`, `golden_receipts`,
`lifecycle_fixtures`, `jurisdiction_fixtures`, and `evidence_bundle_fixture`.

## 3. Running Conformance Tests

### 3.1 Against the Go Reference

Unit-level gate tests:

```bash
cd core && go test ./pkg/conform/... -tags conformance
```

The gate runner is the `conform` subcommand of the kernel binary. Build it
first — a `helm-ai-kernel` already on `PATH` may be an older release, and its
flags will not match this guide:

```bash
make build   # writes ./bin/helm-ai-kernel
```

`conform` dispatches on three positional subcommands; with none of them, it
runs the gate engine over the current working tree.

| Invocation                    | Behaviour                                                            |
| ----------------------------- | -------------------------------------------------------------------- |
| `conform [flags]`             | Runs the conformance gate engine over the current working tree       |
| `conform vectors [--json]`    | Prints the built-in negative execution-boundary vectors              |
| `conform negative [--json]`   | The same vectors, with receipt and dispatch expectations             |
| `conform managed-agents …`    | Managed-agent live evidence packs                                    |

There is **no `conform run` subcommand**. Because Go's flag package stops at
the first non-flag argument, `run` is taken as a positional, every flag after
it is ignored, and the command exits 2 with
`Error: --profile or --level is required`.

Flags accepted by `conform` (source: `core/cmd/helm-ai-kernel/conform.go`):

| Flag                    | Meaning                                                                                    |
| ----------------------- | ------------------------------------------------------------------------------------------ |
| `--profile`             | `SMB`, `CORE`, `ENTERPRISE`, `REGULATED_FINANCE`, `REGULATED_HEALTH`, `AGENTIC_WEB_ROUTER` |
| `--level`               | Gate-set shortcut, `L1` or `L2` only — **not** the §1 spec levels                          |
| `--gate`                | Run only the named gate(s); repeatable                                                     |
| `--jurisdiction`        | Jurisdiction code (e.g. `US`, `EU`, `APAC`)                                                |
| `--output`              | EvidencePack output directory (default `artifacts/conformance`)                            |
| `--json`                | Emit the report as JSON on stdout                                                          |
| `--signed`              | Also write `conform_report.json` + `.sha256` + `.sig`                                      |
| `--vector`              | Run one **external-failure** vector JSON (singular; see below)                              |
| `--validation-manifest` | Write the signed external-failure HCV validation manifest                                  |
| `--evidencepack`        | EvidencePack bound into that manifest (required with `--validation-manifest`)               |
| `--kernel-commit`       | Kernel commit SHA recorded in that manifest                                                |

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

`--vector` is **not** a way to run `test-vectors.json`. It loads a single
external-failure vector, which is a different schema: one object, not a suite,
with the fields `id`, `vector_id`, `hpr_id`, `failure_mode`, `expected_verdict`,
`expected_reason_code`, `must_emit_receipt`, `must_not_dispatch`,
`must_bind_evidence`, `expected` (`verdict`, `reason_code`, `receipt_required`,
`evidencepack_required`), and `negative_assertions`.

### 3.2 Against an External Implementation

> **Status: not implemented — target.** No shipped command drives
> `test-vectors.json` against a remote PDP/EffectBoundary. `conform` has no
> `--vectors` and no `--endpoint` flag — both are rejected with
> `flag provided but not defined` — and nothing in this repository reads
> `test-vectors.json`. An endpoint-driven runner remains the intended design;
> until it ships, the procedure below is the conformance path.

External implementations self-certify: load `test-vectors.json` in your own
harness, submit each vector's `input` to your PDP/EffectBoundary, and assert its
`expected` block plus the invariants in §4–§6. Publish the result per §8.2.

The reference behaviour your harness must reproduce for the fail-closed cases
is printed by the kernel itself and needs no server:

```bash
./bin/helm-ai-kernel conform negative --json
```

### 3.3 Against a Language SDK

The SDKs do not ship separate conformance suites. Their contract tests run
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
