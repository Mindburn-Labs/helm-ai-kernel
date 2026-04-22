# HELM RFC: Authority Court Protocol

| Field        | Value                         |
|-------------|-------------------------------|
| RFC          | HELM-RFC-0001                 |
| Status       | Draft                         |
| Version      | 1.0.0-alpha.1                 |
| Authors      | HELM Core                     |
| Created      | 2026-02-22                    |
| Canonical    | `specs/authority-court/`      |

## Abstract

Authority Court is a **protocol**, not a feature. It defines the deterministic, versioned,
external-facing contract through which any agent execution request is evaluated, authorized,
and committed. Every tool invocation passes through Authority Court before producing any effect.

## Motivation

Without a protocol, policy enforcement degrades into an internal "security layer" — opaque,
non-reproducible, and untestable by third parties. Authority Court makes HELM's execution
governance a **standard** that can be independently verified, audited, and replayed.

### Design Principles

1. **Protocol over feature** — hard schemas, versioned, external.
2. **Deterministic evaluation** — same inputs → same DecisionRecord, byte-for-byte.
3. **Fail-closed** — any evaluation error results in DENY.
4. **Signed and replayable** — every decision produces a DecisionRecord that can reconstruct the evaluation.
5. **Two-phase for irreversible** — effects classified as irreversible require preflight+commit.

## Protocol Messages

### AuthorizationRequest v1

The agent (or orchestrator) emits:

```
Intent + ToolCallDraft → AuthorizationRequest
```

Required fields:

| Field                | Type     | Description |
|---------------------|----------|-------------|
| `request_id`        | UUID     | Unique request identifier |
| `intent`            | Object   | Structured intent (type + goal) |
| `tool_call_draft`   | Object   | Tool ID + args hash + schema pin |
| `effects`           | string[] | Declared effect types from taxonomy |
| `context_capsules`  | Capsule[]| Authenticated memory/context capsules |
| `risk_profile_ref`  | string   | Reference to risk profile |
| `policy_epoch`      | string   | Policy version binding |
| `idempotency_key`   | string   | Client-provided dedup key |
| `timestamp`         | datetime | Request creation time |

See: [authorization_request.v1.schema.json](authorization_request.v1.schema.json)

### AuthorizationDecision v1

The Authority Court returns:

| Field                | Type     | Description |
|---------------------|----------|-------------|
| `decision_id`       | UUID     | Unique decision identifier |
| `request_id`        | UUID     | Binds to the originating request |
| `result`            | enum     | ALLOW / DENY / REQUIRE_APPROVAL / REQUIRE_EVIDENCE / DEFER |
| `reason_codes`      | string[] | Machine-readable reason codes |
| `ceilings_snapshot` | Object   | Budget, rate, scope ceilings at decision time |
| `commit_token`      | Object   | If ALLOW: token bound to draft+ceilings+epoch+TTL |
| `policy_epoch`      | string   | Policy version used |
| `evaluation_trace`  | Object   | Hash of evaluation DAG + rules fired |
| `issued_at`         | datetime | Authority time of decision |
| `expires_at`        | datetime | Decision TTL |

See: [authorization_decision.v1.schema.json](authorization_decision.v1.schema.json)

### DecisionRecord v1

Canonical, signed, replayable artifact:

| Field                      | Type     | Description |
|---------------------------|----------|-------------|
| `version`                 | string   | `DR.v1` |
| `policy_epoch`            | string   | Policy version |
| `intent`                  | Object   | Intent type + goal |
| `tool_call_draft`         | Object   | Tool + args_hash |
| `effects`                 | string[] | Declared effects |
| `counterfactuals_checked` | string[] | Mandatory checks performed |
| `invariants_passed`       | string[] | Tool-specific validations |
| `ceilings_snapshot`       | Object   | Budget/rate/scope ceilings |
| `context_capsules`        | Capsule[]| Used memory capsules |
| `decision`                | Object   | Result + reason_codes |
| `commit_token_hash`       | string   | SHA-256 of commit token |
| `signatures`              | Object   | policy_root_sig + authority_sig |

See: [../decision-record/decision_record.v1.schema.json](../decision-record/decision_record.v1.schema.json)

## Evaluation Pipeline

The Authority Court runs a **deterministic evaluation pipeline** in strict order:

```
┌─────────────────────────────────────────────────────────────┐
│                    AuthorizationRequest                      │
└──────────┬──────────────────────────────────────────────────┘
           │
           ▼
┌──────────────────────┐
│ 1. Contract Pinning  │  Schema pins match? Drift detected?
│    + Drift Checks    │  → DENY if schemas drifted since last eval
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 2. Ceiling Checks    │  P0 budgets, rights, rate limits, scope
│                      │  → DENY if any ceiling exceeded
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 3. Counterfactual    │  Mandatory minimum set per effect class
│    Set               │  e.g. rollback_plan_exists, blast_radius_under_ceiling
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 4. Invariant Checks  │  Tool-specific validators
│                      │  e.g. schema_pinned, idempotency_key_present
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 5. Preflight Sim     │  If risk class requires (E3/E4 effects)
│    (optional)        │  Dry-run, balance checks, blast radius estimate
└──────────┬───────────┘
           ▼
┌──────────────────────────────────────────────────────────────┐
│ OUTPUT: AuthorizationDecision + CommitToken (if ALLOW)        │
│         DecisionRecord (always, signed)                       │
└──────────────────────────────────────────────────────────────┘
```

## CommitToken Semantics

The CommitToken is the **only artifact** that authorizes tool execution.

- Bound to: `tool_call_draft_hash + ceilings_snapshot_hash + policy_epoch + TTL`
- Single-use: once consumed, cannot be replayed
- Time-bound: `expires_at` enforced by authority clock (not wall clock)
- The tool executor MUST validate the CommitToken before any effect

### Two-Phase Commit (irreversible effects)

For effects classified as `irreversible`:

1. **Preflight**: `Preflight(CommitToken)` → `EffectEstimate` (cost, blast radius, side-effects)
2. **Commit**: `Commit(CommitToken)` → executes, generates Receipt + EvidencePack
3. **Without** valid CommitToken → execution MUST be rejected

This eliminates: replay attacks, race conditions, drift between intent and execution,
"agent changed its mind" after preflight.

## Reason Codes

Standard reason codes for decisions:

| Code | Meaning |
|------|---------|
| `OK_POLICY` | Policy evaluation passed |
| `OK_PREFLIGHT` | Preflight simulation passed |
| `OK_CEILINGS` | All ceilings within bounds |
| `DENY_SCHEMA_DRIFT` | Tool schema pin mismatch |
| `DENY_CEILING_EXCEEDED` | Budget/rate/scope ceiling exceeded |
| `DENY_COUNTERFACTUAL_FAIL` | Required counterfactual not satisfied |
| `DENY_INVARIANT_FAIL` | Tool-specific invariant violated |
| `DENY_PREFLIGHT_FAIL` | Preflight simulation failed |
| `DENY_UNAUTHENTICATED_MEMORY` | Context capsule provenance invalid |
| `DENY_POLICY_EPOCH_EXPIRED` | Policy epoch no longer valid |
| `DENY_EFFECT_NOT_TYPED` | Tool missing effect type descriptors |
| `REQUIRE_APPROVAL` | Human approval required |
| `REQUIRE_EVIDENCE` | Additional evidence required |

## Canonicalization

All protocol messages MUST be canonicalized using JCS (RFC 8785) before hashing or signing.
DecisionRecords are deterministic: same inputs → same canonical bytes → same hash.

## Versioning

Protocol messages are independently versioned: `AuthorizationRequest.v1`,
`AuthorizationDecision.v1`, `DecisionRecord.v1`. Breaking changes increment the major version.
Non-breaking additions use minor version bumps.
