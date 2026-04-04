# Automation Schedule Standard

**Version:** 1.0.0
**Status:** DRAFT
**Owner:** Mindburn Labs / HELM Core
**Last Updated:** 2026-04-04

---

## Abstract

This standard defines the canonical structure, dispatch semantics, and
validation rules for automation schedules within the HELM runtime. A
`ScheduleSpec` describes a recurring or one-shot trigger that, when fired,
creates a governed HELM Intent from a pre-registered `intent_template_id`.

All scheduling is fail-closed: a schedule that fires but cannot produce a
valid, policy-authorized Intent MUST be logged as a `SCHEDULE_DISPATCH_FAILURE`
and MUST NOT silently drop. Idempotency is guaranteed through a
deterministically derived `idempotency_key` on each `TriggerDecision`. Jitter
windows distribute load across the tenant's execution surface without
compromising the bounded scheduling contract.

---

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

| Term | Definition |
|---|---|
| **ScheduleSpec** | The canonical descriptor for a recurring automation trigger. |
| **TriggerDecision** | A computed dispatch record produced when a schedule fires. |
| **ScheduleKind** | The expression format of the schedule (`cron` or `rrule`). |
| **CatchupPolicy** | Controls behavior when missed fires are detected after downtime. |
| **RetryPolicy** | Describes how failed dispatches are retried. |
| **Idempotency Key** | A deterministic string that prevents duplicate dispatches for the same fire event. |
| **Jitter Window** | A randomized delay (up to `jitter_window_ms`) applied to each dispatch to spread load. |
| **Intent Template** | A pre-registered parameterized Intent structure that the schedule instantiates on fire. |
| **PolicyEpoch** | The versioned policy snapshot active at dispatch time. |
| **Max Concurrency** | The maximum number of simultaneously active Intents spawned by this schedule. |

---

## Wire Format

### ScheduleSpec

```json
{
  "schema": "https://helm.mindburn.org/schemas/schedules/schedule_spec.v1.json",
  "schedule_id": "sched_01HX9ZD2E3F4G5H6I7J8K9L0MN",
  "tenant_id": "tenant_acme_corp",
  "name": "Daily Executive Email Triage",
  "kind": "cron",
  "expression": "0 8 * * 1-5",
  "timezone": "America/New_York",
  "catchup_policy": "single",
  "max_concurrency": 1,
  "jitter_window_ms": 30000,
  "retry": {
    "max_attempts": 3,
    "backoff_mode": "exponential",
    "min_backoff_s": 30,
    "max_backoff_s": 300
  },
  "enabled": true,
  "intent_template_id": "intent-templates/exec-ops/email-triage-v2",
  "created_by": "principal_ops_manager",
  "created_at_unix_ms": 1743765000000,
  "last_modified_at_unix_ms": 1743765000000,
  "policy_hash": "sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
}
```

### Field Descriptions

| Field | Type | Constraints | Description |
|---|---|---|---|
| `schema` | string (URI) | REQUIRED | JSON Schema `$id`. |
| `schedule_id` | string | REQUIRED, globally unique | Stable identifier. Format: `sched_{ULID}`. |
| `tenant_id` | string | REQUIRED | Owning HELM tenant. |
| `name` | string | REQUIRED, 1–256 chars | Human-readable schedule name. |
| `kind` | ScheduleKind | REQUIRED | Expression format (`cron` or `rrule`). |
| `expression` | string | REQUIRED | The schedule expression. MUST be a valid cron-5 or RFC 5545 RRULE string. |
| `timezone` | string | REQUIRED | IANA timezone name (e.g., `America/New_York`, `UTC`). |
| `catchup_policy` | CatchupPolicy | REQUIRED | Behavior for missed fire events. |
| `max_concurrency` | integer | REQUIRED, ≥ 1 | Maximum simultaneously active dispatched Intents. |
| `jitter_window_ms` | integer | OPTIONAL, 0–300000 | Maximum random delay added to each dispatch. Default: 0. |
| `retry` | RetryPolicy | REQUIRED | Retry configuration for failed dispatches. |
| `enabled` | bool | REQUIRED | If `false`, the schedule MUST NOT fire. |
| `intent_template_id` | string | REQUIRED | Reference to the Intent template instantiated on fire. |
| `created_by` | string | REQUIRED | HELM principal that created this schedule. |
| `created_at_unix_ms` | integer | REQUIRED | Unix millisecond creation timestamp. |
| `last_modified_at_unix_ms` | integer | REQUIRED | Unix millisecond last-modified timestamp. |
| `policy_hash` | string | REQUIRED, format `sha256:{hex}` | Active policy hash at the time of schedule creation or last modification. |

### ScheduleKind Enum

| Value | Format | Example |
|---|---|---|
| `cron` | 5-field cron (`min hour dom month dow`) | `0 8 * * 1-5` = weekdays at 08:00 |
| `rrule` | RFC 5545 RRULE | `FREQ=WEEKLY;BYDAY=MO,WE,FR;BYHOUR=9;BYMINUTE=0` |

### CatchupPolicy Enum

| Value | Behavior |
|---|---|
| `none` | Missed fires are silently skipped. No catch-up dispatch. |
| `single` | At most one catch-up dispatch is issued for all missed fires since the last successful run. |
| `backfill` | One dispatch is issued for each missed fire in order. Bounded by `policy.max_catchup_fires`. |

### RetryPolicy

| Field | Type | Constraints | Description |
|---|---|---|---|
| `max_attempts` | integer | REQUIRED, 1–10 | Maximum dispatch attempts per fire event including the first. |
| `backoff_mode` | string | REQUIRED, enum `exponential`/`linear`/`fixed` | Delay growth function between attempts. |
| `min_backoff_s` | integer | REQUIRED, ≥ 1 | Minimum delay in seconds before the first retry. |
| `max_backoff_s` | integer | REQUIRED, ≥ `min_backoff_s` | Maximum delay cap in seconds. |

---

## Validation Rules

1. **MUST** — `expression` MUST be validated against the declared `kind`
   parser before the schedule is stored. Invalid expressions MUST be rejected
   at creation time with a descriptive `INVALID_SCHEDULE_EXPRESSION` error.

2. **MUST** — `timezone` MUST be a valid IANA timezone string. The scheduler
   MUST use the IANA tzdata at dispatch time (not at creation time) to correctly
   handle DST transitions.

3. **MUST** — `intent_template_id` MUST resolve to an existing, active Intent
   template at schedule creation time. Schedules that reference deleted templates
   MUST be automatically disabled and MUST emit a `TEMPLATE_NOT_FOUND` alert.

4. **MUST** — `max_concurrency` MUST be enforced. When the active Intent count
   for a schedule reaches `max_concurrency`, the next fire event MUST be skipped
   (not queued) and logged as `CONCURRENCY_LIMIT_REACHED`.

5. **MUST** — The `idempotency_key` for each `TriggerDecision` MUST be derived
   as `sha256({schedule_id}:{fire_at_unix_ms})`. Dispatchers MUST check for an
   existing non-failed Intent with the same `idempotency_key` before creating a
   new one.

6. **MUST** — `policy_hash` MUST be refreshed whenever the schedule is modified.
   Schedules whose `policy_hash` is older than the current `PolicyEpoch` by more
   than `policy.stale_schedule_ttl_ms` MUST be automatically disabled and flagged
   for review.

7. **SHOULD** — `jitter_window_ms` SHOULD be set to at least
   `ceil(expected_dispatch_duration_ms / 2)` for schedules that share an Intent
   template with other schedules, to avoid thundering herd.

8. **MUST** — Disabled schedules (`enabled: false`) MUST NOT fire. The scheduler
   MUST check `enabled` at fire time, not only at load time, to respect
   real-time disables.

9. **MUST** — `backfill` catch-up dispatches MUST be bounded by
   `policy.max_catchup_fires`. Exceeding the limit MUST emit a
   `CATCHUP_LIMIT_EXCEEDED` event and stop backfilling.

10. **MUST** — All schedule mutations (create, update, enable/disable, delete)
    MUST produce a `ScheduleMutationEvent` recorded in the ProofGraph with the
    `created_by` principal and the new `policy_hash`.

---

## TriggerDecision

When the scheduler determines that a schedule should fire, it produces a
`TriggerDecision` record before dispatching:

```json
{
  "schema": "https://helm.mindburn.org/schemas/schedules/trigger_decision.v1.json",
  "decision_id": "tdec_01HX9ZE2F3G4H5I6J7K8L9M0NO",
  "schedule_id": "sched_01HX9ZD2E3F4G5H6I7J8K9L0MN",
  "fire_at_unix_ms": 1743793200000,
  "dispatch_after_ms": 14237,
  "idempotency_key": "sha256:8f3a1b2c...",
  "reason": "scheduled_fire",
  "attempt": 1,
  "max_attempts": 3,
  "created_at_unix_ms": 1743793199500
}
```

### TriggerDecision Fields

| Field | Type | Description |
|---|---|---|
| `decision_id` | string | Unique ID for this dispatch attempt. |
| `schedule_id` | string | Parent `ScheduleSpec` ID. |
| `fire_at_unix_ms` | integer | Nominal fire time (before jitter). |
| `dispatch_after_ms` | integer | Actual jitter delay applied. |
| `idempotency_key` | string | Deduplication key (see rule 5). |
| `reason` | string | `scheduled_fire`, `catchup_single`, `catchup_backfill`, or `retry`. |
| `attempt` | integer | Current attempt number (1-based). |
| `max_attempts` | integer | Max attempts from `RetryPolicy`. |
| `created_at_unix_ms` | integer | Timestamp of decision creation. |

---

## Dispatch Lifecycle

```
[schedule clock fires]
         │
         ▼
  [idempotency check]
         │
   (duplicate?)──yes──▶ skip, log DUPLICATE_DISPATCH
         │ no
         ▼
  [concurrency check]
         │
   (at limit?)──yes──▶ skip, log CONCURRENCY_LIMIT_REACHED
         │ no
         ▼
  [apply jitter delay]
         │
         ▼
  [instantiate Intent from template]
         │
   (template missing?)──yes──▶ disable schedule, log TEMPLATE_NOT_FOUND
         │ no
         ▼
  [PEP evaluation]
         │
   (denied?)──yes──▶ log DISPATCH_POLICY_DENIED, retry per RetryPolicy
         │ no
         ▼
  [Intent created, TriggerDecision recorded in ProofGraph]
```

---

## Versioning Policy

- `ScheduleSpec` and `TriggerDecision` schemas are versioned per ADR-006.
- The `expression` format for each `ScheduleKind` is frozen in v1. New
  expression formats require a new `kind` enum value in a future version.
- Existing schedules created under v1 MUST continue to function after a schema
  upgrade until explicitly migrated.

---

## Security Considerations

- **Policy staleness.** Schedules that were created under a long-superseded
  policy MUST be reviewed before they continue firing. The `policy_hash` field
  provides the audit anchor.

- **Idempotency key derivation.** The idempotency key MUST be computed by the
  scheduler, not supplied externally, to prevent adversarial key injection that
  could cause legitimate dispatches to be skipped.

- **Catchup backfill limits.** Unbounded backfill could flood the execution
  surface after a long outage. The `max_catchup_fires` ceiling is a required
  safety brake.

- **Template authority.** Intent templates are governance artifacts. Modification
  of a template referenced by an active schedule MUST trigger a policy review
  notification to the schedule owner.

---

## References

- ADR-001: HELM Is Execution Authority, Not Assistant Shell
- ADR-005: R0-R3 Action Risk Class Taxonomy
- ADR-006: Schema Namespace Organization
- pack-definition-v1.md (this standard set) — schedules are pack-composable
- GOVERNANCE_SPEC.md
- EXECUTION_SECURITY_MODEL.md
