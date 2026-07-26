# Reversibility-Aware Policy Classes (R3)

**Status:** preview. Schema merged (`capability/rollback_plan.v1.json`).
Chunk 3 implemented in `core/pkg/capability` (plan loader with registry
cross-validation of step actions, hash pinning, guarantee-expiry handling)
and enforced in the guardian (`WithRollbackPlanStore`; reversible
non-read-only dispatches bind a valid unexpired plan or DENY with
`CAPABILITY_ROLLBACK_PLAN_INVALID`; reversible-external and irreversible
external reach ESCALATE to the permit flow; irreversible effect class DENYs
without an approval artifact). Rollback *execution* and outcome verification
(receipt pairing / state-digest match) are follow-up work.
**Origin:** Step AOS alignment (their 可逆 "one-click rollback"), adapted to
fail-closed enforcement instead of a UX promise.

## Principle

Step AOS advertises reversibility as a user-facing comfort feature
("误操作一键回滚"). HELM treats reversibility as a **policy input with
machine-checkable evidence**: an action's reversibility class determines what
must exist *before* dispatch, and rollback success is proven by receipts, not
asserted.

## Classes

The existing `effect_type_definition/v2` reversibility enum is kept as the
base vocabulary. Policy classes compose it with effect reach:

| Class | Definition | Dispatch requirement |
| --- | --- | --- |
| `reversible-local` | `exact_undo` or `compensating_action`, effect confined to `local_only` / `device_boundary` | ALLOW may proceed with a bound rollback plan (`rollback_plan.v1`) recorded in the decision receipt |
| `reversible-external` | `exact_undo` or `compensating_action`, effect reaches `org_boundary` or `external` | ESCALATE by default; ALLOW only with rollback plan + `single_approval` minimum |
| `irreversible` | `none` (any boundary) | DENY for protected targets; otherwise ESCALATE to permit flow. **No rollback promise may be made** |

## Rules

1. **No plan, no dispatch.** A capability whose `reversibility` is
   `compensating_action` or `exact_undo` and whose `effect_class` is not
   `read_only` must carry `rollback.plan_ref` in its manifest. The guardian
   refuses registration and dispatch otherwise (fail closed).
2. **Rollback steps are capabilities.** Every step in a rollback plan
   references a certified `capability_id`; compensating actions pass through
   the same boundary as forward actions and produce paired receipts.
3. **Verification is evidence.** `rollback_plan.v1.verification.method`:
   - `receipt_pairing` — compensating receipt references the original receipt id;
   - `state_digest_match` — post-rollback state digest equals the pre-effect
     digest in the original receipt (strongest; preferred for local state);
   - `human_attestation` — signed human confirmation; weakest, allowed only
     where no machine check exists.
4. **Guarantee expiry.** Rollback plans may declare `guarantee_expiry`. After
   expiry the effect is treated as `irreversible` for policy purposes.
5. **Emergency stop supersedes.** Rollback execution never bypasses
   `EMERGENCY_STOP_FENCE`; a stopped subject rolls back only through the
   fenced path.

## Conformance vectors

Covered together with adversarial cases in
`reference_packs/adversarial-policy-v1/vectors.json` (category
`rollback-after-irreversible`, `rollback-plan-missing`).
