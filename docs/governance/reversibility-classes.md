# Reversibility-Aware Policy Classes (R3)

**Status:** core Guardian enforcement is implemented: validated rollback plans
are bound before dispatch for reversible capabilities, invalid or expired
plans deny, and external paths escalate. Rollback execution, outcome-receipt
pairing, and authoritative approval-receipt verification remain follow-up.
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
| `reversible-local` | `exact_undo` or `compensating_action`, effect confined to `local_only` / `device_boundary` | ALLOW may proceed only after a valid, capability-bound `rollback_plan.v1` is recorded in the decision context |
| `reversible-external` | `exact_undo` or `compensating_action`, effect reaches `org_boundary` or `external` | ESCALATE after valid plan binding. The current core does not accept a raw caller-supplied approval as authority to ALLOW. |
| `irreversible-effect` | `effect_class=irreversible` | DENY in the current core. **No rollback promise may be made.** |
| `non-reversible` | `reversibility=none` with another effect class | ESCALATE to the permit flow; approval-receipt verification is follow-up. |

## Rules

1. **No plan, no dispatch.** A capability whose `reversibility` is
   `compensating_action` or `exact_undo` and whose `effect_class` is not
   `read_only` must carry `rollback.plan_ref` in its manifest. The guardian
   refuses registration and dispatch otherwise (fail closed).
2. **Rollback steps are capabilities.** The current plan registry validates a
   plan's target capability binding. Certification of every execution step,
   execution through the forward boundary, and paired receipts are follow-up.
3. **Verification is evidence.** `rollback_plan.v1.verification.method` is
   required plan metadata; actual outcome verification is follow-up:
   - `receipt_pairing` — compensating receipt references the original receipt id;
   - `state_digest_match` — post-rollback state digest equals the pre-effect
     digest in the original receipt (strongest; preferred for local state);
   - `human_attestation` — signed human confirmation; weakest, allowed only
     where no machine check exists.
4. **Guarantee expiry.** Rollback plans may declare `guarantee_expiry`. The
   current Guardian denies dispatch when a required plan is expired.
5. **Emergency stop supersedes.** Rollback execution never bypasses
   `EMERGENCY_STOP_FENCE`; a stopped subject rolls back only through the
   fenced path.

## Conformance vectors

Covered together with adversarial cases in
`reference_packs/adversarial-policy-v1/vectors.json` (category
`rollback-after-irreversible`, `rollback-plan-missing`).
