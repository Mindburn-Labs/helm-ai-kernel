# Task Capability Tokens (R4)

**Status:** preview specification. Schema merged
(`capability/capability_token.v1.json`); mint/verify wiring is follow-up.
**Origin:** Step AOS 可控 ("权限按需授予、用完即收" — granted on demand,
revoked when the task ends), formalized as a verifiable credential.

## Problem

Standing privileges are the dominant failure mode of agent systems: an agent
granted broad access "for the session" keeps it through scope creep,
compromise, or drift. Step AOS's answer is dynamic least privilege with
auto-revoke — stated, not proven. HELM already has permit interlocks for
change control; this spec extends the same discipline to **runtime
per-capability grants**.

## Model

A capability token binds five things into one signed, offline-verifiable
artifact:

1. **task_id** — dispatch under any other task fails closed;
2. **capability_ref** — exact manifest revision by `sha256` (manifest drift
   invalidates the token);
3. **subject** — agent (+ optional session/device) identity;
4. **grant window** — `issued_at` → `expires_at`, optional `max_uses`,
   optional `args_digest` (exact-argument grant) and
   `data_boundary_ceiling`;
5. **status** — `active` / `used_up` / `expired` / `revoked`; all terminal
   states refuse dispatch and write a refusal receipt.

Recommended defaults: TTL = min(task end, 15 minutes); single-use for
`financial` and `credential_access` effect classes; no tokens at all for
`irreversible` effects on protected targets (those stay DENY/permit-only).

## Lifecycle

```text
mint (permit flow or policy-automatic for low-risk classes)
  → dispatch checks: signature, task binding, manifest hash, expiry,
    use count, constraints
  → task end / scope violation / emergency stop
  → revoke → revocation receipt (who, when, why)
```

Revocation is itself a receipted effect — "用完即收" with a paper trail.

## Relationship to existing surfaces

- Permit artifacts (`approval_artifact`, multi-party permits) authorize the
  *mint*; the token authorizes individual *dispatches*.
- Emergency stop revokes all outstanding tokens for the fenced subject.
- Tokens compose with, never replace, guardian decisions: a valid token for a
  DENY-class effect still gets DENY.
