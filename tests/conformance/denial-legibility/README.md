# Denial legibility

Conformance scenario for denials that carry what a consuming agent needs in
order to learn from them.

A fail-closed boundary that only ever says "no" teaches an agent nothing: the
agent that exceeded a TTL ceiling by sixty days and the agent that touched a
forbidden host receive the same answer and retry at random. This scenario pins
down the two fields that make the difference, and the limits on both.

## Contents

- `policy-snapshot.json` — the frozen policy profile every check runs against
- `golden.json` — the recorded denials and the digest over them
- `denial_legibility_test.go` — the checks

## What an implementation has to satisfy

1. **Every refusal is classified.** Each denial reports one of five finality
   values — `class_forbidden`, `ungranted`, `instance_parameter`,
   `instance_context`, `instance_membership` — derived from the rule that
   fired. Never from a reason code the agent's own event log declares: a
   producer that could relabel its refusal as `instance_context` would be
   telling the consumer to keep going.
2. **Classification replays identically.** The same snapshot evaluated again
   produces a byte-identical result, and matches a digest frozen in an earlier
   process. The golden comparison is the load-bearing half — an implementation
   with per-process hash seeding will look stable within a single run.
3. **Membership refusals disclose nothing.** An `instance_membership` refusal
   says a caller-chosen target was refused against a confidential set — an
   egress allowlist, a set of workspace roots. That target is closed, other
   targets may work, and the set itself is never described: answering "not
   that one, try these" turns every refusal into a free probe of the estate.
   `class_forbidden` — a policy-named category of action from a fixed public
   vocabulary, like a disallowed memory class — carries no counterfactual
   either.
4. **Disclosure follows the rule, not the finality.** `instance_parameter` and
   `ungranted` *may* carry an envelope — a scalar ceiling, or a capability name
   from the fixed permission vocabulary — but neither always does. The pack
   contains an `instance_parameter` refusal that discloses nothing, because
   treating the finality value as a licence to disclose is the mistake an
   implementation is most likely to make.
5. **Opting out removes the fields.** With the profile switches off, the keys
   are absent rather than empty. Presence is itself a policy statement, and an
   empty field claims the policy said nothing when it did.
6. **The artifacts satisfy their published schemas.** The snapshot validates
   against `workstation_policy_profile.v1`, and a denial carrying these fields
   validates against `agent_run_receipt.v1`. A feature whose output its own
   contract rejects is not shippable.

An ALLOW control runs against the same snapshot. Without it, a boundary that
refuses everything — or one that hardcodes answers for the known event ids —
would pass this pack in full.

## Scope

This scenario covers the workstation boundary, which is where these fields are
produced today. In `protocols/policy-schema/v1/verdict.proto`, `DenyPayload`
carries both fields and `RequireApprovalPayload` carries `finality` only; the
policy VM that populates either is not in this repository, so no check here
claims to cover it.

`ungranted` is terminal at this boundary because the workstation layer has no
approver to escalate to. At the kernel PDP the same finality rides
`VERDICT_KIND_REQUIRE_APPROVAL` with the required signers attached. A consumer
reads the verdict kind to know what to do and the finality to know what to
learn, so the two never have to be inferred from each other.

## Regenerating the golden

Don't, as a way of making a failure go away. A diff here means the boundary
changed what it discloses, which is either a deliberate policy change or the
defect this pack exists to catch. `TestVerdictsSplitAsExpected` and
`TestMembershipRefusalsDiscloseNothing` assert their properties directly for
that reason: they still fail on a regenerated golden.

## Run

```bash
cd tests/conformance && go test ./denial-legibility/...
```
