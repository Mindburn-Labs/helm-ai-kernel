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

1. **Every refusal is classified.** Each denial reports one of four finality
   values — `class_forbidden`, `ungranted`, `instance_parameter`,
   `instance_context` — derived from the rule that fired.
2. **Classification replays identically.** The same snapshot evaluated again
   produces a byte-identical result. A boundary that drifts between rounds
   cannot be proven to an auditor.
3. **Membership refusals disclose nothing.** A `class_forbidden` refusal never
   carries a counterfactual. An egress allowlist or a set of workspace roots is
   a map of internal infrastructure; answering "not that one, try these" turns
   every refusal into a free probe of the estate.
4. **Bounded refusals disclose the bound.** `instance_parameter` carries the
   scalar ceiling, and `ungranted` carries the capability name, so a compliant
   retry does not require guessing.
5. **Opting out removes the fields.** With the profile switches off, the keys
   are absent rather than empty. Presence is itself a policy statement, and an
   empty field claims the policy said nothing when it did.

## Scope

This scenario covers the workstation boundary, which is where these fields are
produced today. `DenyPayload` and `RequireApprovalPayload` in
`protocols/policy-schema/v1/verdict.proto` carry the same two fields for CPI
verdicts; the policy VM that populates them is not in this repository, so no
check here claims to cover it.

`ungranted` is terminal at this boundary because the workstation layer has no
approver to escalate to. At the kernel PDP the same finality rides
`VERDICT_KIND_REQUIRE_APPROVAL` with the required signers attached. A consumer
reads the verdict kind to know what to do and the finality to know what to
learn, so the two never have to be inferred from each other.

## Regenerating the golden

Don't, as a way of making a failure go away. A diff here means the boundary
changed what it discloses, which is either a deliberate policy change or the
defect this pack exists to catch. `TestEveryScenarioIsDenied` and
`TestMembershipRefusalsDiscloseNothing` assert their properties directly for
that reason: they still fail on a regenerated golden.

## Run

```bash
cd tests/conformance && go test ./denial-legibility/...
```
