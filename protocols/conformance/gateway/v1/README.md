# Gateway conformance table (v1)

<!-- quantum_posture: the table pins its files by SHA-256 and describes token
claims abstractly; it signs nothing and makes no post-quantum claim. -->

Machine-readable scenarios for the gateway effect API,
`helm.gateway.v1.EffectGatewayService`
([proto](../../../proto/helm/gateway/v1/gateway.proto),
[design note](../../../../docs/architecture/gateway-effect-api.md)). The real
`helm-gateway` and every fake of it, such as the Control Plane's, must pass
every scenario. HELM-751.

The real gateway runs the table in CI: `core/pkg/gateway/conformance`,
`TestPostgresGatewayConformanceTable`, listed in
`scripts/ci/postgres-proofs.txt`. It runs every scenario against PostgreSQL 16
with a scripted adapter, the GitHub App connection custody and the kernel's
JWKS token verifier, over Connect. If the gateway fails a scenario, CI fails,
so the table cannot drift from the gateway.
`TestPostgresConformanceRunnerRejectsAFlippedExpectation` flips one
expectation of each kind (state, error reason, adapter call count, exposure,
`existing`) in a temporary copy and proves the runner fails at that step.

## Files

| File | What it is |
|---|---|
| `conformance-pack.json` | The manifest. It lists every scenario with the SHA-256 of its file, and the schema's. |
| `scenario.schema.json` | JSON Schema (2020-12) for one scenario. The `json-schemas` gate validates every scenario against it (`scripts/ci/check_json_schemas_test.py`). |
| `scenarios/GW-NNN-*.json` | One scenario per file. |

## The scenarios

| ID | Rule |
|---|---|
| GW-001 | The walking skeleton: read, branch and draft pull request, approved by a distinct human |
| GW-002 | A branch on the default branch is DENIED (`MISSING_REQUIREMENT`), not an error |
| GW-003 | A repository outside the mandate's targets is DENIED (`EFFECT_OUT_OF_SCOPE`) |
| GW-004 | Self-approval (`APPROVER_NOT_DISTINCT`), a non-human approver and a wrong digest are refused, and the attempt stays ESCALATED |
| GW-005 | A decide token's jti is single-use |
| GW-006 | A decide token bound to another attempt, another action or nothing is refused |
| GW-007 | Step-up is required for high, irreversible and `helm.authority.*` approvals, and not for medium plus `approval_required` |
| GW-008 | A stop between approve and dispatch gives CANCELLED (`EMERGENCY_STOP_FENCED`), with the permit voided and no adapter call |
| GW-009 | M3: only the proposing workload dispatches or observes |
| GW-010 | A human's, read, propose or missing token cannot dispatch |
| GW-011 | A double dispatch calls the adapter once |
| GW-012 | INDEFINITE gives UNKNOWN. Absence inside the fence stays UNKNOWN; after the fence it reconciles FAILED |
| GW-013 | After SENT, absence inside the fence stays DISPATCHED |
| GW-014 | A contradicting read-back is FAILED (`READBACK_MISMATCH`), and the reservation is used |
| GW-015 | NOT_SENT is FAILED with the adapter's reason, and the reservation is released |
| GW-016 | Propose replay is idempotent; the same key with another digest is `IDEMPOTENCY_CONFLICT` |
| GW-017 | Another tenant's or workspace's attempt is `not_found` |
| GW-018 | `branch_attempt_id` accepts RECONCILED(SUCCEEDED) and refuses a branch that is not established |
| GW-019 | Cancel is the requester's or a human operator's single-use stop token, and only before dispatch |

## How a fake consumes the table

Run each scenario in a fresh state.

1. **Fixtures.** Seed the authority rows in every tenant of
   `fixtures.tenants`. That means:
   - the principals with their kind (`human`, `agent`, `service`);
   - `configured_actor`, the one workload a token's `act.sub` may name (the
     Control Plane runner);
   - the effect types with their risk;
   - the mandates as data: effect types, targets, a CEL `condition`,
     `approval_required`, `risk_classes`, and `limits` (a `sum` over the unit
     per window).

   Each mandate is valid from one hour before the scenario starts to one
   hour after. `activation` is the widening approval that activated it; a
   fake may ignore it.
2. **Tokens.** Each named token is a set of abstract claims:
   - `scope`, `sub`, `act_sub` (absent means a direct call), `tenant`,
     `workspace` and `jti`;
   - optionally `authorization_details` (RFC 9396).

   A fake reads them directly, with no signature. A step that names a token
   presents that token, so a name used twice is the same jti twice. A step
   with no `token` sends no `Authorization` header. The real runner signs
   each token once, as an RS256 JWT for audience `helm-gateway:conformance`
   that expires two minutes later.
3. **Placeholders.** Resolve the placeholders in requests, token claims and
   controls from the attempt that an earlier step's `label` names:
   - `{{attempt_id:<label>}}` becomes that attempt's `attempt_id`;
   - `{{approval_digest:<label>}}` becomes its
     `pending_approval.approval_digest`, in base64.
4. **Requests.** `request` is the request message in proto3 JSON with
   snake_case names. The one exception is `ProposeRequest.effect`, which
   carries `arguments_json`, a JSON object, instead of base64 `arguments`.
   The argument bytes are its compact serialization with members in document
   order: the bytes of `JSON.stringify(JSON.parse(text))`, or Go's
   `json.Compact`. They are identical because every string in the table
   escapes only `"`, `\` and `\n`.
5. **The adapter.** `fixtures.adapter` is a fake provider behind the gateway:
   - `dispatch` answers `SENT`, `NOT_SENT` or `INDEFINITE`, with a
     `reason_code` for the last two.
   - `observe` answers `SUCCEEDED`, `ABSENT` (FAILED because the object was
     not found, `READBACK_MISMATCH`), `CONTRADICTING` (FAILED because an
     object is not this effect, `READBACK_MISMATCH`) or `INCONCLUSIVE`.
   - `provider` holds what a SUCCEEDED read-back reports: the default branch
     and its commit, and the branch commit. The arguments name the same
     values.

   The gateway calls the adapter as the design note says: once per claimed
   Dispatch, then an immediate read-back after `SENT`, and none after
   `NOT_SENT` or `INDEFINITE`. `adapter_calls` counts both kinds of call
   since the scenario started. A fake that folds the adapter into the gateway
   must still count calls this way.
6. **Controls** are steps outside the RPC surface:
   - `stop`: an operator's stop row takes effect. The runner writes it
     directly, because the `Stop` RPC is not served yet.
   - `pass_dispatch_fence`: the attempt's `dispatch_deadline` is now in the
     past.
   - `set_adapter`: the adapter's behaviour changes from the next call on.
7. **Expectations.** Each RPC step expects one of two things:
   - An `attempt`. `state` and `reason_code` are always compared; `""` means
     empty. Every other field is compared only when present:
     - `outcome`, `outcome_basis`, `risk_class`, `requester_principal_id`,
       `requester_actor_id`, `approver_principal_id` and `pending_approval`
       compare with the attempt's own fields.
     - `permit` is derived. `NONE` means no permit, `CONSUMED` means
       `consumed_at` is set, `VOIDED` means `void_reason_code` is set, and
       `ISSUED` means none of these.
     - `exposure` is the kind every exposure has, or `NONE`.
     - `same_attempt_as` compares the `attempt_id`.

     The response's `existing` flag is compared when given.
   - An `error`: the Connect code, and the `reason_code` of its one
     `helm.errors.v1.ErrorDetail`.

   `adapter_calls` is checked after the step when present.

A fake does not need to reproduce the approval digest construction to pass;
it echoes the digest it returned. The digest's construction is pinned by the
design note's test vector.

## Pinning it (WS-B)

Pin two values: a commit of `Mindburn-Labs/helm-ai-kernel` and the SHA-256 of
`conformance-pack.json` at that commit. The pack pins every other file by its
own SHA-256, so the one hash covers the table.

```sh
REF=<commit sha>
PACK_SHA256=<sha256 of conformance-pack.json at REF>
DIR=protocols/conformance/gateway/v1
mkdir -p gateway-conformance && cd gateway-conformance
for f in conformance-pack.json scenario.schema.json; do
  gh api "repos/Mindburn-Labs/helm-ai-kernel/contents/$DIR/$f?ref=$REF" -H "Accept: application/vnd.github.raw" > "$f"
done
echo "$PACK_SHA256  conformance-pack.json" | shasum -a 256 -c
jq -r '.scenarios[].file' conformance-pack.json | while read -r f; do
  mkdir -p "$(dirname "$f")"
  gh api "repos/Mindburn-Labs/helm-ai-kernel/contents/$DIR/$f?ref=$REF" -H "Accept: application/vnd.github.raw" > "$f"
done
jq -r '(.scenario_schema | "\(.sha256)  \(.file)"), (.scenarios[] | "\(.sha256)  \(.file)")' conformance-pack.json | shasum -a 256 -c
```

Vendor the fetched directory, and have the fake's test suite repeat the two
`shasum` checks before it runs the scenarios, so that a hand edit of the
vendored copy fails. To move the pin, fetch at the new commit and update both
values.

## Versioning

- **New scenarios are additive.** A new file gets the next unused
  `GW-NNN`, and a pack entry. The pack's minor version goes up. An id is
  never reused.
- **Changing an expectation needs a design-note change.** A scenario encodes
  a rule of the contract. Changing what it expects, or removing a scenario,
  changes the rule. The same pull request must change the design note section
  the scenario cites (`docs/architecture/gateway-effect-api.md`), or the
  proto comment, and must bump the pack's major version. A pinned fake then
  fails on purpose until its owner moves the pin.
- **Wording only.** A fix to a title, a note or a statement that leaves every
  expectation the same changes the file's hash, but not the version.

`TestConformanceTableIsConsistent` (no database) checks the following:
- every file's hash matches the pack, and every scenario file is listed in
  it;
- ids are unique and name their files;
- every token and label resolves;
- every citation names a file and section that exist.

## Not in the table yet

- `Stop` and `Lift` answer `unimplemented`. Stops are a control step until
  they are served.
- Not covered: `ListAttempts`, escalation expiry, model calls, and
  `ESCALATED_TO_HUMAN`.
- A `helm.authority.*` effect whose mandate does not list it in
  `approval_required`, and whose effect-type row is low or medium, is ADMITTED
  without approval. The contract says authority widening needs another
  principal's approval (the `Lift` comment in the proto; §4.1 item 7). The
  table asserts only what the gateway enforces, so it has no scenario for this
  until the gateway escalates such effects. GW-007 covers the step-up for an
  escalated one.
