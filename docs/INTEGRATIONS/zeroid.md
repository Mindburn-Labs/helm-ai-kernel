# Highflame ZeroID — Not Integrated

<!-- quantum_posture: this page describes the Guardian's classical Ed25519 decision signer as it exists; it implements no cryptographic control and makes no post-quantum claim. -->

> [!IMPORTANT]
> **ZeroID credential authentication is not implemented, and is not staged for
> release.** No availability label applies to it: it is not Live, not Preview,
> not reviewed access, and not a pilot. It is not on a roadmap either — there is
> no dated ticket to build it. HELM does not verify Highflame ZeroID tokens,
> does not derive a principal from them, and does not treat a SPIFFE URI
> supplied by a caller as an identity.
>
> **What is Live** is a deny gate. `ZeroIDInterceptor` is the first interceptor
> in every Guardian's default boundary chain, and it refuses any request whose
> caller-supplied context contains a non-empty string `zeroid_token` or
> `spiffe_uri`. Requests where both values are absent, empty, or non-string are
> untouched by this interceptor.
>
> Implementation of record: [`core/pkg/guardian/zeroid.go`](../../core/pkg/guardian/zeroid.go)
> and its regression test [`core/pkg/guardian/zeroid_test.go`](../../core/pkg/guardian/zeroid_test.go).
> Chain position: [`core/pkg/guardian/guardian.go`](../../core/pkg/guardian/guardian.go) (`boundaryChain`).

## Retraction

An earlier revision of this page stated that HELM "ensures that all dispatched
tool calls and model requests originate from authenticated, policy-authorized
principals" by "validating ZeroID cryptographic tokens and SPIFFE URIs", that a
validated SPIFFE URI is "bound to the `EvaluationContext.Request.Principal`",
and that "the backend is pinned to `zeroid_verified`".

**None of that is true, and the behaviour it described was the security defect,
not the defence.** It is recorded as finding **F-04 (severity T0)** in the
[kernel security remediation ledger](../security/kernel-security-remediation-ledger.md):
the interceptor overwrote the authenticated principal with a caller-supplied
`spiffe_uri` after checking only that the string began with `spiffe://`, then
labelled the result `zeroid_verified`. Because the interceptor runs first in
every Guardian, that gave any caller who could reach the kernel a one-field
cross-tenant impersonation primitive — the spoofed principal went on to drive
privilege-tier resolution and behavioural trust scoring downstream. The proof of
concept promoted a tenant-A low-privilege agent to
`spiffe://tenant-b.example/admin` before the PDP ever ran.

F-04 is fixed. The fix was to stop binding the principal, not to start verifying
the token. The string `zeroid_verified` no longer appears in any runtime path;
its remaining occurrences explain the removed behaviour or assert negatively
that the runtime does not select that backend.

## What actually happens to a request

The interceptor reads non-empty string values for `zeroid_token` and
`spiffe_uri` from `EvaluationContext.Request.Context` — the caller-supplied
context map — and nothing else. Missing, empty, and non-string values are
treated as no envelope. It never writes to `Request.Principal`.

| Request | Outcome | Reason code |
|---|---|---|
| Neither key contains a non-empty string | Passes through to the rest of the chain, unmodified | — |
| `zeroid_token` is a non-empty string present in the in-process revocation index | `DENY` | `TAINTED_CREDENTIAL_ACCESS_DENY` |
| `spiffe_uri` is a non-empty string not prefixed `spiffe://` | `DENY` | `IDENTITY_ISOLATION_VIOLATION` |
| Any other non-empty string envelope, including a well-formed `spiffe://` URI or a plausible token | `DENY` | `IDENTITY_ISOLATION_VIOLATION` |

The last row is the one that matters: **a correctly formatted ZeroID envelope is
denied.** There is no ZeroID token format, no issuer/audience/expiry model, and
no trust-distribution mechanism for verification keys, so there is nothing the
interceptor could check a token against. It refuses rather than guesses.

The interceptor is retained rather than deleted so that a recognized non-empty
string envelope meets an explicit signed `DENY` instead of being silently
ignored by a later stage.

### The revocation index does not gate anything

`IngestCAEPRevocation(tokenHash string)` is an in-process Go method on the
interceptor. **No CAEP or SSF stream receiver ships in this repository** — the
method has no caller outside the test suite, and nothing subscribes to a
Continuous Access Evaluation or Shared Signals feed. An embedder can call it
directly, but doing so changes only which reason code a denied request carries.
Revocation is checked first purely so that an explicitly revoked credential is
distinguishable from one that merely cannot be verified. Every envelope is
denied either way.

## Decision records

A deny is written as a `DecisionRecord` with verdict `DENY`, the reason code
above, the Guardian's environment fingerprint, and the request context as
`InputContext`. It is signed with the Guardian's configured signer; if signing
fails the interceptor returns an error and no decision, so the request cannot
proceed. When an audit log is configured, the interceptor attempts to append
the record under the event type `ZEROID_DENY`. The append is best-effort:
failures are not propagated and do not change the signed `DENY` returned to the
caller.

The denial path calls the Guardian's configured `SignDecision`. The shipped
kernel signers stamp `DecisionRecordSignatureV4`, whose preimage is
JCS-canonical JSON; the legacy colon-joined preimage described by F-06 in the
[remediation ledger](../security/kernel-security-remediation-ledger.md) therefore
does not describe newly issued ZeroID decisions.

V4 is not a whole-record signature. Fields outside its envelope — including
`Timestamp`, `EnvFingerprint`, `InputContext`, and `GateRosterHash` — remain
unsigned. This page makes no claim that the signature covers the whole record
or is independently offline-verifiable.

## Verification

```bash
cd core
go test ./pkg/guardian -run TestZeroIDContinuousEvaluation -v
```

The suite asserts the behaviour documented above, including that an unverifiable
envelope is denied, that it never reaches the rest of the chain, that the
authenticated principal survives untouched, and that nothing is labelled
`zeroid_verified`.

## What building a real ZeroID adapter would require

Not a roadmap commitment — the preconditions, so that the gap is legible:

1. A specified ZeroID token format.
2. Signature verification against keys obtained from a trust root, not from the
   request.
3. Issuer, audience, and expiry checks.
4. A real revocation source wired to the index — an actual CAEP/SSF subscriber.
5. Principal binding only after all of the above.

Until all five exist, binding an unverified principal is worse than refusing the
request.
