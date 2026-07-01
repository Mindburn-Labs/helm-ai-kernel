# Highflame ZeroID Interoperability Adapter

> Status: source-backed adapter candidate. This page documents the source-owned adapter path for Highflame ZeroID cryptographic credentials within the HELM AI Kernel Guardian policy engine; it is not release or runtime evidence.

HELM integrates with Highflame ZeroID to enforce zero-trust identity authentication at the execution boundary. By validating ZeroID cryptographic tokens and SPIFFE URIs, HELM ensures that all dispatched tool calls and model requests originate from authenticated, policy-authorized principals.

## Architecture & Policy-Routing Logic

The ZeroID implementation is centered around the `ZeroIDInterceptor` under `core/pkg/guardian/zeroid.go`. It intercepts every inbound execution request to validate identity claims:

1. **Continuous Access Evaluation (CAEP / SSF)**:
   The interceptor maintains an in-memory revocation index. When a token revocation event is received via a CAEP (Continuous Access Evaluation Protocol) or SSF (Shared Signals and Events) stream, the token hash is dynamically marked as revoked. Subsequent requests using the revoked token are immediately blocked.
   
2. **SPIFFE URI Format Validation**:
   Any SPIFFE identity provided in the request context (`spiffe_uri`) must conform to the standard format (prefixed with `spiffe://`). Malformed identities trigger an immediate deny decision.

3. **Context Binding & Cedar Policy Down-Routing**:
   Once validated, the SPIFFE URI is bound to the `EvaluationContext.Request.Principal` and the backend is pinned to `zeroid_verified`. This allows downstream Cedar policy evaluations to route decisions based on verified cryptographically bound identities rather than arbitrary names.

## Verification

To run the automated suite verifying continuous CAEP revocation and SPIFFE format validation:

```bash
cd core
go test ./pkg/guardian -run TestZeroIDContinuousEvaluation -v
```

## Deny Reason Classification

If a credential is found to be revoked or dynamically tainted, the Guardian issues a signed decision record with `ReasonTaintedCredentialDeny`. If the SPIFFE identity contains format violations, `ReasonIdentityIsolationViolation` is returned instead. All decisions are sealed and signed with HELM's offline-verifiable keys.
