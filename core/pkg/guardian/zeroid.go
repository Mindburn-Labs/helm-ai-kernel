package guardian

import (
	"context"
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ZeroIDInterceptor rejects requests carrying a ZeroID credential envelope.
//
// It does NOT authenticate ZeroID credentials, and deliberately does not
// pretend to. There is no specified token format, no issuer/audience/expiry
// model, and no trust distribution mechanism for the verification keys — so
// there is nothing this interceptor could check a token against.
//
// It previously read `zeroid_token` and `spiffe_uri` out of the caller-supplied
// request context, checked only that the URI began with "spiffe://", and then
// assigned it to Request.Principal while labelling the decision
// "zeroid_verified". Because the interceptor is first in the default chain for
// every Guardian (see NewGuardian), that gave any caller who could reach the
// kernel a one-field cross-tenant principal-impersonation primitive: the
// spoofed principal went on to drive privilege-tier resolution and behavioural
// trust scoring downstream.
//
// The interceptor is retained, rather than deleted, so that a presented
// envelope is met with an explicit signed DENY instead of being silently
// ignored by a later stage. Requests with no envelope are untouched.
//
// To make ZeroID real, a future change must: define the token format, verify
// its signature against keys obtained from a trust root (not from the request),
// check issuer/audience/expiry/revocation, and only then bind the principal.
// Until all of that exists, binding an unverified principal is worse than
// refusing the request.
type ZeroIDInterceptor struct {
	g              *Guardian
	revocationList map[string]bool // In-memory CAEP/SSF revocation index
}

// NewZeroIDInterceptor initializes a new ZeroIDInterceptor.
//
// The former trustedKeys parameter has been removed: it was stored and never
// read by any code path, which is what let unverified envelopes through.
func NewZeroIDInterceptor(g *Guardian) *ZeroIDInterceptor {
	return &ZeroIDInterceptor{
		g:              g,
		revocationList: make(map[string]bool),
	}
}

// IngestCAEPRevocation dynamically invalidates a token received via CAEP SSF stream.
// Revoked tokens are reported with a distinct reason code for forensics.
func (z *ZeroIDInterceptor) IngestCAEPRevocation(tokenHash string) {
	z.revocationList[tokenHash] = true
}

// Evaluate denies any request presenting a ZeroID envelope and passes every
// other request through untouched. It never modifies Request.Principal.
func (z *ZeroIDInterceptor) Evaluate(ctx context.Context, evalCtx *EvaluationContext, next Handler) (*contracts.DecisionRecord, error) {
	token, _ := evalCtx.Request.Context["zeroid_token"].(string)
	spiffeURI, _ := evalCtx.Request.Context["spiffe_uri"].(string)

	if token == "" && spiffeURI == "" {
		return next(ctx, evalCtx)
	}

	// Revocation is checked first so an explicitly revoked credential is
	// distinguishable from one that merely cannot be verified.
	if token != "" && z.revocationList[token] {
		return z.denyWithReason(evalCtx, contracts.ReasonTaintedCredentialDeny,
			"ZeroID token has been dynamically revoked via CAEP")
	}

	if spiffeURI != "" && !strings.HasPrefix(spiffeURI, "spiffe://") {
		return z.denyWithReason(evalCtx, contracts.ReasonIdentityIsolationViolation,
			"Invalid SPIFFE URI format")
	}

	return z.denyWithReason(evalCtx, contracts.ReasonIdentityIsolationViolation,
		"ZeroID credential presented but no verification is possible; "+
			"refusing to bind an unverified principal")
}

func (z *ZeroIDInterceptor) denyWithReason(evalCtx *EvaluationContext, code contracts.ReasonCode, reason string) (*contracts.DecisionRecord, error) {
	now := z.g.clock.Now()
	envFP := z.g.envFprint
	if envFP == "" {
		envFP = "sha256:unconfigured"
	}

	decision := &contracts.DecisionRecord{
		ID:             newDecisionID(),
		Timestamp:      now,
		Verdict:        string(contracts.VerdictDeny),
		ReasonCode:     string(code),
		Reason:         fmt.Sprintf("ZeroID validation failed: %s", reason),
		EnvFingerprint: envFP,
		InputContext:   evalCtx.Request.Context,
	}

	if err := z.g.signDecisionWithContext(decision, evalCtx); err != nil {
		return nil, fmt.Errorf("failed to sign ZeroID deny decision: %w", err)
	}

	if z.g.auditLog != nil {
		decisionBytes, _ := canonicalize.JCS(decision)
		_, _ = z.g.auditLog.Append("guardian", "ZEROID_DENY", decision.ID, string(decisionBytes))
	}

	return decision, nil
}
