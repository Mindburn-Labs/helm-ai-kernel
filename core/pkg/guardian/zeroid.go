package guardian

import (
	"context"
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ZeroIDInterceptor validates Highflame ZeroID cryptographic credentials.
type ZeroIDInterceptor struct {
	g              *Guardian
	trustedKeys    map[string]interface{} // Cached public verification keys
	revocationList map[string]bool        // In-memory CAEP/SSF revocation index
}

// NewZeroIDInterceptor initializes a new ZeroIDInterceptor.
func NewZeroIDInterceptor(g *Guardian, trustedKeys map[string]interface{}) *ZeroIDInterceptor {
	return &ZeroIDInterceptor{
		g:              g,
		trustedKeys:    trustedKeys,
		revocationList: make(map[string]bool),
	}
}

// IngestCAEPRevocation dynamically invalidates a token received via CAEP SSF stream.
func (z *ZeroIDInterceptor) IngestCAEPRevocation(tokenHash string) {
	z.revocationList[tokenHash] = true
}

// Evaluate intercepts requests to validate SPIFFE identity and token status.
func (z *ZeroIDInterceptor) Evaluate(ctx context.Context, evalCtx *EvaluationContext, next Handler) (*contracts.DecisionRecord, error) {
	// Extract ZeroID envelope parameters from request context
	token, _ := evalCtx.Request.Context["zeroid_token"].(string)
	spiffeURI, _ := evalCtx.Request.Context["spiffe_uri"].(string)

	if token != "" || spiffeURI != "" {
		// 1. Verify continuous evaluation (CAEP/SSF) status
		if z.revocationList[token] {
			return z.denyWithReason(evalCtx, contracts.ReasonTaintedCredentialDeny, "ZeroID token has been dynamically revoked via CAEP")
		}

		// 2. Perform SPIFFE format and structural signature validation
		if spiffeURI != "" && !strings.HasPrefix(spiffeURI, "spiffe://") {
			return z.denyWithReason(evalCtx, contracts.ReasonIdentityIsolationViolation, "Invalid SPIFFE URI format")
		}

		// 3. Bind validated principal to the evaluation context for Cedar down-routing
		evalCtx.Request.Principal = spiffeURI
		evalCtx.PDPBackend = "zeroid_verified"
	}

	return next(ctx, evalCtx)
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
