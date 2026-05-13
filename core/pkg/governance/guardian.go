package governance

import (
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// Guardian is the governance-level authorization gateway. It combines a PolicyEngine
// (CEL-based policy evaluation) with an Ed25519 signer to produce signed DecisionRecords.
// Fail-closed: if policy evaluation errors or the expression is not satisfied, the
// verdict is DENY.
type Guardian struct {
	signer *crypto.Ed25519Signer
	engine *PolicyEngine
}

// NewGuardian creates a Guardian backed by the given signer and policy engine.
func NewGuardian(signer *crypto.Ed25519Signer, engine *PolicyEngine) *Guardian {
	return &Guardian{
		signer: signer,
		engine: engine,
	}
}

// Authorize evaluates the action and risk score against the default governance policy
// and returns a signed DecisionRecord. The built-in policy is:
//
//	risk_score < 80  (actions with risk >= 80 are denied)
//
// The decision is cryptographically signed so downstream consumers can verify provenance.
func (g *Guardian) Authorize(action string, riskScore int) (*contracts.DecisionRecord, error) {
	vars := map[string]interface{}{
		"action":     action,
		"risk_score": riskScore,
	}

	allowed, err := g.engine.EvaluateInline("risk_score < 80", vars)
	if err != nil {
		return nil, fmt.Errorf("guardian policy evaluation failed: %w", err)
	}

	verdict := "DENY"
	reason := fmt.Sprintf("risk_score %d >= threshold 80 for action %q", riskScore, action)
	if allowed {
		verdict = "ALLOW"
		reason = fmt.Sprintf("risk_score %d < threshold 80 for action %q", riskScore, action)
	}

	dec := &contracts.DecisionRecord{
		ID:        fmt.Sprintf("gdec-%d", time.Now().UnixNano()),
		SubjectID: "guardian",
		Action:    action,
		Verdict:   verdict,
		Reason:    reason,
		Timestamp: time.Now(),
	}

	// Sign the decision
	if err := g.signer.SignDecision(dec); err != nil {
		return nil, fmt.Errorf("guardian signing failed: %w", err)
	}

	return dec, nil
}
