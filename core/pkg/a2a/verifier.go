package a2a

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DefaultVerifier implements the Verifier interface with fail-closed semantics.
type DefaultVerifier struct {
	mu          sync.RWMutex
	trustedKeys map[string]TrustedKey // kid → key
	policyRules []PolicyRule
	clock       func() time.Time
}

// NewDefaultVerifier creates a new A2A verifier.
func NewDefaultVerifier() *DefaultVerifier {
	return &DefaultVerifier{
		trustedKeys: make(map[string]TrustedKey),
		clock:       time.Now,
	}
}

// WithClock overrides the clock for testing.
func (v *DefaultVerifier) WithClock(clock func() time.Time) *DefaultVerifier {
	v.clock = clock
	return v
}

// RegisterKey adds a trusted key for signature verification.
func (v *DefaultVerifier) RegisterKey(key TrustedKey) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.trustedKeys[key.KeyID] = key
}

// AddPolicyRule adds a cross-agent policy rule.
func (v *DefaultVerifier) AddPolicyRule(rule PolicyRule) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.policyRules = append(v.policyRules, rule)
}

// Negotiate performs schema/feature negotiation with fail-closed semantics.
func (v *DefaultVerifier) Negotiate(ctx context.Context, env *Envelope, localFeatures []Feature) (*NegotiationResult, error) {
	_ = ctx
	v.mu.RLock()
	defer v.mu.RUnlock()

	now := v.clock()
	result := &NegotiationResult{
		ReceiptID: "a2a-neg:" + uuid.NewString()[:8],
		Timestamp: now,
	}

	// 1. Check expiration
	if !env.ExpiresAt.IsZero() && now.After(env.ExpiresAt) {
		result.Accepted = false
		result.DenyReason = DenyVersionIncompatible
		result.DenyDetails = fmt.Sprintf("envelope expired at %s", env.ExpiresAt.Format(time.RFC3339))
		return result, nil
	}

	// 2. Check schema version compatibility (same major required)
	if env.SchemaVersion.Major != CurrentVersion.Major {
		result.Accepted = false
		result.DenyReason = DenyVersionIncompatible
		result.DenyDetails = fmt.Sprintf(
			"incompatible version: remote=%s local=%s",
			env.SchemaVersion.String(), CurrentVersion.String(),
		)
		return result, nil
	}

	// 3. Check policy rules
	if deny, reason := v.checkPolicies(env); deny {
		result.Accepted = false
		result.DenyReason = DenyPolicyViolation
		result.DenyDetails = reason
		return result, nil
	}

	// 4. Feature negotiation: all required features must be available locally
	localFeatureSet := make(map[Feature]bool)
	for _, f := range localFeatures {
		localFeatureSet[f] = true
	}

	for _, required := range env.RequiredFeatures {
		if !localFeatureSet[required] {
			result.Accepted = false
			result.DenyReason = DenyFeatureMissing
			result.DenyDetails = fmt.Sprintf("required feature %q not available locally", required)
			return result, nil
		}
	}

	// 5. Compute agreed features (intersection of offered + local)
	var agreed []Feature
	offeredSet := make(map[Feature]bool)
	for _, f := range env.OfferedFeatures {
		offeredSet[f] = true
	}
	for _, f := range localFeatures {
		if offeredSet[f] {
			agreed = append(agreed, f)
		}
	}

	agreedVersion := CurrentVersion
	result.Accepted = true
	result.AgreedFeatures = agreed
	result.AgreedVersion = &agreedVersion

	return result, nil
}

// VerifySignature verifies the envelope signature.
func (v *DefaultVerifier) VerifySignature(ctx context.Context, env *Envelope) (bool, error) {
	_ = ctx
	v.mu.RLock()
	defer v.mu.RUnlock()

	sig := env.Signature
	if sig.KeyID == "" || sig.Value == "" {
		return false, nil
	}

	// Look up trusted key
	key, ok := v.trustedKeys[sig.KeyID]
	if !ok {
		return false, nil
	}

	// Verify key belongs to the originating agent
	if key.AgentID != env.OriginAgentID {
		return false, nil
	}

	if !key.Active {
		return false, nil
	}

	// Verify algorithm matches
	if key.Algorithm != sig.Algorithm {
		return false, nil
	}

	// Verify signature (hash-based check for reference implementation)
	expectedHash := ComputeEnvelopeHash(env)
	return sig.Value == expectedHash, nil
}

// checkPolicies evaluates policy rules against the envelope.
func (v *DefaultVerifier) checkPolicies(env *Envelope) (deny bool, reason string) {
	for _, rule := range v.policyRules {
		originMatch := rule.OriginAgent == "*" || rule.OriginAgent == env.OriginAgentID
		targetMatch := rule.TargetAgent == "*" || rule.TargetAgent == env.TargetAgentID
		if !originMatch || !targetMatch {
			continue
		}

		if rule.Action == PolicyDeny {
			for _, denied := range rule.DeniedFeatures {
				for _, required := range env.RequiredFeatures {
					if denied == required {
						return true, fmt.Sprintf("policy %s denies feature %s for %s→%s",
							rule.RuleID, denied, env.OriginAgentID, env.TargetAgentID)
					}
				}
			}
		}
	}
	return false, ""
}

// Compile-time interface check.
var _ Verifier = (*DefaultVerifier)(nil)
