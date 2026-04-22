package policies

import (
	"fmt"
	"time"
)

// Effect represents an effect to be executed.
type Effect struct {
	EffectID        string                 `json:"effect_id"`
	EffectType      EffectType             `json:"effect_type"`
	IdempotencyKey  string                 `json:"idempotency_key,omitempty"`
	ToolFingerprint string                 `json:"tool_fingerprint,omitempty"`
	Principal       string                 `json:"principal"`
	Target          string                 `json:"target"`
	Payload         map[string]interface{} `json:"payload"`
	Evidence        map[string]string      `json:"evidence,omitempty"`
	Approvals       []Approval             `json:"approvals,omitempty"`
}

// Approval represents an approval for an effect.
type Approval struct {
	ApproverID string    `json:"approver_id"`
	ApprovedAt time.Time `json:"approved_at"`
	Signature  string    `json:"signature,omitempty"`
}

// Receipt represents the result of an executed effect.
type Receipt struct {
	ReceiptID       string            `json:"receipt_id"`
	EffectID        string            `json:"effect_id"`
	EffectType      EffectType        `json:"effect_type"`
	Status          ReceiptStatus     `json:"status"`
	ToolFingerprint string            `json:"tool_fingerprint,omitempty"`
	Evidence        map[string]string `json:"evidence"`
	ContentHash     string            `json:"content_hash"`
	Timestamp       time.Time         `json:"timestamp"`
	IdempotencyKey  string            `json:"idempotency_key,omitempty"`
	RetryCount      int               `json:"retry_count"`
}

// ReceiptStatus represents the outcome of an effect.
type ReceiptStatus string

const (
	ReceiptStatusSuccess ReceiptStatus = "SUCCESS"
	ReceiptStatusFailed  ReceiptStatus = "FAILED"
	ReceiptStatusPending ReceiptStatus = "PENDING"
	ReceiptStatusBlocked ReceiptStatus = "BLOCKED"
)

// PolicyEnforcer validates effects against their policies.
type PolicyEnforcer struct {
	policyTable     map[EffectType]EffectPolicy
	strictMode      bool
	prohibitedTools map[string]bool // Set of prohibited tools
}

// EnforcerOption configures a PolicyEnforcer.
type EnforcerOption func(*PolicyEnforcer)

// WithPolicyTable overrides the default global PolicyTable with a custom one.
func WithPolicyTable(pt map[EffectType]EffectPolicy) EnforcerOption {
	return func(e *PolicyEnforcer) { e.policyTable = pt }
}

// NewPolicyEnforcer creates a new enforcer with the default policy table.
func NewPolicyEnforcer(strictMode bool, opts ...EnforcerOption) *PolicyEnforcer {
	e := &PolicyEnforcer{
		policyTable:     PolicyTable,
		strictMode:      strictMode,
		prohibitedTools: make(map[string]bool),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// SetProhibitedTools updates the set of prohibited tools.
func (e *PolicyEnforcer) SetProhibitedTools(tools []string) {
	e.prohibitedTools = make(map[string]bool)
	for _, t := range tools {
		e.prohibitedTools[t] = true
	}
}

// IsToolAllowed checks if a tool is permitted.
func (e *PolicyEnforcer) IsToolAllowed(toolName string) bool {
	return !e.prohibitedTools[toolName]
}

// PrerequisiteError describes a policy prerequisite violation.
type PrerequisiteError struct {
	Policy     *EffectPolicy
	Violations []string
}

func (e *PrerequisiteError) Error() string {
	return fmt.Sprintf("policy prerequisites failed for %s: %v", e.Policy.EffectType, e.Violations)
}

// ValidatePrerequisites checks if an effect meets its policy prerequisites.
// This MUST be called before executing any effect.
func (e *PolicyEnforcer) ValidatePrerequisites(effect *Effect) error {
	policy, err := e.getPolicy(effect.EffectType)
	if err != nil {
		return err
	}

	violations := []string{}

	// Check idempotency key if required
	if policy.IdempotencyRequired && effect.IdempotencyKey == "" {
		violations = append(violations, "idempotency_key required")
	}

	// Check corroboration (approvals)
	if policy.CorroborationThreshold > 0 {
		if len(effect.Approvals) < policy.CorroborationThreshold {
			violations = append(violations, fmt.Sprintf(
				"requires %d approvals, got %d",
				policy.CorroborationThreshold,
				len(effect.Approvals)))
		}
	}

	// Check required approval flag
	if policy.RequiresApproval && len(effect.Approvals) == 0 {
		violations = append(violations, "approval required")
	}

	// Check required evidence classes (before execution)
	// Some evidence may only be available after execution
	for _, required := range policy.RequiredEvidenceClass {
		// Pre-execution evidence: tool_fingerprint
		if required == "tool_fingerprint" && effect.ToolFingerprint == "" {
			violations = append(violations, "tool_fingerprint required")
		}
	}

	if len(violations) > 0 {
		return &PrerequisiteError{
			Policy:     policy,
			Violations: violations,
		}
	}

	return nil
}

// ReceiptError describes a policy violation in a receipt.
type ReceiptError struct {
	Policy     *EffectPolicy
	Receipt    *Receipt
	Violations []string
}

func (e *ReceiptError) Error() string {
	return fmt.Sprintf("receipt policy violation for %s (receipt: %s): %v",
		e.Policy.EffectType, e.Receipt.ReceiptID, e.Violations)
}

// ValidateReceipt checks if a receipt meets its policy requirements.
// This MUST be called after executing any effect.
func (e *PolicyEnforcer) ValidateReceipt(receipt *Receipt, effect *Effect) error {
	policy, err := e.getPolicy(effect.EffectType)
	if err != nil {
		return err
	}

	violations := []string{}

	// Check all required evidence is present
	for _, required := range policy.RequiredEvidenceClass {
		if _, ok := receipt.Evidence[required]; !ok {
			violations = append(violations, fmt.Sprintf("missing evidence: %s", required))
		}
	}

	// Check content hash is present
	if receipt.ContentHash == "" {
		violations = append(violations, "content_hash required")
	}

	// Check idempotency key matches
	if policy.IdempotencyRequired {
		if receipt.IdempotencyKey != effect.IdempotencyKey {
			violations = append(violations, "idempotency_key mismatch")
		}
	}

	// Check retry count is within limits
	if receipt.RetryCount > policy.MaxRetries {
		violations = append(violations, fmt.Sprintf(
			"exceeded max retries: %d > %d",
			receipt.RetryCount, policy.MaxRetries))
	}

	// Check tool fingerprint matches if required
	if effect.ToolFingerprint != "" && receipt.ToolFingerprint != effect.ToolFingerprint {
		violations = append(violations, "tool_fingerprint mismatch - reevaluation required")
	}

	if len(violations) > 0 {
		return &ReceiptError{
			Policy:     policy,
			Receipt:    receipt,
			Violations: violations,
		}
	}

	return nil
}

// MustHaveIdempotencyKey returns true if the effect type requires idempotency.
func (e *PolicyEnforcer) MustHaveIdempotencyKey(effectType EffectType) bool {
	policy, err := e.getPolicy(effectType)
	if err != nil {
		return e.strictMode // Default to requiring it in strict mode
	}
	return policy.IdempotencyRequired
}

// GetRetentionPeriod returns the retention period for an effect type.
func (e *PolicyEnforcer) GetRetentionPeriod(effectType EffectType) time.Duration {
	policy, err := e.getPolicy(effectType)
	if err != nil {
		return 365 * 24 * time.Hour // Default 1 year
	}
	return time.Duration(policy.RetentionPeriod)
}

// GetGuardianTriggers returns the guardian triggers for an effect type.
func (e *PolicyEnforcer) GetGuardianTriggers(effectType EffectType) []string {
	policy, err := e.getPolicy(effectType)
	if err != nil {
		return nil
	}
	return policy.GuardianTriggers
}

// getPolicy retrieves the policy with error handling.
func (e *PolicyEnforcer) getPolicy(effectType EffectType) (*EffectPolicy, error) {
	policy, ok := e.policyTable[effectType]
	if !ok {
		if e.strictMode {
			return nil, fmt.Errorf("no policy defined for effect type: %s", effectType)
		}
		// Return a permissive default in non-strict mode
		return &EffectPolicy{
			EffectType:          effectType,
			IdempotencyRequired: false,
			MaxRetries:          3,
			RetentionPeriod:     Duration(30 * 24 * time.Hour),
		}, nil
	}
	return &policy, nil
}
