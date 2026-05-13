// Package envelope provides validation, hashing, and lifecycle management
// for the Autonomy Envelope — the signed runtime boundary contract.
//
// The envelope is the foundational primitive for autonomy-by-default:
//   - Pre-approved and continuously enforced
//   - Every run must bind to a valid envelope before any effects execute
//   - Anything outside the envelope becomes an exception requiring escalation
package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ValidationError represents a specific validation failure.
type ValidationError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s (%s)", e.Field, e.Message, e.Code)
}

// ValidationResult contains the outcome of envelope validation.
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors,omitempty"`
	Hash   string            `json:"hash,omitempty"` // Content hash if valid
}

// Validator validates Autonomy Envelopes for structural correctness,
// constraint consistency, and cryptographic integrity.
type Validator struct {
	// allowedAlgorithms restricts which signing algorithms are accepted.
	allowedAlgorithms map[string]bool
	// clock allows deterministic time for testing.
	clock func() time.Time
}

// NewValidator creates a new envelope validator.
func NewValidator() *Validator {
	return &Validator{
		allowedAlgorithms: map[string]bool{
			"ED25519":      true,
			"ECDSA-P256":   true,
			"RSA-PSS-2048": true,
		},
		clock: time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (v *Validator) WithClock(clock func() time.Time) *Validator {
	v.clock = clock
	return v
}

// Validate performs comprehensive validation of an Autonomy Envelope.
// This is fail-closed: any structural issue results in a validation failure.
func (v *Validator) Validate(env *contracts.AutonomyEnvelope) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if env == nil {
		v.addError(result, "envelope", "REQUIRED", "envelope must not be nil")
		return result
	}

	// Required identity fields
	v.requireNonEmpty(result, "envelope_id", env.EnvelopeID)
	v.requireNonEmpty(result, "version", env.Version)
	v.requireNonEmpty(result, "format_version", env.FormatVersion)

	if env.FormatVersion != "" && env.FormatVersion != "1.0.0" {
		v.addError(result, "format_version", "UNSUPPORTED_FORMAT",
			fmt.Sprintf("unsupported format version %q, expected \"1.0.0\"", env.FormatVersion))
	}

	// Validity window
	now := v.clock().UTC()
	if !env.ValidFrom.IsZero() && !env.ValidUntil.IsZero() {
		if env.ValidUntil.Before(env.ValidFrom) {
			v.addError(result, "valid_until", "INVALID_WINDOW",
				"valid_until must be after valid_from")
		}
	}
	if !env.ValidUntil.IsZero() && env.ValidUntil.Before(now) {
		v.addError(result, "valid_until", "EXPIRED",
			fmt.Sprintf("envelope expired at %s", env.ValidUntil.Format(time.RFC3339)))
	}

	// Jurisdiction scope
	v.validateJurisdiction(result, &env.JurisdictionScope)

	// Data handling
	v.validateDataHandling(result, &env.DataHandling)

	// Allowed effects
	v.validateAllowedEffects(result, env.AllowedEffects)

	// Budgets
	v.validateBudgets(result, &env.Budgets)

	// Required evidence
	v.validateRequiredEvidence(result, env.RequiredEvidence)

	// Escalation policy
	v.validateEscalationPolicy(result, &env.EscalationPolicy)

	// Attestation
	v.validateAttestation(result, env)

	if result.Valid {
		hash, err := ComputeContentHash(env)
		if err == nil {
			result.Hash = hash
		}
	}

	return result
}

func (v *Validator) validateJurisdiction(result *ValidationResult, j *contracts.JurisdictionConstraint) {
	if len(j.AllowedJurisdictions) == 0 {
		v.addError(result, "jurisdiction_scope.allowed_jurisdictions", "REQUIRED",
			"at least one allowed jurisdiction is required")
	}

	validModes := map[string]bool{
		contracts.RegulatoryModeStrict:     true,
		contracts.RegulatoryModePermissive: true,
		contracts.RegulatoryModeAuditOnly:  true,
	}
	if !validModes[j.RegulatoryMode] {
		v.addError(result, "jurisdiction_scope.regulatory_mode", "INVALID_VALUE",
			fmt.Sprintf("invalid regulatory mode %q", j.RegulatoryMode))
	}

	// Check for conflicts between allowed and prohibited
	prohibited := make(map[string]bool)
	for _, p := range j.ProhibitedJurisdictions {
		prohibited[p] = true
	}
	for _, a := range j.AllowedJurisdictions {
		if prohibited[a] {
			v.addError(result, "jurisdiction_scope", "CONFLICT",
				fmt.Sprintf("jurisdiction %q is both allowed and prohibited", a))
		}
	}
}

func (v *Validator) validateDataHandling(result *ValidationResult, d *contracts.DataHandlingRules) {
	validClassifications := map[string]bool{
		contracts.DataClassPublic:       true,
		contracts.DataClassInternal:     true,
		contracts.DataClassConfidential: true,
		contracts.DataClassRestricted:   true,
	}
	if !validClassifications[d.MaxClassification] {
		v.addError(result, "data_handling.max_classification", "INVALID_VALUE",
			fmt.Sprintf("invalid data classification %q", d.MaxClassification))
	}

	validRedaction := map[string]bool{"none": true, "pii_only": true, "strict": true}
	if !validRedaction[d.RedactionPolicy] {
		v.addError(result, "data_handling.redaction_policy", "INVALID_VALUE",
			fmt.Sprintf("invalid redaction policy %q", d.RedactionPolicy))
	}
}

func (v *Validator) validateAllowedEffects(result *ValidationResult, effects []contracts.EffectClassAllowlist) {
	if len(effects) == 0 {
		v.addError(result, "allowed_effects", "REQUIRED",
			"at least one allowed effect class is required")
		return
	}

	validClasses := map[string]bool{"E0": true, "E1": true, "E2": true, "E3": true, "E4": true}
	seen := make(map[string]bool)

	for i, e := range effects {
		if !validClasses[e.EffectClass] {
			v.addError(result, fmt.Sprintf("allowed_effects[%d].effect_class", i), "INVALID_VALUE",
				fmt.Sprintf("invalid effect class %q", e.EffectClass))
		}
		if seen[e.EffectClass] {
			v.addError(result, fmt.Sprintf("allowed_effects[%d].effect_class", i), "DUPLICATE",
				fmt.Sprintf("duplicate effect class %q", e.EffectClass))
		}
		seen[e.EffectClass] = true

		if e.MaxPerRun < 0 {
			v.addError(result, fmt.Sprintf("allowed_effects[%d].max_per_run", i), "INVALID_VALUE",
				"max_per_run must be non-negative")
		}
	}
}

func (v *Validator) validateBudgets(result *ValidationResult, b *contracts.EnvelopeBudgets) {
	if b.CostCeilingCents <= 0 {
		v.addError(result, "budgets.cost_ceiling_cents", "INVALID_VALUE",
			"cost_ceiling_cents must be positive")
	}
	if b.TimeCeilingSeconds <= 0 {
		v.addError(result, "budgets.time_ceiling_seconds", "INVALID_VALUE",
			"time_ceiling_seconds must be positive")
	}
	if b.ToolCallCap <= 0 {
		v.addError(result, "budgets.tool_call_cap", "INVALID_VALUE",
			"tool_call_cap must be positive")
	}

	if b.BlastRadius != "" {
		validRadius := map[string]bool{
			contracts.BlastRadiusSingleRecord: true,
			contracts.BlastRadiusDataset:      true,
			contracts.BlastRadiusSystemWide:   true,
		}
		if !validRadius[b.BlastRadius] {
			v.addError(result, "budgets.blast_radius", "INVALID_VALUE",
				fmt.Sprintf("invalid blast radius %q", b.BlastRadius))
		}
	}

	for i, rl := range b.RateLimits {
		if rl.Resource == "" {
			v.addError(result, fmt.Sprintf("budgets.rate_limits[%d].resource", i), "REQUIRED",
				"resource is required")
		}
		if rl.MaxPerMinute <= 0 {
			v.addError(result, fmt.Sprintf("budgets.rate_limits[%d].max_per_minute", i), "INVALID_VALUE",
				"max_per_minute must be positive")
		}
	}
}

func (v *Validator) validateRequiredEvidence(result *ValidationResult, reqs []contracts.EvidenceRequirement) {
	validTypes := map[string]bool{
		contracts.EvidenceTypeReceipt:              true,
		contracts.EvidenceTypeHashProof:            true,
		contracts.EvidenceTypeDualAttestation:      true,
		contracts.EvidenceTypeExternalVerification: true,
		contracts.EvidenceTypeReplayProof:          true,
	}
	validWhen := map[string]bool{"before": true, "after": true, "both": true}

	for i, r := range reqs {
		if r.ActionClass == "" {
			v.addError(result, fmt.Sprintf("required_evidence[%d].action_class", i), "REQUIRED",
				"action_class is required")
		}
		if !validTypes[r.EvidenceType] {
			v.addError(result, fmt.Sprintf("required_evidence[%d].evidence_type", i), "INVALID_VALUE",
				fmt.Sprintf("invalid evidence type %q", r.EvidenceType))
		}
		if !validWhen[r.When] {
			v.addError(result, fmt.Sprintf("required_evidence[%d].when", i), "INVALID_VALUE",
				fmt.Sprintf("invalid when value %q", r.When))
		}
	}
}

func (v *Validator) validateEscalationPolicy(result *ValidationResult, e *contracts.EscalationRules) {
	validModes := map[string]bool{
		contracts.EscalationModeAutonomous: true,
		contracts.EscalationModeSupervised: true,
		contracts.EscalationModeManual:     true,
	}
	if !validModes[e.DefaultMode] {
		v.addError(result, "escalation_policy.default_mode", "INVALID_VALUE",
			fmt.Sprintf("invalid default mode %q", e.DefaultMode))
	}

	validActions := map[string]bool{
		contracts.EscalationActionRequireApproval: true,
		contracts.EscalationActionPauseAndNotify:  true,
		contracts.EscalationActionAbort:           true,
	}

	for i, t := range e.EscalationTriggers {
		if t.Condition == "" {
			v.addError(result, fmt.Sprintf("escalation_policy.escalation_triggers[%d].condition", i),
				"REQUIRED", "condition is required")
		}
		if !validActions[t.Action] {
			v.addError(result, fmt.Sprintf("escalation_policy.escalation_triggers[%d].action", i),
				"INVALID_VALUE", fmt.Sprintf("invalid escalation action %q", t.Action))
		}
		if t.Action == contracts.EscalationActionRequireApproval && t.Quorum <= 0 {
			v.addError(result, fmt.Sprintf("escalation_policy.escalation_triggers[%d].quorum", i),
				"INVALID_VALUE", "quorum must be positive when action is require_approval")
		}
	}

	validClassifications := map[string]bool{
		contracts.JudgmentAutonomous: true,
		contracts.JudgmentRequired:   true,
	}
	for i, j := range e.JudgmentTaxonomy {
		if j.Category == "" {
			v.addError(result, fmt.Sprintf("escalation_policy.judgment_taxonomy[%d].category", i),
				"REQUIRED", "category is required")
		}
		if !validClassifications[j.Classification] {
			v.addError(result, fmt.Sprintf("escalation_policy.judgment_taxonomy[%d].classification", i),
				"INVALID_VALUE", fmt.Sprintf("invalid classification %q", j.Classification))
		}
	}
}

func (v *Validator) validateAttestation(result *ValidationResult, env *contracts.AutonomyEnvelope) {
	if env.Attestation.ContentHash == "" {
		v.addError(result, "attestation.content_hash", "REQUIRED",
			"content_hash is required")
		return
	}

	// Verify content hash matches
	computed, err := ComputeContentHash(env)
	if err != nil {
		v.addError(result, "attestation.content_hash", "HASH_ERROR",
			fmt.Sprintf("failed to compute content hash: %v", err))
		return
	}
	if computed != env.Attestation.ContentHash {
		v.addError(result, "attestation.content_hash", "HASH_MISMATCH",
			"content_hash does not match computed hash — possible tamper")
	}

	// Validate algorithm if signature present
	if env.Attestation.Signature != "" {
		if !v.allowedAlgorithms[env.Attestation.Algorithm] {
			v.addError(result, "attestation.algorithm", "INVALID_VALUE",
				fmt.Sprintf("unsupported signing algorithm %q", env.Attestation.Algorithm))
		}
	}
}

func (v *Validator) requireNonEmpty(result *ValidationResult, field, value string) {
	if value == "" {
		v.addError(result, field, "REQUIRED", fmt.Sprintf("%s is required", field))
	}
}

func (v *Validator) addError(result *ValidationResult, field, code, message string) {
	result.Valid = false
	result.Errors = append(result.Errors, ValidationError{
		Field:   field,
		Code:    code,
		Message: message,
	})
}

// ComputeContentHash computes the SHA-256 content hash of an envelope,
// excluding the attestation section. This is deterministic: same envelope
// content always produces the same hash.
func ComputeContentHash(env *contracts.AutonomyEnvelope) (string, error) {
	hashable := struct {
		EnvelopeID        string                           `json:"envelope_id"`
		Version           string                           `json:"version"`
		FormatVersion     string                           `json:"format_version"`
		ValidFrom         time.Time                        `json:"valid_from,omitempty"`
		ValidUntil        time.Time                        `json:"valid_until,omitempty"`
		TenantID          string                           `json:"tenant_id,omitempty"`
		JurisdictionScope contracts.JurisdictionConstraint `json:"jurisdiction_scope"`
		DataHandling      contracts.DataHandlingRules      `json:"data_handling"`
		AllowedEffects    []contracts.EffectClassAllowlist `json:"allowed_effects"`
		Budgets           contracts.EnvelopeBudgets        `json:"budgets"`
		RequiredEvidence  []contracts.EvidenceRequirement  `json:"required_evidence"`
		EscalationPolicy  contracts.EscalationRules        `json:"escalation_policy"`
	}{
		EnvelopeID:        env.EnvelopeID,
		Version:           env.Version,
		FormatVersion:     env.FormatVersion,
		ValidFrom:         env.ValidFrom,
		ValidUntil:        env.ValidUntil,
		TenantID:          env.TenantID,
		JurisdictionScope: env.JurisdictionScope,
		DataHandling:      env.DataHandling,
		AllowedEffects:    env.AllowedEffects,
		Budgets:           env.Budgets,
		RequiredEvidence:  env.RequiredEvidence,
		EscalationPolicy:  env.EscalationPolicy,
	}

	bytes, err := json.Marshal(hashable)
	if err != nil {
		return "", fmt.Errorf("failed to marshal envelope for hashing: %w", err)
	}

	hash := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

// Sign computes the content hash and sets it on the envelope's attestation.
// In production, this would also compute a cryptographic signature.
func Sign(env *contracts.AutonomyEnvelope, signerID string) error {
	hash, err := ComputeContentHash(env)
	if err != nil {
		return fmt.Errorf("failed to compute content hash for signing: %w", err)
	}

	env.Attestation.ContentHash = hash
	env.Attestation.SignerID = signerID
	env.Attestation.SignedAt = time.Now().UTC()

	return nil
}
