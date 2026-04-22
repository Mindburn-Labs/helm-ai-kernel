// Package policies provides per-EffectType receipt policy enforcement.
// Per Section 2.1 - Canonical semantic receipt layer with policy governance.
package policies

import (
	"fmt"
	"time"
)

// EffectType represents the category of effect being executed.
type EffectType string

const (
	EffectTypeDataWrite        EffectType = "DATA_WRITE"
	EffectTypeFundsTransfer    EffectType = "FUNDS_TRANSFER"
	EffectTypePermissionChange EffectType = "PERMISSION_CHANGE"
	EffectTypeDeploy           EffectType = "DEPLOY"
	EffectTypeNotify           EffectType = "NOTIFY"
	EffectTypeModuleInstall    EffectType = "MODULE_INSTALL"
	EffectTypeConfigChange     EffectType = "CONFIG_CHANGE"
	EffectTypeAuditLog         EffectType = "AUDIT_LOG"
	EffectTypeExternalAPICall  EffectType = "EXTERNAL_API_CALL"
)

// EffectPolicy defines the receipt and enforcement requirements for an effect type.
type EffectPolicy struct {
	EffectType             EffectType `json:"effect_type"`
	IdempotencyRequired    bool       `json:"idempotency_required"`
	RequiredEvidenceClass  []string   `json:"required_evidence_class"`
	CorroborationThreshold int        `json:"corroboration_threshold"`
	ReplayabilityRequired  bool       `json:"replayability_required"`
	MaxBlastRadius         int        `json:"max_blast_radius"`
	GuardianTriggers       []string   `json:"guardian_triggers"`
	RetentionPeriod        Duration   `json:"retention_period"`
	RequiresApproval       bool       `json:"requires_approval"`
	MaxRetries             int        `json:"max_retries"`
}

// Duration wraps time.Duration for JSON marshaling.
type Duration time.Duration

// PolicyTable is the canonical map of EffectType to EffectPolicy.
var PolicyTable = map[EffectType]EffectPolicy{
	EffectTypeDataWrite: {
		EffectType:            EffectTypeDataWrite,
		IdempotencyRequired:   true,
		RequiredEvidenceClass: []string{"content_hash", "schema_version"},
		ReplayabilityRequired: true,
		MaxBlastRadius:        1000,
		RetentionPeriod:       Duration(90 * 24 * time.Hour), // 90 days
		MaxRetries:            3,
	},
	EffectTypeFundsTransfer: {
		EffectType:             EffectTypeFundsTransfer,
		IdempotencyRequired:    true,
		RequiredEvidenceClass:  []string{"SLSA", "transaction_id", "amount_hash"},
		CorroborationThreshold: 2, // Requires dual approval
		ReplayabilityRequired:  true,
		MaxBlastRadius:         1,
		GuardianTriggers:       []string{"funds_guardian", "compliance_audit"},
		RetentionPeriod:        Duration(7 * 365 * 24 * time.Hour), // 7 years
		RequiresApproval:       true,
		MaxRetries:             1,
	},
	EffectTypePermissionChange: {
		EffectType:            EffectTypePermissionChange,
		IdempotencyRequired:   true,
		RequiredEvidenceClass: []string{"permission_diff", "approver_id"},
		ReplayabilityRequired: true,
		GuardianTriggers:      []string{"access_audit"},
		RetentionPeriod:       Duration(5 * 365 * 24 * time.Hour), // 5 years
		RequiresApproval:      true,
		MaxRetries:            1,
	},
	EffectTypeDeploy: {
		EffectType:            EffectTypeDeploy,
		IdempotencyRequired:   true,
		RequiredEvidenceClass: []string{"SLSA", "container_hash", "attestation"},
		ReplayabilityRequired: true,
		GuardianTriggers:      []string{"deploy_audit", "security_scan"},
		RetentionPeriod:       Duration(365 * 24 * time.Hour), // 1 year
		MaxRetries:            2,
	},
	EffectTypeModuleInstall: {
		EffectType:            EffectTypeModuleInstall,
		IdempotencyRequired:   true,
		RequiredEvidenceClass: []string{"attestation", "module_hash", "signature"},
		ReplayabilityRequired: true,
		GuardianTriggers:      []string{"module_audit"},
		RetentionPeriod:       Duration(365 * 24 * time.Hour), // 1 year
		RequiresApproval:      true,
		MaxRetries:            1,
	},
	EffectTypeNotify: {
		EffectType:            EffectTypeNotify,
		IdempotencyRequired:   false, // Notifications may be repeated
		RequiredEvidenceClass: []string{"message_hash"},
		ReplayabilityRequired: false,
		MaxBlastRadius:        100,
		RetentionPeriod:       Duration(30 * 24 * time.Hour), // 30 days
		MaxRetries:            5,
	},
	EffectTypeConfigChange: {
		EffectType:            EffectTypeConfigChange,
		IdempotencyRequired:   true,
		RequiredEvidenceClass: []string{"config_diff", "schema_version"},
		ReplayabilityRequired: true,
		GuardianTriggers:      []string{"config_audit"},
		RetentionPeriod:       Duration(365 * 24 * time.Hour), // 1 year
		MaxRetries:            2,
	},
	EffectTypeAuditLog: {
		EffectType:            EffectTypeAuditLog,
		IdempotencyRequired:   true,
		RequiredEvidenceClass: []string{"log_hash"},
		ReplayabilityRequired: false,                              // Audit logs are append-only
		RetentionPeriod:       Duration(7 * 365 * 24 * time.Hour), // 7 years
		MaxRetries:            10,                                 // High retry for critical audit logs
	},
	EffectTypeExternalAPICall: {
		EffectType:            EffectTypeExternalAPICall,
		IdempotencyRequired:   true,
		RequiredEvidenceClass: []string{"request_hash", "response_hash", "tool_fingerprint"},
		ReplayabilityRequired: true,
		MaxBlastRadius:        10,
		RetentionPeriod:       Duration(90 * 24 * time.Hour), // 90 days
		MaxRetries:            3,
	},
}

// GetPolicy retrieves the policy for a given effect type.
// Returns an error if no policy is defined.
func GetPolicy(effectType EffectType) (*EffectPolicy, error) {
	policy, ok := PolicyTable[effectType]
	if !ok {
		return nil, fmt.Errorf("no policy defined for effect type: %s", effectType)
	}
	return &policy, nil
}

// ListEffectTypes returns all registered effect types.
func ListEffectTypes() []EffectType {
	types := make([]EffectType, 0, len(PolicyTable))
	for t := range PolicyTable {
		types = append(types, t)
	}
	return types
}
