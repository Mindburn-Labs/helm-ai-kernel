package policies

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyTable_AllEffectTypesHavePolicies(t *testing.T) {
	expectedTypes := []EffectType{
		EffectTypeDataWrite,
		EffectTypeFundsTransfer,
		EffectTypePermissionChange,
		EffectTypeDeploy,
		EffectTypeNotify,
		EffectTypeModuleInstall,
		EffectTypeConfigChange,
		EffectTypeAuditLog,
		EffectTypeExternalAPICall,
	}

	for _, et := range expectedTypes {
		policy, err := GetPolicy(et)
		require.NoError(t, err, "Policy should exist for %s", et)
		assert.Equal(t, et, policy.EffectType)
	}
}

func TestPolicyTable_FundsTransferRequiresCorroboration(t *testing.T) {
	policy, err := GetPolicy(EffectTypeFundsTransfer)
	require.NoError(t, err)

	assert.True(t, policy.IdempotencyRequired)
	assert.Equal(t, 2, policy.CorroborationThreshold)
	assert.True(t, policy.RequiresApproval)
	assert.Contains(t, policy.GuardianTriggers, "funds_guardian")
}

func TestPolicyTable_DataWriteRequiresIdempotency(t *testing.T) {
	policy, err := GetPolicy(EffectTypeDataWrite)
	require.NoError(t, err)

	assert.True(t, policy.IdempotencyRequired)
	assert.True(t, policy.ReplayabilityRequired)
	assert.Contains(t, policy.RequiredEvidenceClass, "content_hash")
}

func TestPolicyTable_NotifyDoesNotRequireIdempotency(t *testing.T) {
	policy, err := GetPolicy(EffectTypeNotify)
	require.NoError(t, err)

	assert.False(t, policy.IdempotencyRequired)
	assert.False(t, policy.ReplayabilityRequired)
}

func TestPolicyEnforcer_ValidatePrerequisites(t *testing.T) {
	enforcer := NewPolicyEnforcer(true)

	t.Run("Valid DATA_WRITE effect passes", func(t *testing.T) {
		effect := &Effect{
			EffectID:       "eff-1",
			EffectType:     EffectTypeDataWrite,
			IdempotencyKey: "idem-key-123",
			Principal:      "user@example.com",
			Target:         "/data/users",
		}

		err := enforcer.ValidatePrerequisites(effect)
		assert.NoError(t, err)
	})

	t.Run("DATA_WRITE without idempotency key fails", func(t *testing.T) {
		effect := &Effect{
			EffectID:   "eff-2",
			EffectType: EffectTypeDataWrite,
			// Missing IdempotencyKey
			Principal: "user@example.com",
			Target:    "/data/users",
		}

		err := enforcer.ValidatePrerequisites(effect)
		assert.Error(t, err)

		var prereqErr *PrerequisiteError
		require.ErrorAs(t, err, &prereqErr)
		assert.Contains(t, prereqErr.Violations, "idempotency_key required")
	})

	t.Run("FUNDS_TRANSFER without approvals fails", func(t *testing.T) {
		effect := &Effect{
			EffectID:       "eff-3",
			EffectType:     EffectTypeFundsTransfer,
			IdempotencyKey: "idem-key-456",
			Principal:      "user@example.com",
			Target:         "/funds/transfer",
			// Missing Approvals - requires 2
		}

		err := enforcer.ValidatePrerequisites(effect)
		assert.Error(t, err)

		var prereqErr *PrerequisiteError
		require.ErrorAs(t, err, &prereqErr)
		assert.Len(t, prereqErr.Violations, 2) // Missing approval + corroboration
	})

	t.Run("FUNDS_TRANSFER with sufficient approvals passes", func(t *testing.T) {
		effect := &Effect{
			EffectID:       "eff-4",
			EffectType:     EffectTypeFundsTransfer,
			IdempotencyKey: "idem-key-789",
			Principal:      "user@example.com",
			Target:         "/funds/transfer",
			Approvals: []Approval{
				{ApproverID: "approver-1", ApprovedAt: time.Now()},
				{ApproverID: "approver-2", ApprovedAt: time.Now()},
			},
		}

		err := enforcer.ValidatePrerequisites(effect)
		assert.NoError(t, err)
	})
}

func TestPolicyEnforcer_ValidateReceipt(t *testing.T) {
	enforcer := NewPolicyEnforcer(true)

	t.Run("Valid receipt passes", func(t *testing.T) {
		effect := &Effect{
			EffectID:       "eff-1",
			EffectType:     EffectTypeDataWrite,
			IdempotencyKey: "idem-key-123",
		}

		receipt := &Receipt{
			ReceiptID:      "rcpt-1",
			EffectID:       "eff-1",
			EffectType:     EffectTypeDataWrite,
			Status:         ReceiptStatusSuccess,
			ContentHash:    "sha256:abc123",
			IdempotencyKey: "idem-key-123",
			Evidence: map[string]string{
				"content_hash":   "sha256:abc123",
				"schema_version": "1.0.0",
			},
		}

		err := enforcer.ValidateReceipt(receipt, effect)
		assert.NoError(t, err)
	})

	t.Run("Receipt missing evidence fails", func(t *testing.T) {
		effect := &Effect{
			EffectID:       "eff-2",
			EffectType:     EffectTypeDataWrite,
			IdempotencyKey: "idem-key-456",
		}

		receipt := &Receipt{
			ReceiptID:      "rcpt-2",
			EffectID:       "eff-2",
			EffectType:     EffectTypeDataWrite,
			Status:         ReceiptStatusSuccess,
			ContentHash:    "sha256:def456",
			IdempotencyKey: "idem-key-456",
			Evidence:       map[string]string{
				// Missing content_hash and schema_version
			},
		}

		err := enforcer.ValidateReceipt(receipt, effect)
		assert.Error(t, err)

		var receiptErr *ReceiptError
		require.ErrorAs(t, err, &receiptErr)
		assert.Contains(t, receiptErr.Violations[0], "missing evidence")
	})

	t.Run("Exceeded max retries fails", func(t *testing.T) {
		effect := &Effect{
			EffectID:       "eff-3",
			EffectType:     EffectTypeDataWrite,
			IdempotencyKey: "idem-key-789",
		}

		receipt := &Receipt{
			ReceiptID:      "rcpt-3",
			EffectID:       "eff-3",
			EffectType:     EffectTypeDataWrite,
			Status:         ReceiptStatusFailed,
			ContentHash:    "sha256:ghi789",
			IdempotencyKey: "idem-key-789",
			RetryCount:     5, // Exceeds max of 3 for DATA_WRITE
			Evidence: map[string]string{
				"content_hash":   "sha256:ghi789",
				"schema_version": "1.0.0",
			},
		}

		err := enforcer.ValidateReceipt(receipt, effect)
		assert.Error(t, err)

		var receiptErr *ReceiptError
		require.ErrorAs(t, err, &receiptErr)
		assert.Contains(t, receiptErr.Violations[0], "exceeded max retries")
	})

	t.Run("Tool fingerprint mismatch fails", func(t *testing.T) {
		effect := &Effect{
			EffectID:        "eff-4",
			EffectType:      EffectTypeExternalAPICall,
			IdempotencyKey:  "idem-key-abc",
			ToolFingerprint: "fingerprint-original",
		}

		receipt := &Receipt{
			ReceiptID:       "rcpt-4",
			EffectID:        "eff-4",
			EffectType:      EffectTypeExternalAPICall,
			Status:          ReceiptStatusSuccess,
			ContentHash:     "sha256:jkl012",
			IdempotencyKey:  "idem-key-abc",
			ToolFingerprint: "fingerprint-different", // Changed!
			Evidence: map[string]string{
				"request_hash":     "hash1",
				"response_hash":    "hash2",
				"tool_fingerprint": "fingerprint-different",
			},
		}

		err := enforcer.ValidateReceipt(receipt, effect)
		assert.Error(t, err)

		var receiptErr *ReceiptError
		require.ErrorAs(t, err, &receiptErr)
		assert.Contains(t, receiptErr.Violations[0], "tool_fingerprint mismatch")
	})
}

func TestPolicyEnforcer_BypassAttemptsMustFail(t *testing.T) {
	enforcer := NewPolicyEnforcer(true)

	// These are intentional bypass attempts that MUST fail

	t.Run("FUNDS_TRANSFER with forged single approval fails", func(t *testing.T) {
		effect := &Effect{
			EffectID:       "bypass-1",
			EffectType:     EffectTypeFundsTransfer,
			IdempotencyKey: "bypass-key",
			Approvals: []Approval{
				{ApproverID: "attacker", ApprovedAt: time.Now()},
				// Only 1 approval, needs 2
			},
		}

		err := enforcer.ValidatePrerequisites(effect)
		assert.Error(t, err, "Bypass with insufficient approvals MUST fail")
	})

	t.Run("PERMISSION_CHANGE without approval fails", func(t *testing.T) {
		effect := &Effect{
			EffectID:       "bypass-2",
			EffectType:     EffectTypePermissionChange,
			IdempotencyKey: "bypass-key-2",
			// Missing approval
		}

		err := enforcer.ValidatePrerequisites(effect)
		assert.Error(t, err, "Bypass without approval MUST fail")
	})

	t.Run("MODULE_INSTALL without approval fails", func(t *testing.T) {
		effect := &Effect{
			EffectID:       "bypass-3",
			EffectType:     EffectTypeModuleInstall,
			IdempotencyKey: "bypass-key-3",
			// Missing approval
		}

		err := enforcer.ValidatePrerequisites(effect)
		assert.Error(t, err, "Bypass without approval MUST fail")
	})

	t.Run("Unknown effect type in strict mode fails", func(t *testing.T) {
		effect := &Effect{
			EffectID:   "bypass-4",
			EffectType: EffectType("UNKNOWN_DANGEROUS_TYPE"),
		}

		err := enforcer.ValidatePrerequisites(effect)
		assert.Error(t, err, "Unknown effect type in strict mode MUST fail")
	})
}

func TestPolicyEnforcer_NonStrictMode(t *testing.T) {
	enforcer := NewPolicyEnforcer(false) // Non-strict

	t.Run("Unknown effect type in non-strict mode uses defaults", func(t *testing.T) {
		effect := &Effect{
			EffectID:   "test-1",
			EffectType: EffectType("CUSTOM_TYPE"),
		}

		err := enforcer.ValidatePrerequisites(effect)
		assert.NoError(t, err, "Non-strict mode should allow unknown types")
	})
}

func TestGetRetentionPeriod(t *testing.T) {
	enforcer := NewPolicyEnforcer(true)

	t.Run("FUNDS_TRANSFER has 7 year retention", func(t *testing.T) {
		retention := enforcer.GetRetentionPeriod(EffectTypeFundsTransfer)
		expectedYears := 7
		expectedDuration := time.Duration(expectedYears) * 365 * 24 * time.Hour
		assert.Equal(t, expectedDuration, retention)
	})

	t.Run("NOTIFY has 30 day retention", func(t *testing.T) {
		retention := enforcer.GetRetentionPeriod(EffectTypeNotify)
		expectedDays := 30
		expectedDuration := time.Duration(expectedDays) * 24 * time.Hour
		assert.Equal(t, expectedDuration, retention)
	})
}

func TestGetGuardianTriggers(t *testing.T) {
	enforcer := NewPolicyEnforcer(true)

	t.Run("DEPLOY triggers security scan", func(t *testing.T) {
		triggers := enforcer.GetGuardianTriggers(EffectTypeDeploy)
		assert.Contains(t, triggers, "security_scan")
		assert.Contains(t, triggers, "deploy_audit")
	})

	t.Run("NOTIFY has no triggers", func(t *testing.T) {
		triggers := enforcer.GetGuardianTriggers(EffectTypeNotify)
		assert.Empty(t, triggers)
	})
}
