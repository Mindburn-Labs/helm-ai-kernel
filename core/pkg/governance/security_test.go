package governance

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ============================================================================
// Section H: Delegation Revocation Tests
// ============================================================================

func TestDelegationRevocationList(t *testing.T) {
	t.Run("create and revoke", func(t *testing.T) {
		drl := NewDelegationRevocationList()
		require.Equal(t, "1.0.0", drl.Version)
		require.Len(t, drl.Entries, 0)

		err := drl.Revoke("del-1", "admin", "policy violation")
		require.NoError(t, err)
		require.True(t, drl.IsRevoked("del-1"))
	})

	t.Run("duplicate revocation fails", func(t *testing.T) {
		drl := NewDelegationRevocationList()
		_ = drl.Revoke("del-1", "admin", "")

		err := drl.Revoke("del-1", "admin", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "already revoked")
	})

	t.Run("check unrevoked delegation", func(t *testing.T) {
		drl := NewDelegationRevocationList()
		require.False(t, drl.IsRevoked("unknown"))
	})

	t.Run("get entry", func(t *testing.T) {
		drl := NewDelegationRevocationList()
		_ = drl.Revoke("del-1", "admin", "test reason")

		entry, exists := drl.GetEntry("del-1")
		require.True(t, exists)
		require.Equal(t, "del-1", entry.DelegationID)
		require.Equal(t, "test reason", entry.Reason)
	})

	t.Run("prune expired", func(t *testing.T) {
		drl := NewDelegationRevocationList()
		_ = drl.Revoke("del-1", "admin", "")

		expired := time.Now().Add(-1 * time.Hour)
		drl.Entries["del-1"].ExpiresAt = &expired

		count := drl.PruneExpired()
		require.Equal(t, 1, count)
		require.False(t, drl.IsRevoked("del-1"))
	})
}

// ============================================================================
// Section I: Compensation Failure Tests
// ============================================================================

func TestCompensationState(t *testing.T) {
	t.Run("create state", func(t *testing.T) {
		cs := NewCompensationState("tx-1", "op-1", CompensationPolicyEscalate)
		require.Equal(t, "tx-1", cs.TransactionID)
		require.Equal(t, MaxCompensationAttempts, cs.MaxAttempts)
		require.Equal(t, 0, cs.AttemptCount)
	})

	t.Run("successful attempt", func(t *testing.T) {
		cs := NewCompensationState("tx-1", "op-1", CompensationPolicyEscalate)
		outcome := cs.RecordAttempt(true, "")
		require.Equal(t, CompensationOutcomeSuccess, outcome)
		require.Equal(t, 1, cs.AttemptCount)
	})

	t.Run("failed attempts with retry", func(t *testing.T) {
		cs := NewCompensationState("tx-1", "op-1", CompensationPolicyEscalate)

		outcome := cs.RecordAttempt(false, "error 1")
		require.Equal(t, CompensationOutcomeRetry, outcome)

		outcome = cs.RecordAttempt(false, "error 2")
		require.Equal(t, CompensationOutcomeRetry, outcome)

		outcome = cs.RecordAttempt(false, "error 3")
		require.Equal(t, CompensationOutcomeEscalate, outcome)
	})

	t.Run("escalation policy", func(t *testing.T) {
		cs := NewCompensationState("tx-1", "op-1", CompensationPolicyEscalate)
		cs.AttemptCount = MaxCompensationAttempts - 1

		outcome := cs.RecordAttempt(false, "final error")
		require.Equal(t, CompensationOutcomeEscalate, outcome)
		require.NotNil(t, cs.EscalatedAt)
		require.True(t, cs.NeedsIntervention())
	})

	t.Run("manual policy", func(t *testing.T) {
		cs := NewCompensationState("tx-1", "op-1", CompensationPolicyManual)
		cs.AttemptCount = MaxCompensationAttempts - 1

		outcome := cs.RecordAttempt(false, "")
		require.Equal(t, CompensationOutcomeManual, outcome)
		require.True(t, cs.NeedsIntervention())
	})

	t.Run("fallback policy", func(t *testing.T) {
		cs := NewCompensationState("tx-1", "op-1", CompensationPolicyFallback)
		cs.AttemptCount = MaxCompensationAttempts - 1

		outcome := cs.RecordAttempt(false, "")
		require.Equal(t, CompensationOutcomeFallback, outcome)
		require.True(t, cs.FallbackExecuted)
	})
}

// ============================================================================
// Section J: PDP Compromise Detection Tests
// ============================================================================

func TestPDPAttestation(t *testing.T) {
	t.Run("create attestation", func(t *testing.T) {
		att := NewPDPAttestation("pdp-1", 1*time.Hour)
		require.Equal(t, "pdp-1", att.PDPID)
		require.NotEmpty(t, att.AttestationID)
		require.Equal(t, PDPAttestationValid, att.Status)
		require.True(t, att.IsValid())
	})

	t.Run("expired attestation", func(t *testing.T) {
		att := NewPDPAttestation("pdp-1", -1*time.Hour) // Already expired
		require.False(t, att.IsValid())
	})

	t.Run("revoke attestation", func(t *testing.T) {
		att := NewPDPAttestation("pdp-1", 1*time.Hour)
		att.Revoke()
		require.Equal(t, PDPAttestationRevoked, att.Status)
		require.False(t, att.IsValid())
	})

	t.Run("mark suspect", func(t *testing.T) {
		att := NewPDPAttestation("pdp-1", 1*time.Hour)
		att.MarkSuspect()
		require.Equal(t, PDPAttestationSuspect, att.Status)
	})

	t.Run("mark compromised", func(t *testing.T) {
		att := NewPDPAttestation("pdp-1", 1*time.Hour)
		att.MarkCompromised()
		require.Equal(t, PDPAttestationCompromised, att.Status)
	})
}

func TestCompromiseDetector(t *testing.T) {
	t.Run("register attestation", func(t *testing.T) {
		cd := NewCompromiseDetector()
		att := NewPDPAttestation("pdp-1", 1*time.Hour)
		cd.RegisterAttestation(att)

		status := cd.GetPDPStatus("pdp-1")
		require.Equal(t, PDPAttestationValid, status)
	})

	t.Run("unknown PDP returns expired", func(t *testing.T) {
		cd := NewCompromiseDetector()
		status := cd.GetPDPStatus("unknown")
		require.Equal(t, PDPAttestationExpired, status)
	})

	t.Run("report anomaly", func(t *testing.T) {
		cd := NewCompromiseDetector()
		att := NewPDPAttestation("pdp-1", 1*time.Hour)
		cd.RegisterAttestation(att)

		anomaly := cd.ReportAnomaly("pdp-1", AnomalyTypeDecisionDrift, "decisions inconsistent", 5)
		require.NotEmpty(t, anomaly.AnomalyID)
		require.Equal(t, 5, anomaly.Severity)
	})

	t.Run("high severity triggers suspect", func(t *testing.T) {
		cd := NewCompromiseDetector()
		att := NewPDPAttestation("pdp-1", 1*time.Hour)
		cd.RegisterAttestation(att)

		// Report high severity anomaly (threshold is 7 for decision drift)
		cd.ReportAnomaly("pdp-1", AnomalyTypeDecisionDrift, "major drift", 8)

		status := cd.GetPDPStatus("pdp-1")
		require.Equal(t, PDPAttestationSuspect, status)
	})

	t.Run("should fail closed", func(t *testing.T) {
		cd := NewCompromiseDetector()
		att := NewPDPAttestation("pdp-1", 1*time.Hour)
		cd.RegisterAttestation(att)

		require.False(t, cd.ShouldFailClosed("pdp-1"))

		att.MarkSuspect()
		require.True(t, cd.ShouldFailClosed("pdp-1"))
	})

	t.Run("fail closed on compromised", func(t *testing.T) {
		cd := NewCompromiseDetector()
		att := NewPDPAttestation("pdp-1", 1*time.Hour)
		cd.RegisterAttestation(att)

		att.MarkCompromised()
		require.True(t, cd.ShouldFailClosed("pdp-1"))
	})

	t.Run("fail closed on revoked", func(t *testing.T) {
		cd := NewCompromiseDetector()
		att := NewPDPAttestation("pdp-1", 1*time.Hour)
		cd.RegisterAttestation(att)

		att.Revoke()
		require.True(t, cd.ShouldFailClosed("pdp-1"))
	})
}
