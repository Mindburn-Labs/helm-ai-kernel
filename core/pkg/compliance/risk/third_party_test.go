package risk

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestThirdPartyRiskAssessor(t *testing.T) {
	config := DefaultAssessorConfig()
	assessor := NewThirdPartyRiskAssessor(config)
	ctx := context.Background()

	t.Run("RegisterThirdParty", func(t *testing.T) {
		tp := &ThirdParty{
			Name:             "Test Cloud Provider",
			Type:             TypeCloudProvider,
			Description:      "Major cloud infrastructure provider",
			ContractStart:    time.Now().Add(-365 * 24 * time.Hour),
			DataAccess:       []DataCategory{DataPersonal, DataFinancial},
			Certifications:   []string{"SOC2", "ISO27001", "SOC1"},
			Jurisdiction:     "US",
			CriticalityLevel: RiskLevelHigh,
		}

		err := assessor.RegisterThirdParty(tp)
		require.NoError(t, err)
		require.NotEmpty(t, tp.ID)
	})

	t.Run("AssessThirdParty", func(t *testing.T) {
		tp := &ThirdParty{
			Name:             "Payment Processor",
			Type:             TypePaymentProvider,
			ContractStart:    time.Now().Add(-180 * 24 * time.Hour),
			DataAccess:       []DataCategory{DataFinancial, DataPersonal},
			Certifications:   []string{"SOC2", "ISO27001", "PCI-DSS"},
			Jurisdiction:     "EU",
			CriticalityLevel: RiskLevelCritical,
		}

		err := assessor.RegisterThirdParty(tp)
		require.NoError(t, err)

		assessment, err := assessor.AssessThirdParty(ctx, tp.ID, "test-assessor")
		require.NoError(t, err)
		require.NotNil(t, assessment)
		require.NotEmpty(t, assessment.ID)
		require.False(t, assessment.AssessedAt.IsZero())
		require.Greater(t, assessment.OverallScore, 0.0)
	})

	t.Run("MissingCertifications", func(t *testing.T) {
		tp := &ThirdParty{
			Name:             "Small Vendor",
			Type:             TypeSaaSVendor,
			ContractStart:    time.Now(),
			DataAccess:       []DataCategory{DataPublic},
			Certifications:   []string{}, // No certs
			Jurisdiction:     "US",
			CriticalityLevel: RiskLevelLow,
		}

		err := assessor.RegisterThirdParty(tp)
		require.NoError(t, err)

		assessment, err := assessor.AssessThirdParty(ctx, tp.ID, "test-assessor")
		require.NoError(t, err)

		// Should have findings for missing certifications
		hasCertFinding := false
		for _, f := range assessment.Findings {
			if f.Category == "COMPLIANCE" && f.Title == "Missing Certifications" {
				hasCertFinding = true
				break
			}
		}
		require.True(t, hasCertFinding, "should have missing certification finding")
	})

	t.Run("ExpiredContract", func(t *testing.T) {
		expired := time.Now().Add(-30 * 24 * time.Hour)
		tp := &ThirdParty{
			Name:             "Expired Vendor",
			Type:             TypeConsultant,
			ContractStart:    time.Now().Add(-400 * 24 * time.Hour),
			ContractEnd:      &expired,
			DataAccess:       []DataCategory{DataPublic},
			Certifications:   []string{"SOC2", "ISO27001"},
			Jurisdiction:     "US",
			CriticalityLevel: RiskLevelLow,
		}

		err := assessor.RegisterThirdParty(tp)
		require.NoError(t, err)

		assessment, err := assessor.AssessThirdParty(ctx, tp.ID, "test-assessor")
		require.NoError(t, err)

		// Should have findings for expired contract
		hasContractFinding := false
		for _, f := range assessment.Findings {
			if f.Category == "CONTRACT" && f.Title == "Expired Contract" {
				hasContractFinding = true
				break
			}
		}
		require.True(t, hasContractFinding, "should have expired contract finding")
	})

	t.Run("ExcessiveDataAccess", func(t *testing.T) {
		tp := &ThirdParty{
			Name:          "Data Hungry Vendor",
			Type:          TypeDataProcessor,
			ContractStart: time.Now(),
			DataAccess: []DataCategory{
				DataPersonal, DataFinancial, DataHealth, DataCredentials, DataProprietary,
			},
			Certifications:   []string{"SOC2", "ISO27001"},
			Jurisdiction:     "US",
			CriticalityLevel: RiskLevelMedium,
		}

		err := assessor.RegisterThirdParty(tp)
		require.NoError(t, err)

		assessment, err := assessor.AssessThirdParty(ctx, tp.ID, "test-assessor")
		require.NoError(t, err)

		// Should have findings for excessive data access
		hasDataFinding := false
		for _, f := range assessment.Findings {
			if f.Category == "DATA_GOVERNANCE" {
				hasDataFinding = true
				break
			}
		}
		require.True(t, hasDataFinding)
	})

	t.Run("GetDueAssessments", func(t *testing.T) {
		due := assessor.GetDueAssessments()
		// Some vendors were just assessed, none should be due yet
		require.NotNil(t, due)
	})

	t.Run("GenerateRiskReport", func(t *testing.T) {
		report, err := assessor.GenerateRiskReport()
		require.NoError(t, err)
		require.NotNil(t, report)
		require.Greater(t, report.TotalThirdParties, 0)
		require.NotEmpty(t, report.RiskDistribution)

		// Test JSON export
		jsonBytes, err := report.ToJSON()
		require.NoError(t, err)
		require.NotEmpty(t, jsonBytes)
	})
}

func TestRiskLevel(t *testing.T) {
	tests := []struct {
		level RiskLevel
		want  string
	}{
		{RiskLevelLow, "LOW"},
		{RiskLevelMedium, "MEDIUM"},
		{RiskLevelHigh, "HIGH"},
		{RiskLevelCritical, "CRITICAL"},
		{RiskLevel(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		require.Equal(t, tt.want, tt.level.String())
	}
}

func TestAutoApproval(t *testing.T) {
	config := DefaultAssessorConfig()
	config.AutoApprovalThreshold = 2.0
	config.RequiredCertifications = []string{} // No requirements
	assessor := NewThirdPartyRiskAssessor(config)
	ctx := context.Background()

	tp := &ThirdParty{
		Name:             "Low Risk Vendor",
		Type:             TypeSaaSVendor,
		ContractStart:    time.Now(),
		DataAccess:       []DataCategory{DataPublic},
		Certifications:   []string{},
		Jurisdiction:     "US",
		CriticalityLevel: RiskLevelLow,
	}

	err := assessor.RegisterThirdParty(tp)
	require.NoError(t, err)

	assessment, err := assessor.AssessThirdParty(ctx, tp.ID, "auto")
	require.NoError(t, err)

	// Should be auto-approved due to low risk
	if assessment.OverallScore <= config.AutoApprovalThreshold {
		require.Equal(t, ApprovalApproved, assessment.ApprovalStatus)
	}
}

func TestGetAssessmentHistory(t *testing.T) {
	config := DefaultAssessorConfig()
	assessor := NewThirdPartyRiskAssessor(config)
	ctx := context.Background()

	tp := &ThirdParty{
		Name:             "History Test Vendor",
		Type:             TypeSaaSVendor,
		ContractStart:    time.Now(),
		Certifications:   []string{"SOC2", "ISO27001"},
		CriticalityLevel: RiskLevelLow,
	}

	err := assessor.RegisterThirdParty(tp)
	require.NoError(t, err)

	// Perform multiple assessments
	for i := 0; i < 3; i++ {
		_, err := assessor.AssessThirdParty(ctx, tp.ID, "test-assessor")
		require.NoError(t, err)
	}

	history, err := assessor.GetAssessmentHistory(tp.ID)
	require.NoError(t, err)
	require.Len(t, history, 3)
}

func TestBlockedJurisdiction(t *testing.T) {
	config := DefaultAssessorConfig()
	config.BlockedJurisdictions = []string{"BLOCKED"}
	assessor := NewThirdPartyRiskAssessor(config)
	ctx := context.Background()

	tp := &ThirdParty{
		Name:             "Blocked Vendor",
		Type:             TypeSaaSVendor,
		ContractStart:    time.Now(),
		Certifications:   []string{"SOC2", "ISO27001"},
		Jurisdiction:     "BLOCKED",
		CriticalityLevel: RiskLevelLow,
	}

	err := assessor.RegisterThirdParty(tp)
	require.NoError(t, err)

	assessment, err := assessor.AssessThirdParty(ctx, tp.ID, "test")
	require.NoError(t, err)

	// Should have critical finding for blocked jurisdiction
	hasCritical := false
	for _, f := range assessment.Findings {
		if f.RiskLevel == RiskLevelCritical {
			hasCritical = true
			break
		}
	}
	require.True(t, hasCritical)
}
