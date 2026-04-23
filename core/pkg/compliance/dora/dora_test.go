package dora

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewDORAComplianceEngine(t *testing.T) {
	entity := EntityInfo{
		LEI:          "529900HNOAA1KXQJZ9",
		Name:         "Test Financial Entity",
		Type:         "investment_firm",
		Jurisdiction: "BG",
		Regulators:   []string{"FSC"},
		ICTOfficer:   "John Doe",
		ContactEmail: "ict@test.com",
	}

	engine := NewDORAComplianceEngine(entity)
	require.NotNil(t, engine)
	require.Equal(t, entity.LEI, engine.entityInfo.LEI)
}

func TestRegisterRisk(t *testing.T) {
	engine := NewDORAComplianceEngine(EntityInfo{Name: "Test"})

	risk := &ICTRisk{
		Name:           "Network Vulnerability",
		Description:    "Unpatched firewall software",
		Level:          RiskLevelHigh,
		Category:       "network",
		AffectedAssets: []string{"fw-01", "fw-02"},
		MitigationPlan: "Patch to latest version",
		Owner:          "IT Security",
	}

	err := engine.RegisterRisk(context.Background(), risk)
	require.NoError(t, err)
	require.NotEmpty(t, risk.ID)
	require.Equal(t, "identified", risk.Status)
	require.False(t, risk.IdentifiedAt.IsZero())
}

func TestReportIncident(t *testing.T) {
	engine := NewDORAComplianceEngine(EntityInfo{Name: "Test"})

	incident := &ICTIncident{
		Type:             IncidentCyberAttack,
		Description:      "DDoS attack on trading platform",
		Severity:         RiskLevelCritical,
		AffectedServices: []string{"trading-api", "order-book"},
		AffectedClients:  1500,
	}

	err := engine.ReportIncident(context.Background(), incident)
	require.NoError(t, err)
	require.NotEmpty(t, incident.ID)
	require.False(t, incident.DetectedAt.IsZero())
}

func TestRegisterProvider(t *testing.T) {
	engine := NewDORAComplianceEngine(EntityInfo{Name: "Test"})

	provider := &ThirdPartyProvider{
		Name:           "AWS",
		ServiceType:    "cloud",
		Criticality:    RiskLevelCritical,
		ContractStart:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		ExitStrategy:   "Multi-cloud migration plan",
		Certifications: []string{"ISO27001", "SOC2"},
		Location:       "EU",
		DataResidency:  []string{"IE", "DE"},
	}

	err := engine.RegisterProvider(context.Background(), provider)
	require.NoError(t, err)
	require.NotEmpty(t, provider.ID)
}

func TestRecordResilienceTest(t *testing.T) {
	engine := NewDORAComplianceEngine(EntityInfo{Name: "Test"})

	test := &ResilienceTest{
		Type:        "pentest",
		Description: "Annual penetration test",
		Duration:    5 * 24 * time.Hour,
		Scope:       []string{"web-app", "api", "mobile"},
		Findings:    []string{"XSS in search", "SQL injection in login"},
		Remediated:  false,
	}

	err := engine.RecordResilienceTest(context.Background(), test)
	require.NoError(t, err)
	require.NotEmpty(t, test.ID)
	require.False(t, test.ExecutedAt.IsZero())
}

func TestGenerateROI(t *testing.T) {
	entity := EntityInfo{
		LEI:          "529900HNOAA1KXQJZ9",
		Name:         "Test Financial Entity",
		Type:         "investment_firm",
		Jurisdiction: "BG",
		Regulators:   []string{"FSC"},
	}

	engine := NewDORAComplianceEngine(entity)
	ctx := context.Background()

	// Register some data
	now := time.Now()
	periodStart := now.AddDate(0, -1, 0)
	periodEnd := now.AddDate(0, 1, 0)

	_ = engine.RegisterRisk(ctx, &ICTRisk{
		Name:  "Test Risk",
		Level: RiskLevelMedium,
	})

	_ = engine.ReportIncident(ctx, &ICTIncident{
		Type:     IncidentSystemFailure,
		Severity: RiskLevelLow,
	})

	_ = engine.RegisterProvider(ctx, &ThirdPartyProvider{
		Name:        "Test Cloud",
		ServiceType: "cloud",
	})

	_ = engine.RecordResilienceTest(ctx, &ResilienceTest{
		Type: "vulnerability_scan",
	})

	// Generate ROI
	roi, err := engine.GenerateROI(ctx, periodStart, periodEnd)
	require.NoError(t, err)
	require.NotNil(t, roi)
	require.NotEmpty(t, roi.ID)
	require.NotEmpty(t, roi.Hash)
	require.Len(t, roi.ICTRisks, 1)
	require.Len(t, roi.Incidents, 1)
	require.Len(t, roi.ThirdPartyProviders, 1)
	require.Len(t, roi.ResilienceTests, 1)
}

func TestExportROIJSON(t *testing.T) {
	engine := NewDORAComplianceEngine(EntityInfo{Name: "Test"})
	ctx := context.Background()

	roi, err := engine.GenerateROI(ctx, time.Now().AddDate(-1, 0, 0), time.Now())
	require.NoError(t, err)

	jsonData, err := engine.ExportROIJSON(ctx, roi)
	require.NoError(t, err)
	require.NotEmpty(t, jsonData)
	require.Contains(t, string(jsonData), "Test")
}

func TestGetComplianceStatus(t *testing.T) {
	engine := NewDORAComplianceEngine(EntityInfo{Name: "Test"})
	ctx := context.Background()

	// Initially should be compliant (no risks/incidents)
	status := engine.GetComplianceStatus(ctx)
	require.True(t, status.IsCompliant)
	require.Equal(t, 0, status.UnmitigatedCritical)

	// Add unmitigated critical risk
	_ = engine.RegisterRisk(ctx, &ICTRisk{
		Name:   "Critical Unmitigated",
		Level:  RiskLevelCritical,
		Status: "identified",
	})

	status = engine.GetComplianceStatus(ctx)
	require.False(t, status.IsCompliant)
	require.Equal(t, 1, status.UnmitigatedCritical)
}

func TestComplianceStatusWithUnreportedIncident(t *testing.T) {
	engine := NewDORAComplianceEngine(EntityInfo{Name: "Test"})
	ctx := context.Background()

	// Add critical incident not reported to NCAs
	_ = engine.ReportIncident(ctx, &ICTIncident{
		Type:           IncidentCyberAttack,
		Severity:       RiskLevelCritical,
		ReportedToNCAs: false,
	})

	status := engine.GetComplianceStatus(ctx)
	require.False(t, status.IsCompliant)
	require.Equal(t, 1, status.UnreportedIncidents)
}

func TestComplianceStatusWithOverdueAudit(t *testing.T) {
	engine := NewDORAComplianceEngine(EntityInfo{Name: "Test"})
	ctx := context.Background()

	// Add critical provider with overdue audit
	twoYearsAgo := time.Now().AddDate(-2, 0, 0)
	_ = engine.RegisterProvider(ctx, &ThirdPartyProvider{
		Name:        "Old Provider",
		Criticality: RiskLevelCritical,
		LastAudit:   &twoYearsAgo,
	})

	status := engine.GetComplianceStatus(ctx)
	require.False(t, status.IsCompliant)
	require.Equal(t, 1, status.OverdueAudits)
}

func TestRiskLevelConstants(t *testing.T) {
	require.Equal(t, RiskLevel("CRITICAL"), RiskLevelCritical)
	require.Equal(t, RiskLevel("HIGH"), RiskLevelHigh)
	require.Equal(t, RiskLevel("MEDIUM"), RiskLevelMedium)
	require.Equal(t, RiskLevel("LOW"), RiskLevelLow)
}

func TestIncidentTypeConstants(t *testing.T) {
	require.Equal(t, IncidentType("CYBER_ATTACK"), IncidentCyberAttack)
	require.Equal(t, IncidentType("SYSTEM_FAILURE"), IncidentSystemFailure)
	require.Equal(t, IncidentType("DATA_BREACH"), IncidentDataBreach)
	require.Equal(t, IncidentType("SERVICE_DISRUPTION"), IncidentServiceDisruption)
	require.Equal(t, IncidentType("THIRD_PARTY_FAILURE"), IncidentThirdPartyFailure)
}

func TestGenerateID(t *testing.T) {
	id1 := generateID("test")
	id2 := generateID("test")

	// Should generate unique IDs
	require.NotEqual(t, id1, id2)
	require.Contains(t, id1, "test-")
	require.Contains(t, id2, "test-")
}
