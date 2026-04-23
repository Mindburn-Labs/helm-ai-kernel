package euaiact

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------
// Engine Construction
// -----------------------------------------------------------------------

func TestNewEUAIActComplianceEngine(t *testing.T) {
	engine := NewEUAIActComplianceEngine()
	require.NotNil(t, engine)
	require.NotNil(t, engine.systems)
	require.NotNil(t, engine.riskRecords)
	require.NotNil(t, engine.incidents)
	require.NotNil(t, engine.transparency)
}

// -----------------------------------------------------------------------
// AI System Registration & Classification (Art.6 + Annex III)
// -----------------------------------------------------------------------

func TestRegisterAISystem(t *testing.T) {
	engine := NewEUAIActComplianceEngine()

	sys := &AISystem{
		Name:        "HELM Guardian",
		Provider:    "Mindburn Labs",
		Description: "AI execution firewall for agent governance",
	}

	err := engine.RegisterAISystem(context.Background(), sys)
	require.NoError(t, err)
	require.NotEmpty(t, sys.ID)
	require.Equal(t, RiskCategoryMinimal, sys.RiskCategory, "default risk category should be MINIMAL")
}

func TestRegisterAISystemWithExplicitID(t *testing.T) {
	engine := NewEUAIActComplianceEngine()

	sys := &AISystem{
		ID:           "custom-id-001",
		Name:         "Custom System",
		RiskCategory: RiskCategoryHigh,
	}

	err := engine.RegisterAISystem(context.Background(), sys)
	require.NoError(t, err)
	require.Equal(t, "custom-id-001", sys.ID)
}

func TestClassifyRisk_HighRiskViaAnnexIII(t *testing.T) {
	engine := NewEUAIActComplianceEngine()

	sys := &AISystem{
		ID:            "sys-critical",
		Name:          "Critical Infra AI",
		RiskCategory:  RiskCategoryMinimal,
		AnnexIIIAreas: []AnnexIIIArea{AnnexIIICriticalInfra},
	}
	_ = engine.RegisterAISystem(context.Background(), sys)

	category, err := engine.ClassifyRisk(context.Background(), "sys-critical")
	require.NoError(t, err)
	require.Equal(t, RiskCategoryHigh, category,
		"system in Annex III area must be classified HIGH regardless of declared category")
}

func TestClassifyRisk_MultipleAnnexIIIAreas(t *testing.T) {
	engine := NewEUAIActComplianceEngine()

	sys := &AISystem{
		ID:            "sys-multi",
		Name:          "Multi-area AI",
		AnnexIIIAreas: []AnnexIIIArea{AnnexIIICriticalInfra, AnnexIIIEssentialServices},
	}
	_ = engine.RegisterAISystem(context.Background(), sys)

	category, err := engine.ClassifyRisk(context.Background(), "sys-multi")
	require.NoError(t, err)
	require.Equal(t, RiskCategoryHigh, category)
}

func TestClassifyRisk_MinimalWithoutAnnexIII(t *testing.T) {
	engine := NewEUAIActComplianceEngine()

	sys := &AISystem{
		ID:           "sys-minimal",
		Name:         "Simple Chatbot",
		RiskCategory: RiskCategoryMinimal,
	}
	_ = engine.RegisterAISystem(context.Background(), sys)

	category, err := engine.ClassifyRisk(context.Background(), "sys-minimal")
	require.NoError(t, err)
	require.Equal(t, RiskCategoryMinimal, category)
}

func TestClassifyRisk_UnknownSystem(t *testing.T) {
	engine := NewEUAIActComplianceEngine()

	_, err := engine.ClassifyRisk(context.Background(), "nonexistent")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

// -----------------------------------------------------------------------
// Risk Management System (Art.9)
// -----------------------------------------------------------------------

func TestRecordRiskManagement(t *testing.T) {
	engine := NewEUAIActComplianceEngine()

	record := &RiskManagementRecord{
		AISystemID: "sys-001",
		RisksIdentified: []IdentifiedRisk{
			{Name: "Bias in outputs", Severity: "high", Mitigated: false},
		},
		MitigationMeasures: []string{"Debiasing pipeline"},
		TestingResults:     []string{"Fairness test passed at 0.92"},
	}

	err := engine.RecordRiskManagement(context.Background(), record)
	require.NoError(t, err)
	require.NotEmpty(t, record.ID)
	require.Equal(t, "active", record.Status)
	require.False(t, record.LastReviewDate.IsZero())
}

// -----------------------------------------------------------------------
// Incident Reporting (Art.62)
// -----------------------------------------------------------------------

func TestReportIncident(t *testing.T) {
	engine := NewEUAIActComplianceEngine()

	incident := &SeriousIncident{
		AISystemID:      "sys-001",
		Description:     "AI system produced discriminatory output",
		AffectedPersons: 500,
		Severity:        "critical",
	}

	err := engine.ReportIncident(context.Background(), incident)
	require.NoError(t, err)
	require.NotEmpty(t, incident.ID)
	require.False(t, incident.DetectedAt.IsZero())
}

func TestIncidentReportingDeadlineIs72Hours(t *testing.T) {
	require.Equal(t, 72*time.Hour, IncidentReportingDeadline,
		"Art.62 mandates 72-hour reporting deadline")
}

func TestIsIncidentReportOverdue_WithinDeadline(t *testing.T) {
	engine := NewEUAIActComplianceEngine()

	incident := &SeriousIncident{
		DetectedAt:          time.Now().Add(-1 * time.Hour), // 1 hour ago
		ReportedToAuthority: false,
	}

	require.False(t, engine.IsIncidentReportOverdue(incident),
		"incident detected 1h ago should not be overdue (72h deadline)")
}

func TestIsIncidentReportOverdue_PastDeadline(t *testing.T) {
	engine := NewEUAIActComplianceEngine()

	incident := &SeriousIncident{
		DetectedAt:          time.Now().Add(-73 * time.Hour), // 73 hours ago
		ReportedToAuthority: false,
	}

	require.True(t, engine.IsIncidentReportOverdue(incident),
		"incident detected 73h ago should be overdue (72h deadline)")
}

func TestIsIncidentReportOverdue_AlreadyReported(t *testing.T) {
	engine := NewEUAIActComplianceEngine()

	incident := &SeriousIncident{
		DetectedAt:          time.Now().Add(-100 * time.Hour),
		ReportedToAuthority: true,
	}

	require.False(t, engine.IsIncidentReportOverdue(incident),
		"already-reported incident should never be overdue")
}

// -----------------------------------------------------------------------
// Transparency (Art.50)
// -----------------------------------------------------------------------

func TestRecordTransparency(t *testing.T) {
	engine := NewEUAIActComplianceEngine()

	record := &TransparencyRecord{
		AISystemID:            "sys-001",
		AIGeneratedDisclosure: true,
		TrainingDataSummary:   "Public web corpus, curated datasets",
		ModelCapabilities:     "Text generation, reasoning",
		ModelLimitations:      "May hallucinate, context window limit",
		CopyrightCompliance:   true,
	}

	err := engine.RecordTransparency(context.Background(), record)
	require.NoError(t, err)
	require.NotEmpty(t, record.ID)
}

// -----------------------------------------------------------------------
// Obligation Categories
// -----------------------------------------------------------------------

func TestGetObligations_AllCategoriesPresent(t *testing.T) {
	engine := NewEUAIActComplianceEngine()
	obligations := engine.GetObligations()

	require.Len(t, obligations, 6, "should have 6 obligation categories")

	categories := make(map[ObligationCategory]bool)
	for _, o := range obligations {
		categories[o.Category] = true
	}

	require.True(t, categories[ObligationHighRiskClassification], "missing HIGH_RISK_CLASSIFICATION")
	require.True(t, categories[ObligationRiskManagement], "missing RISK_MANAGEMENT")
	require.True(t, categories[ObligationHumanOversight], "missing HUMAN_OVERSIGHT")
	require.True(t, categories[ObligationTransparency], "missing TRANSPARENCY")
	require.True(t, categories[ObligationIncidentReporting], "missing INCIDENT_REPORTING")
	require.True(t, categories[ObligationConformityAssessment], "missing CONFORMITY_ASSESSMENT")
}

func TestGetObligations_EffectiveDatesCorrect(t *testing.T) {
	engine := NewEUAIActComplianceEngine()
	obligations := engine.GetObligations()

	dateMap := make(map[ObligationCategory]time.Time)
	for _, o := range obligations {
		dateMap[o.Category] = o.EffectiveFrom
	}

	// Art.50 (Transparency) has the earliest date: 2025-08-02
	require.Equal(t, DateGPAITransparency, dateMap[ObligationTransparency],
		"Transparency obligation effective date must be 2025-08-02")

	// All other obligations use the high-risk deadline: 2026-08-02
	require.Equal(t, DateHighRiskObligations, dateMap[ObligationHighRiskClassification])
	require.Equal(t, DateHighRiskObligations, dateMap[ObligationRiskManagement])
	require.Equal(t, DateHighRiskObligations, dateMap[ObligationHumanOversight])
	require.Equal(t, DateHighRiskObligations, dateMap[ObligationIncidentReporting])
	require.Equal(t, DateHighRiskObligations, dateMap[ObligationConformityAssessment])
}

func TestGetObligations_AllHaveEvidenceReqs(t *testing.T) {
	engine := NewEUAIActComplianceEngine()
	for _, o := range engine.GetObligations() {
		require.NotEmpty(t, o.EvidenceReqs,
			"obligation %s must specify evidence requirements", o.Category)
	}
}

func TestGetObligations_AllHavePenalties(t *testing.T) {
	engine := NewEUAIActComplianceEngine()
	for _, o := range engine.GetObligations() {
		require.NotEmpty(t, o.PenaltyMax,
			"obligation %s must specify maximum penalty", o.Category)
	}
}

func TestGetObligations_AllHaveHELMImpact(t *testing.T) {
	engine := NewEUAIActComplianceEngine()
	for _, o := range engine.GetObligations() {
		require.NotEmpty(t, o.HELMImpact,
			"obligation %s must specify HELM impact mapping", o.Category)
	}
}

// -----------------------------------------------------------------------
// Enforcement Dates
// -----------------------------------------------------------------------

func TestEnforcementDates(t *testing.T) {
	require.Equal(t, time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC), DateProhibitedPractices,
		"Prohibited practices date must be 2025-02-02")
	require.Equal(t, time.Date(2025, 8, 2, 0, 0, 0, 0, time.UTC), DateGPAITransparency,
		"GPAI transparency date must be 2025-08-02")
	require.Equal(t, time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC), DateHighRiskObligations,
		"High-risk obligations date must be 2026-08-02")
	require.Equal(t, time.Date(2027, 8, 2, 0, 0, 0, 0, time.UTC), DateAnnexIHighRisk,
		"Annex I high-risk date must be 2027-08-02")
}

func TestEnforcementDatesChronologicalOrder(t *testing.T) {
	require.True(t, DateProhibitedPractices.Before(DateGPAITransparency))
	require.True(t, DateGPAITransparency.Before(DateHighRiskObligations))
	require.True(t, DateHighRiskObligations.Before(DateAnnexIHighRisk))
}

// -----------------------------------------------------------------------
// Human Oversight → Guardian Gate Mapping (Art.14)
// -----------------------------------------------------------------------

func TestDefaultHumanOversightMappings_Count(t *testing.T) {
	mappings := DefaultHumanOversightMappings()
	require.Len(t, mappings, 4, "Art.14 has 4 sub-requirements")
}

func TestDefaultHumanOversightMappings_AllHaveGates(t *testing.T) {
	for _, m := range DefaultHumanOversightMappings() {
		require.NotEmpty(t, m.GuardianGates,
			"mapping %s must reference at least one Guardian gate", m.Article14Ref)
	}
}

func TestHumanOversight_UnderstandCapabilities(t *testing.T) {
	mappings := DefaultHumanOversightMappings()
	var found *HumanOversightMapping
	for i := range mappings {
		if mappings[i].Requirement == "understand_capabilities" {
			found = &mappings[i]
			break
		}
	}
	require.NotNil(t, found, "must have understand_capabilities mapping")
	require.Equal(t, "Art.14(1)", found.Article14Ref)
	require.Contains(t, found.GuardianGates, GuardianGateContext)
	require.Contains(t, found.GuardianGates, GuardianGateIdentity)
}

func TestHumanOversight_MonitorOperation(t *testing.T) {
	mappings := DefaultHumanOversightMappings()
	var found *HumanOversightMapping
	for i := range mappings {
		if mappings[i].Requirement == "monitor_operation" {
			found = &mappings[i]
			break
		}
	}
	require.NotNil(t, found, "must have monitor_operation mapping")
	require.Equal(t, "Art.14(2)", found.Article14Ref)
	require.Contains(t, found.GuardianGates, GuardianGateContext)
	require.Contains(t, found.GuardianGates, GuardianGateThreat)
	require.Contains(t, found.GuardianGates, GuardianGateEgress)
}

func TestHumanOversight_InterveneInterrupt(t *testing.T) {
	mappings := DefaultHumanOversightMappings()
	var found *HumanOversightMapping
	for i := range mappings {
		if mappings[i].Requirement == "intervene_interrupt" {
			found = &mappings[i]
			break
		}
	}
	require.NotNil(t, found, "must have intervene_interrupt mapping")
	require.Equal(t, "Art.14(3)", found.Article14Ref)
	require.Contains(t, found.GuardianGates, GuardianGateFreeze,
		"intervention must map to Freeze gate (emergency halt)")
	require.Contains(t, found.GuardianGates, GuardianGateDelegation)
}

func TestHumanOversight_DecideNotToUse(t *testing.T) {
	mappings := DefaultHumanOversightMappings()
	var found *HumanOversightMapping
	for i := range mappings {
		if mappings[i].Requirement == "decide_not_to_use" {
			found = &mappings[i]
			break
		}
	}
	require.NotNil(t, found, "must have decide_not_to_use mapping")
	require.Equal(t, "Art.14(4)", found.Article14Ref)
	require.Contains(t, found.GuardianGates, GuardianGateFreeze,
		"decide-not-to-use must map to Freeze gate")
}

// -----------------------------------------------------------------------
// Annex III Area Constants
// -----------------------------------------------------------------------

func TestAnnexIIIAreaConstants(t *testing.T) {
	require.Equal(t, AnnexIIIArea("BIOMETRICS"), AnnexIIIBiometrics)
	require.Equal(t, AnnexIIIArea("CRITICAL_INFRASTRUCTURE"), AnnexIIICriticalInfra)
	require.Equal(t, AnnexIIIArea("EDUCATION"), AnnexIIIEducation)
	require.Equal(t, AnnexIIIArea("EMPLOYMENT"), AnnexIIIEmployment)
	require.Equal(t, AnnexIIIArea("ESSENTIAL_SERVICES"), AnnexIIIEssentialServices)
	require.Equal(t, AnnexIIIArea("LAW_ENFORCEMENT"), AnnexIIILawEnforcement)
	require.Equal(t, AnnexIIIArea("MIGRATION"), AnnexIIIMigration)
	require.Equal(t, AnnexIIIArea("JUSTICE"), AnnexIIIJustice)
}

func TestRiskCategoryConstants(t *testing.T) {
	require.Equal(t, RiskCategory("UNACCEPTABLE"), RiskCategoryUnacceptable)
	require.Equal(t, RiskCategory("HIGH"), RiskCategoryHigh)
	require.Equal(t, RiskCategory("LIMITED"), RiskCategoryLimited)
	require.Equal(t, RiskCategory("MINIMAL"), RiskCategoryMinimal)
}

// -----------------------------------------------------------------------
// Compliance Status
// -----------------------------------------------------------------------

func TestGetComplianceStatus_EmptyIsCompliant(t *testing.T) {
	engine := NewEUAIActComplianceEngine()
	status := engine.GetComplianceStatus(context.Background())

	require.True(t, status.IsCompliant, "empty engine should be compliant")
	require.Equal(t, 0, status.RegisteredSystems)
	require.Equal(t, 0, status.HighRiskSystems)
}

func TestGetComplianceStatus_HighRiskWithoutCEMarking(t *testing.T) {
	engine := NewEUAIActComplianceEngine()
	ctx := context.Background()

	_ = engine.RegisterAISystem(ctx, &AISystem{
		ID:             "sys-hr",
		Name:           "HR System",
		RiskCategory:   RiskCategoryHigh,
		AnnexIIIAreas:  []AnnexIIIArea{AnnexIIICriticalInfra},
		CEMarking:      false,
		EUDBRegistered: false,
	})

	status := engine.GetComplianceStatus(ctx)
	require.False(t, status.IsCompliant)
	require.Equal(t, 1, status.HighRiskSystems)
	require.Equal(t, 1, status.SystemsWithoutCEMarking)
	require.Equal(t, 1, status.SystemsWithoutEUDB)
}

func TestGetComplianceStatus_HighRiskFullyCompliant(t *testing.T) {
	engine := NewEUAIActComplianceEngine()
	ctx := context.Background()

	_ = engine.RegisterAISystem(ctx, &AISystem{
		ID:             "sys-compliant",
		Name:           "Compliant System",
		RiskCategory:   RiskCategoryHigh,
		AnnexIIIAreas:  []AnnexIIIArea{AnnexIIIEssentialServices},
		CEMarking:      true,
		EUDBRegistered: true,
	})

	// Add transparency record so there are no gaps.
	_ = engine.RecordTransparency(ctx, &TransparencyRecord{
		AISystemID:            "sys-compliant",
		AIGeneratedDisclosure: true,
		TrainingDataSummary:   "summary",
	})

	status := engine.GetComplianceStatus(ctx)
	require.True(t, status.IsCompliant)
	require.Equal(t, 1, status.HighRiskSystems)
	require.Equal(t, 0, status.SystemsWithoutCEMarking)
	require.Equal(t, 0, status.SystemsWithoutEUDB)
	require.Equal(t, 0, status.TransparencyGaps)
}

func TestGetComplianceStatus_OverdueRiskReview(t *testing.T) {
	engine := NewEUAIActComplianceEngine()
	ctx := context.Background()

	_ = engine.RecordRiskManagement(ctx, &RiskManagementRecord{
		AISystemID:     "sys-001",
		NextReviewDate: time.Now().AddDate(0, -1, 0), // 1 month overdue
	})

	status := engine.GetComplianceStatus(ctx)
	require.False(t, status.IsCompliant)
	require.Equal(t, 1, status.OverdueRiskReviews)
}

func TestGetComplianceStatus_UnreportedIncident(t *testing.T) {
	engine := NewEUAIActComplianceEngine()
	ctx := context.Background()

	_ = engine.ReportIncident(ctx, &SeriousIncident{
		AISystemID:          "sys-001",
		Description:         "Serious malfunction",
		DetectedAt:          time.Now().Add(-1 * time.Hour), // within deadline
		ReportedToAuthority: false,
	})

	status := engine.GetComplianceStatus(ctx)
	require.Equal(t, 1, status.UnreportedIncidents)
	require.Equal(t, 0, status.OverdueIncidentReports, "within 72h so not overdue")
}

func TestGetComplianceStatus_OverdueIncidentReport(t *testing.T) {
	engine := NewEUAIActComplianceEngine()
	ctx := context.Background()

	_ = engine.ReportIncident(ctx, &SeriousIncident{
		AISystemID:          "sys-001",
		Description:         "Serious malfunction",
		DetectedAt:          time.Now().Add(-100 * time.Hour), // way past 72h
		ReportedToAuthority: false,
	})

	status := engine.GetComplianceStatus(ctx)
	require.False(t, status.IsCompliant)
	require.Equal(t, 1, status.UnreportedIncidents)
	require.Equal(t, 1, status.OverdueIncidentReports)
}

func TestGetComplianceStatus_TransparencyGap(t *testing.T) {
	engine := NewEUAIActComplianceEngine()
	ctx := context.Background()

	// Register a HIGH system without a transparency record.
	_ = engine.RegisterAISystem(ctx, &AISystem{
		ID:             "sys-notransparency",
		Name:           "Opaque System",
		RiskCategory:   RiskCategoryHigh,
		CEMarking:      true,
		EUDBRegistered: true,
	})

	status := engine.GetComplianceStatus(ctx)
	require.False(t, status.IsCompliant)
	require.Equal(t, 1, status.TransparencyGaps)
}

// -----------------------------------------------------------------------
// Export
// -----------------------------------------------------------------------

func TestExportComplianceJSON(t *testing.T) {
	engine := NewEUAIActComplianceEngine()
	ctx := context.Background()

	_ = engine.RegisterAISystem(ctx, &AISystem{
		Name: "Test System",
	})

	data, err := engine.ExportComplianceJSON(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, data)
	require.Contains(t, string(data), "is_compliant")
}

// -----------------------------------------------------------------------
// ID Generation
// -----------------------------------------------------------------------

func TestGenerateID_Unique(t *testing.T) {
	id1 := generateID("test")
	id2 := generateID("test")

	require.NotEqual(t, id1, id2)
	require.Contains(t, id1, "test-")
	require.Contains(t, id2, "test-")
}
