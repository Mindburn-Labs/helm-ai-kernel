package euaiact

import (
	"context"
	"testing"
	"time"
)

// ── Risk Classification ──

func TestClassifyRisk_HighForAnnexIII(t *testing.T) {
	e := NewEUAIActComplianceEngine()
	sys := &AISystem{ID: "s1", Name: "Bio-ID", AnnexIIIAreas: []AnnexIIIArea{AnnexIIIBiometrics}}
	e.RegisterAISystem(context.Background(), sys)
	cat, err := e.ClassifyRisk(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if cat != RiskCategoryHigh {
		t.Fatalf("expected HIGH, got %s", cat)
	}
}

func TestClassifyRisk_MinimalDefault(t *testing.T) {
	e := NewEUAIActComplianceEngine()
	sys := &AISystem{ID: "s2", Name: "Chatbot"}
	e.RegisterAISystem(context.Background(), sys)
	cat, _ := e.ClassifyRisk(context.Background(), "s2")
	if cat != RiskCategoryMinimal {
		t.Fatalf("expected MINIMAL, got %s", cat)
	}
}

func TestClassifyRisk_NotFound(t *testing.T) {
	e := NewEUAIActComplianceEngine()
	_, err := e.ClassifyRisk(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown system")
	}
}

// ── Annex III Areas Coverage ──

func TestAnnexIII_AllAreas(t *testing.T) {
	areas := []AnnexIIIArea{
		AnnexIIIBiometrics, AnnexIIICriticalInfra, AnnexIIIEducation,
		AnnexIIIEmployment, AnnexIIIEssentialServices, AnnexIIILawEnforcement,
		AnnexIIIMigration, AnnexIIIJustice,
	}
	e := NewEUAIActComplianceEngine()
	for i, area := range areas {
		sys := &AISystem{ID: string(area), Name: "test", AnnexIIIAreas: []AnnexIIIArea{area}}
		e.RegisterAISystem(context.Background(), sys)
		cat, _ := e.ClassifyRisk(context.Background(), string(area))
		if cat != RiskCategoryHigh {
			t.Fatalf("area %d (%s) should classify as HIGH", i, area)
		}
	}
}

// ── Registration ──

func TestRegister_AutoGeneratesID(t *testing.T) {
	e := NewEUAIActComplianceEngine()
	sys := &AISystem{Name: "NoID"}
	e.RegisterAISystem(context.Background(), sys)
	if sys.ID == "" {
		t.Fatal("expected auto-generated ID")
	}
}

func TestRegister_DefaultsToMinimal(t *testing.T) {
	e := NewEUAIActComplianceEngine()
	sys := &AISystem{ID: "s1"}
	e.RegisterAISystem(context.Background(), sys)
	if sys.RiskCategory != RiskCategoryMinimal {
		t.Fatalf("expected MINIMAL default, got %s", sys.RiskCategory)
	}
}

// ── Enforcement Dates ──

func TestEnforcementDate_ProhibitedPractices(t *testing.T) {
	expected := time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC)
	if !DateProhibitedPractices.Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, DateProhibitedPractices)
	}
}

func TestEnforcementDate_GPAITransparency(t *testing.T) {
	expected := time.Date(2025, 8, 2, 0, 0, 0, 0, time.UTC)
	if !DateGPAITransparency.Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, DateGPAITransparency)
	}
}

func TestEnforcementDate_HighRiskObligations(t *testing.T) {
	expected := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	if !DateHighRiskObligations.Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, DateHighRiskObligations)
	}
}

func TestEnforcementDate_AnnexI(t *testing.T) {
	expected := time.Date(2027, 8, 2, 0, 0, 0, 0, time.UTC)
	if !DateAnnexIHighRisk.Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, DateAnnexIHighRisk)
	}
}

// ── Incident Reporting ──

func TestIncidentReportOverdue_72h(t *testing.T) {
	e := NewEUAIActComplianceEngine()
	inc := &SeriousIncident{ID: "i1", DetectedAt: time.Now().Add(-73 * time.Hour)}
	if !e.IsIncidentReportOverdue(inc) {
		t.Fatal("incident detected >72h ago should be overdue")
	}
}

func TestIncidentReportNotOverdue(t *testing.T) {
	e := NewEUAIActComplianceEngine()
	inc := &SeriousIncident{ID: "i2", DetectedAt: time.Now().Add(-1 * time.Hour)}
	if e.IsIncidentReportOverdue(inc) {
		t.Fatal("incident detected 1h ago should not be overdue")
	}
}

func TestIncidentReportAlreadyReported(t *testing.T) {
	e := NewEUAIActComplianceEngine()
	inc := &SeriousIncident{ID: "i3", DetectedAt: time.Now().Add(-100 * time.Hour), ReportedToAuthority: true}
	if e.IsIncidentReportOverdue(inc) {
		t.Fatal("already reported incident should not be overdue")
	}
}

// ── Obligations ──

func TestGetObligations_Count(t *testing.T) {
	e := NewEUAIActComplianceEngine()
	obligations := e.GetObligations()
	if len(obligations) != 6 {
		t.Fatalf("expected 6 obligations, got %d", len(obligations))
	}
}

func TestGetObligations_IncidentReportingDeadline(t *testing.T) {
	if IncidentReportingDeadline != 72*time.Hour {
		t.Fatalf("expected 72h, got %v", IncidentReportingDeadline)
	}
}

// ── Compliance Status ──

func TestComplianceStatus_CompliantEmpty(t *testing.T) {
	e := NewEUAIActComplianceEngine()
	status := e.GetComplianceStatus(context.Background())
	if !status.IsCompliant {
		t.Fatal("empty engine should be compliant")
	}
}

func TestComplianceStatus_NonCompliantMissingCE(t *testing.T) {
	e := NewEUAIActComplianceEngine()
	e.RegisterAISystem(context.Background(), &AISystem{
		ID: "s1", RiskCategory: RiskCategoryHigh, CEMarking: false, EUDBRegistered: true,
	})
	status := e.GetComplianceStatus(context.Background())
	if status.IsCompliant {
		t.Fatal("system without CE marking should be non-compliant")
	}
	if status.SystemsWithoutCEMarking != 1 {
		t.Fatalf("expected 1 system without CE, got %d", status.SystemsWithoutCEMarking)
	}
}

func TestComplianceStatus_TransparencyGap(t *testing.T) {
	e := NewEUAIActComplianceEngine()
	e.RegisterAISystem(context.Background(), &AISystem{
		ID: "s1", RiskCategory: RiskCategoryHigh, CEMarking: true, EUDBRegistered: true,
	})
	status := e.GetComplianceStatus(context.Background())
	if status.TransparencyGaps != 1 {
		t.Fatalf("expected 1 transparency gap, got %d", status.TransparencyGaps)
	}
}

// ── Human Oversight Mappings ──

func TestHumanOversightMappings_Coverage(t *testing.T) {
	mappings := DefaultHumanOversightMappings()
	if len(mappings) != 4 {
		t.Fatalf("expected 4 Art.14 mappings, got %d", len(mappings))
	}
	refs := make(map[string]bool)
	for _, m := range mappings {
		refs[m.Article14Ref] = true
	}
	for _, ref := range []string{"Art.14(1)", "Art.14(2)", "Art.14(3)", "Art.14(4)"} {
		if !refs[ref] {
			t.Fatalf("missing mapping for %s", ref)
		}
	}
}

// ── Export ──

func TestExportComplianceJSON_NonEmpty(t *testing.T) {
	e := NewEUAIActComplianceEngine()
	data, err := e.ExportComplianceJSON(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty JSON export")
	}
}
