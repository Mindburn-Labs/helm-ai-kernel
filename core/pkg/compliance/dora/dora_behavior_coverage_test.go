package dora

import (
	"context"
	"testing"
	"time"
)

func testEntity() EntityInfo {
	return EntityInfo{
		LEI: "529900TEST", Name: "TestFirm", Type: "investment_firm",
		Jurisdiction: "BG", ICTOfficer: "cto@test.com",
	}
}

func TestDORAEngine_InitCompliant(t *testing.T) {
	engine := NewDORAComplianceEngine(testEntity())
	status := engine.GetComplianceStatus(context.Background())
	if !status.IsCompliant {
		t.Error("empty engine should be compliant")
	}
}

func TestRegisterRisk_StoresRisk(t *testing.T) {
	engine := NewDORAComplianceEngine(testEntity())
	err := engine.RegisterRisk(context.Background(), &ICTRisk{
		Name: "SQL Injection", Level: RiskLevelHigh, Category: "application",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	status := engine.GetComplianceStatus(context.Background())
	if status.ICTRiskCount != 1 {
		t.Error("expected 1 risk")
	}
}

func TestRegisterRisk_AutoGeneratesID(t *testing.T) {
	engine := NewDORAComplianceEngine(testEntity())
	risk := &ICTRisk{Name: "Test Risk", Level: RiskLevelLow}
	engine.RegisterRisk(context.Background(), risk)
	if risk.ID == "" {
		t.Error("ID should be auto-generated")
	}
}

func TestRegisterRisk_DefaultStatus(t *testing.T) {
	engine := NewDORAComplianceEngine(testEntity())
	risk := &ICTRisk{Name: "Test Risk", Level: RiskLevelMedium}
	engine.RegisterRisk(context.Background(), risk)
	if risk.Status != "identified" {
		t.Errorf("expected default status 'identified', got %q", risk.Status)
	}
}

func TestReportIncident_StoresIncident(t *testing.T) {
	engine := NewDORAComplianceEngine(testEntity())
	err := engine.ReportIncident(context.Background(), &ICTIncident{
		Type: IncidentCyberAttack, Severity: RiskLevelCritical,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegisterProvider_StoresProvider(t *testing.T) {
	engine := NewDORAComplianceEngine(testEntity())
	err := engine.RegisterProvider(context.Background(), &ThirdPartyProvider{
		Name: "CloudCo", Criticality: RiskLevelHigh, ServiceType: "cloud",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRecordResilienceTest_StoresTest(t *testing.T) {
	engine := NewDORAComplianceEngine(testEntity())
	err := engine.RecordResilienceTest(context.Background(), &ResilienceTest{
		Type: "pentest", Description: "Annual pen test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComplianceStatus_UnmitigatedCritical(t *testing.T) {
	engine := NewDORAComplianceEngine(testEntity())
	engine.RegisterRisk(context.Background(), &ICTRisk{
		ID: "r1", Name: "Critical", Level: RiskLevelCritical, Status: "identified",
	})
	status := engine.GetComplianceStatus(context.Background())
	if status.UnmitigatedCritical != 1 {
		t.Errorf("expected 1 unmitigated critical, got %d", status.UnmitigatedCritical)
	}
	if status.IsCompliant {
		t.Error("should not be compliant with unmitigated critical risk")
	}
}

func TestComplianceStatus_MitigatedCriticalOK(t *testing.T) {
	engine := NewDORAComplianceEngine(testEntity())
	engine.RegisterRisk(context.Background(), &ICTRisk{
		ID: "r1", Name: "Critical", Level: RiskLevelCritical, Status: "mitigated",
	})
	status := engine.GetComplianceStatus(context.Background())
	if status.UnmitigatedCritical != 0 {
		t.Error("mitigated critical risk should not count")
	}
}

func TestComplianceStatus_UnreportedCriticalIncident(t *testing.T) {
	engine := NewDORAComplianceEngine(testEntity())
	engine.ReportIncident(context.Background(), &ICTIncident{
		ID: "i1", Severity: RiskLevelCritical, ReportedToNCAs: false,
	})
	status := engine.GetComplianceStatus(context.Background())
	if status.UnreportedIncidents != 1 {
		t.Errorf("expected 1 unreported incident, got %d", status.UnreportedIncidents)
	}
}

func TestComplianceStatus_OverdueProviderAudit(t *testing.T) {
	engine := NewDORAComplianceEngine(testEntity())
	engine.RegisterProvider(context.Background(), &ThirdPartyProvider{
		ID: "p1", Name: "OldVendor", Criticality: RiskLevelCritical,
		// No LastAudit set = overdue
	})
	status := engine.GetComplianceStatus(context.Background())
	if status.OverdueAudits != 1 {
		t.Errorf("expected 1 overdue audit, got %d", status.OverdueAudits)
	}
}

func TestGenerateROI_Hash(t *testing.T) {
	engine := NewDORAComplianceEngine(testEntity())
	now := time.Now()
	roi, err := engine.GenerateROI(context.Background(), now.Add(-24*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if roi.Hash == "" {
		t.Error("ROI hash should not be empty")
	}
	if roi.EntityInfo.LEI != "529900TEST" {
		t.Error("ROI should contain entity info")
	}
}

func TestGenerateROI_IncludesAllProviders(t *testing.T) {
	engine := NewDORAComplianceEngine(testEntity())
	ctx := context.Background()
	engine.RegisterProvider(ctx, &ThirdPartyProvider{ID: "p1", Name: "A"})
	engine.RegisterProvider(ctx, &ThirdPartyProvider{ID: "p2", Name: "B"})
	now := time.Now()
	roi, _ := engine.GenerateROI(ctx, now.Add(-time.Hour), now.Add(time.Hour))
	if len(roi.ThirdPartyProviders) != 2 {
		t.Errorf("expected 2 providers in ROI, got %d", len(roi.ThirdPartyProviders))
	}
}

func TestNewIncidentWorkflow_CriticalSeverity(t *testing.T) {
	wf := NewIncidentWorkflow("inc-1", RiskLevelCritical)
	if wf.Status != WorkflowStatusDraft {
		t.Errorf("expected DRAFT status, got %s", wf.Status)
	}
	if len(wf.NCAs) != 2 {
		t.Errorf("critical incident should have 2 NCAs, got %d", len(wf.NCAs))
	}
	if len(wf.Steps) != 9 {
		t.Errorf("expected 9 workflow steps, got %d", len(wf.Steps))
	}
}

func TestIncidentWorkflow_AdvanceAndComplete(t *testing.T) {
	wf := NewIncidentWorkflow("inc-1", RiskLevelHigh)
	for i := 0; i < len(wf.Steps)-1; i++ {
		if err := wf.AdvanceWorkflow("admin", "done"); err != nil {
			t.Fatalf("advance step %d failed: %v", i, err)
		}
	}
	// Final step still in_progress; mark it completed manually
	wf.Steps[wf.CurrentStep].Status = "completed"
	if !wf.IsComplete() {
		t.Error("workflow should be complete")
	}
}
