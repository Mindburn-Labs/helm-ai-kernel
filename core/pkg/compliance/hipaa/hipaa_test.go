package hipaa

import (
	"context"
	"testing"
	"time"
)

func TestHIPAAEngine_RecordPHIAccess_MinimumNecessary(t *testing.T) {
	engine := NewHIPAAComplianceEngine("TestHospital")
	ctx := context.Background()

	// Should fail without minimum necessary
	err := engine.RecordPHIAccess(ctx, &PHIAccessRecord{
		ID:               "phi-001",
		AgentID:          "agent-001",
		PatientID:        "patient-001",
		PHICategories:    []PHICategory{PHIName, PHIMedicalRecord},
		Purpose:          PurposeTreatment,
		MinimumNecessary: false,
	})
	if err == nil {
		t.Error("expected error when MinimumNecessary not met")
	}

	// Should succeed with minimum necessary
	err = engine.RecordPHIAccess(ctx, &PHIAccessRecord{
		ID:               "phi-001",
		AgentID:          "agent-001",
		PatientID:        "patient-001",
		PHICategories:    []PHICategory{PHIName},
		Purpose:          PurposeTreatment,
		MinimumNecessary: true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHIPAAEngine_RecordPHIAccess_BreakGlass(t *testing.T) {
	engine := NewHIPAAComplianceEngine("TestHospital")
	ctx := context.Background()

	// Break-glass bypasses minimum necessary requirement
	err := engine.RecordPHIAccess(ctx, &PHIAccessRecord{
		ID:               "phi-bg-001",
		AgentID:          "agent-001",
		PHICategories:    []PHICategory{PHIName, PHIAddress, PHISSN},
		Purpose:          PurposeBreakGlass,
		MinimumNecessary: false,
		BreakGlass:       true,
	})
	if err != nil {
		t.Fatal("break-glass should bypass minimum necessary check")
	}
}

func TestHIPAAEngine_ReportBreach(t *testing.T) {
	engine := NewHIPAAComplianceEngine("TestHospital")
	ctx := context.Background()

	err := engine.ReportBreach(ctx, &BreachRecord{
		ID:                  "breach-001",
		Description:         "PHI exposed via API",
		PHICategories:       []PHICategory{PHISSN, PHIName},
		IndividualsAffected: 1500,
	})
	if err != nil {
		t.Fatal(err)
	}

	engine.mu.RLock()
	b := engine.breaches["breach-001"]
	engine.mu.RUnlock()

	if b.DiscoveredAt.IsZero() {
		t.Error("DiscoveredAt should be auto-set")
	}
}

func TestHIPAAEngine_ComplianceStatus_OverdueNotification(t *testing.T) {
	engine := NewHIPAAComplianceEngine("TestHospital")
	ctx := context.Background()

	pastDate := time.Now().AddDate(0, 0, -90) // 90 days ago
	engine.mu.Lock()
	engine.breaches["breach-old"] = &BreachRecord{
		ID:                  "breach-old",
		DiscoveredAt:        pastDate,
		IndividualsAffected: 100,
		ReportedToHHS:       false,
	}
	engine.mu.Unlock()

	status := engine.GetComplianceStatus(ctx)
	if status.OverdueNotifications != 1 {
		t.Errorf("expected 1 overdue notification (60-day deadline), got %d", status.OverdueNotifications)
	}
	if status.IsCompliant {
		t.Error("should NOT be compliant with overdue breach notification")
	}
}

func TestHIPAAEngine_ComplianceStatus_MediaNotification(t *testing.T) {
	engine := NewHIPAAComplianceEngine("TestHospital")
	ctx := context.Background()

	engine.ReportBreach(ctx, &BreachRecord{
		ID:                  "breach-large",
		IndividualsAffected: 600, // >500 requires media notification
		ReportedToMedia:     false,
	})

	status := engine.GetComplianceStatus(ctx)
	if status.MediaNotificationRequired != 1 {
		t.Errorf("expected 1 media notification required (>500 individuals), got %d", status.MediaNotificationRequired)
	}
}

func TestHIPAAEngine_ComplianceStatus_ExpiredBAA(t *testing.T) {
	engine := NewHIPAAComplianceEngine("TestHospital")
	ctx := context.Background()

	pastDate := time.Now().AddDate(-1, 0, 0) // expired 1 year ago
	engine.RegisterBAA(ctx, &BAARecord{
		ID:             "baa-001",
		AssociateName:  "CloudVendor",
		ExpirationDate: &pastDate,
		Active:         true,
	})

	status := engine.GetComplianceStatus(ctx)
	if status.ExpiredBAAs != 1 {
		t.Errorf("expected 1 expired BAA, got %d", status.ExpiredBAAs)
	}
	if status.IsCompliant {
		t.Error("should NOT be compliant with expired BAAs")
	}
}

func TestHIPAAEngine_ComplianceStatus_AllClear(t *testing.T) {
	engine := NewHIPAAComplianceEngine("TestHospital")
	ctx := context.Background()

	engine.RecordPHIAccess(ctx, &PHIAccessRecord{
		ID:               "phi-001",
		Purpose:          PurposeTreatment,
		MinimumNecessary: true,
	})

	status := engine.GetComplianceStatus(ctx)
	if !status.IsCompliant {
		t.Error("should be compliant when no violations")
	}
}

func TestHIPAAEngine_BreakGlassCount(t *testing.T) {
	engine := NewHIPAAComplianceEngine("TestHospital")
	ctx := context.Background()

	engine.RecordPHIAccess(ctx, &PHIAccessRecord{
		ID: "phi-bg-001", Purpose: PurposeBreakGlass, BreakGlass: true,
	})
	engine.RecordPHIAccess(ctx, &PHIAccessRecord{
		ID: "phi-bg-002", Purpose: PurposeBreakGlass, BreakGlass: true,
	})

	status := engine.GetComplianceStatus(ctx)
	if status.BreakGlassCount != 2 {
		t.Errorf("expected 2 break-glass accesses, got %d", status.BreakGlassCount)
	}
}

func TestHIPAAEngine_GenerateAuditReport(t *testing.T) {
	engine := NewHIPAAComplianceEngine("TestHospital")
	ctx := context.Background()

	now := time.Now()
	engine.RecordPHIAccess(ctx, &PHIAccessRecord{
		ID: "phi-001", Purpose: PurposeTreatment, MinimumNecessary: true,
	})
	engine.ReportBreach(ctx, &BreachRecord{
		ID: "breach-001", IndividualsAffected: 10,
	})

	report, err := engine.GenerateAuditReport(ctx, now.Add(-1*time.Hour), now.Add(1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if report.Entity != "TestHospital" {
		t.Errorf("expected entity 'TestHospital', got %q", report.Entity)
	}
	if len(report.PHIAccesses) != 1 {
		t.Errorf("expected 1 PHI access, got %d", len(report.PHIAccesses))
	}
	if len(report.Breaches) != 1 {
		t.Errorf("expected 1 breach, got %d", len(report.Breaches))
	}
	if report.Hash == "" {
		t.Error("audit report hash should not be empty")
	}
}
