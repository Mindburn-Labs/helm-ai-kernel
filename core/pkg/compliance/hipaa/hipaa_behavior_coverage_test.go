package hipaa

import (
	"context"
	"testing"
	"time"
)

func TestPHICategoryConstants(t *testing.T) {
	cats := []PHICategory{
		PHIName, PHIAddress, PHIDates, PHIPhone, PHIFax, PHIEmail,
		PHISSN, PHIMedicalRecord, PHIHealthPlan, PHIAccount,
		PHICertLicense, PHIVehicle, PHIDevice, PHIWebURL,
		PHIIP, PHIBiometric, PHIPhoto, PHIOther,
	}
	if len(cats) != 18 {
		t.Fatalf("expected 18 PHI categories, got %d", len(cats))
	}
	seen := make(map[PHICategory]bool)
	for _, c := range cats {
		if seen[c] {
			t.Errorf("duplicate PHI category: %s", c)
		}
		seen[c] = true
	}
}

func TestAccessPurposeConstants(t *testing.T) {
	purposes := []AccessPurpose{
		PurposeTreatment, PurposePayment, PurposeHealthcareOps,
		PurposeResearch, PurposePublicHealth, PurposeBreakGlass,
	}
	if len(purposes) != 6 {
		t.Fatalf("expected 6 access purposes, got %d", len(purposes))
	}
}

func TestRecordPHIAccess_MinimumNecessaryRequired(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	err := engine.RecordPHIAccess(context.Background(), &PHIAccessRecord{
		ID: "a1", Purpose: PurposeTreatment, MinimumNecessary: false,
	})
	if err == nil {
		t.Error("expected error for non-minimum-necessary non-break-glass access")
	}
}

func TestRecordPHIAccess_BreakGlassBypassesMinimumNecessary(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	err := engine.RecordPHIAccess(context.Background(), &PHIAccessRecord{
		ID: "a2", Purpose: PurposeBreakGlass, MinimumNecessary: false, BreakGlass: true,
	})
	if err != nil {
		t.Fatalf("break-glass should bypass minimum-necessary: %v", err)
	}
}

func TestRecordPHIAccess_SetsTimestamp(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	rec := &PHIAccessRecord{ID: "a3", Purpose: PurposePayment, MinimumNecessary: true}
	engine.RecordPHIAccess(context.Background(), rec)
	if rec.Timestamp.IsZero() {
		t.Error("timestamp should be auto-set")
	}
}

func TestRecordPHIAccess_PreservesExplicitTimestamp(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	rec := &PHIAccessRecord{ID: "a4", Purpose: PurposeResearch, MinimumNecessary: true, Timestamp: ts}
	engine.RecordPHIAccess(context.Background(), rec)
	if !rec.Timestamp.Equal(ts) {
		t.Error("explicit timestamp should be preserved")
	}
}

func TestReportBreach_SetsDiscoveredAt(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	b := &BreachRecord{ID: "b1", IndividualsAffected: 5}
	engine.ReportBreach(context.Background(), b)
	if b.DiscoveredAt.IsZero() {
		t.Error("DiscoveredAt should be auto-set")
	}
}

func TestReportBreach_PreservesExplicitDiscoveredAt(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	ts := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	b := &BreachRecord{ID: "b2", DiscoveredAt: ts}
	engine.ReportBreach(context.Background(), b)
	if !b.DiscoveredAt.Equal(ts) {
		t.Error("explicit DiscoveredAt should be preserved")
	}
}

func TestRegisterBAA(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	err := engine.RegisterBAA(context.Background(), &BAARecord{
		ID: "baa-1", AssociateName: "Vendor", Active: true,
	})
	if err != nil {
		t.Fatalf("RegisterBAA should not error: %v", err)
	}
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	if _, ok := engine.baas["baa-1"]; !ok {
		t.Error("BAA should be stored")
	}
}

func TestComplianceStatus_Compliant(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	status := engine.GetComplianceStatus(context.Background())
	if !status.IsCompliant {
		t.Error("empty engine should be compliant")
	}
}

func TestComplianceStatus_OverdueBreachNotification(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	engine.mu.Lock()
	engine.breaches["b1"] = &BreachRecord{
		ID: "b1", DiscoveredAt: time.Now().AddDate(0, 0, -90), ReportedToHHS: false,
	}
	engine.mu.Unlock()
	status := engine.GetComplianceStatus(context.Background())
	if status.OverdueNotifications != 1 {
		t.Errorf("expected 1 overdue notification, got %d", status.OverdueNotifications)
	}
	if status.IsCompliant {
		t.Error("should not be compliant with overdue notification")
	}
}

func TestComplianceStatus_MediaNotificationRequired(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	engine.ReportBreach(context.Background(), &BreachRecord{
		ID: "b2", IndividualsAffected: 500, ReportedToMedia: false,
	})
	status := engine.GetComplianceStatus(context.Background())
	if status.MediaNotificationRequired != 1 {
		t.Errorf("expected 1 media notification required, got %d", status.MediaNotificationRequired)
	}
}

func TestComplianceStatus_MediaNotificationNotRequired_Under500(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	engine.ReportBreach(context.Background(), &BreachRecord{
		ID: "b3", IndividualsAffected: 499, ReportedToMedia: false,
	})
	status := engine.GetComplianceStatus(context.Background())
	if status.MediaNotificationRequired != 0 {
		t.Errorf("expected 0 media notifications for <500, got %d", status.MediaNotificationRequired)
	}
}

func TestComplianceStatus_ExpiredBAA(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	past := time.Now().AddDate(-1, 0, 0)
	engine.RegisterBAA(context.Background(), &BAARecord{
		ID: "baa-exp", Active: true, ExpirationDate: &past,
	})
	status := engine.GetComplianceStatus(context.Background())
	if status.ExpiredBAAs != 1 {
		t.Errorf("expected 1 expired BAA, got %d", status.ExpiredBAAs)
	}
}

func TestComplianceStatus_InactiveExpiredBAAIgnored(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	past := time.Now().AddDate(-1, 0, 0)
	engine.RegisterBAA(context.Background(), &BAARecord{
		ID: "baa-inactive", Active: false, ExpirationDate: &past,
	})
	status := engine.GetComplianceStatus(context.Background())
	if status.ExpiredBAAs != 0 {
		t.Errorf("inactive expired BAA should not count, got %d", status.ExpiredBAAs)
	}
}

func TestComplianceStatus_BreakGlassCount(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	ctx := context.Background()
	engine.RecordPHIAccess(ctx, &PHIAccessRecord{ID: "bg1", Purpose: PurposeBreakGlass, BreakGlass: true})
	engine.RecordPHIAccess(ctx, &PHIAccessRecord{ID: "bg2", Purpose: PurposeBreakGlass, BreakGlass: true})
	engine.RecordPHIAccess(ctx, &PHIAccessRecord{ID: "n1", Purpose: PurposeTreatment, MinimumNecessary: true})
	status := engine.GetComplianceStatus(ctx)
	if status.BreakGlassCount != 2 {
		t.Errorf("expected 2 break-glass, got %d", status.BreakGlassCount)
	}
}

func TestGenerateAuditReport_FiltersByPeriod(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	ctx := context.Background()
	now := time.Now()
	engine.RecordPHIAccess(ctx, &PHIAccessRecord{
		ID: "in-range", Purpose: PurposeTreatment, MinimumNecessary: true, Timestamp: now,
	})
	engine.mu.Lock()
	engine.accessLog["out-of-range"] = &PHIAccessRecord{
		ID: "out-of-range", Timestamp: now.AddDate(-1, 0, 0),
	}
	engine.mu.Unlock()
	report, err := engine.GenerateAuditReport(ctx, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.PHIAccesses) != 1 {
		t.Errorf("expected 1 in-range access, got %d", len(report.PHIAccesses))
	}
}

func TestGenerateAuditReport_HashNonEmpty(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	report, _ := engine.GenerateAuditReport(context.Background(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if report.Hash == "" {
		t.Error("audit report hash should not be empty")
	}
}

func TestGenerateAuditReport_EntityName(t *testing.T) {
	engine := NewHIPAAComplianceEngine("MyEntity")
	report, _ := engine.GenerateAuditReport(context.Background(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if report.Entity != "MyEntity" {
		t.Errorf("expected entity 'MyEntity', got %q", report.Entity)
	}
}

func TestGenerateAuditReport_BreachesFilteredByPeriod(t *testing.T) {
	engine := NewHIPAAComplianceEngine("Hospital")
	ctx := context.Background()
	now := time.Now()
	engine.ReportBreach(ctx, &BreachRecord{ID: "b-in", DiscoveredAt: now})
	engine.mu.Lock()
	engine.breaches["b-out"] = &BreachRecord{ID: "b-out", DiscoveredAt: now.AddDate(-1, 0, 0)}
	engine.mu.Unlock()
	report, _ := engine.GenerateAuditReport(ctx, now.Add(-time.Hour), now.Add(time.Hour))
	if len(report.Breaches) != 1 {
		t.Errorf("expected 1 in-range breach, got %d", len(report.Breaches))
	}
}
