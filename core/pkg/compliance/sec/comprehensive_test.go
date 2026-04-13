package sec

import (
	"context"
	"testing"
	"time"
)

func TestNewSECComplianceEngine(t *testing.T) {
	engine := NewSECComplianceEngine("BrokerDealer")
	if engine.entityName != "BrokerDealer" {
		t.Errorf("expected entity name 'BrokerDealer', got %q", engine.entityName)
	}
	if engine.retentionYears != 6 {
		t.Errorf("default retention should be 6 years, got %d", engine.retentionYears)
	}
}

func TestRetainRecord_SetsImmutable(t *testing.T) {
	engine := NewSECComplianceEngine("Entity")
	rec := &RetentionRecord{ID: "r1", Category: RecordTrade}
	engine.RetainRecord(context.Background(), rec)
	if !rec.Immutable {
		t.Error("retained record should be immutable (WORM)")
	}
}

func TestRetainRecord_SetsTimestamps(t *testing.T) {
	engine := NewSECComplianceEngine("Entity")
	rec := &RetentionRecord{ID: "r1", Category: RecordOrder}
	engine.RetainRecord(context.Background(), rec)
	if rec.CreatedAt.IsZero() {
		t.Error("CreatedAt should be auto-set")
	}
	if rec.RetainUntil.IsZero() {
		t.Error("RetainUntil should be auto-set")
	}
}

func TestRetainRecord_DefaultRetention6Years(t *testing.T) {
	engine := NewSECComplianceEngine("Entity")
	rec := &RetentionRecord{ID: "r1", Category: RecordCompliance}
	before := time.Now()
	engine.RetainRecord(context.Background(), rec)
	expected := before.AddDate(6, 0, 0)
	if rec.RetainUntil.Before(expected.Add(-time.Second)) {
		t.Error("retention should be at least 6 years from now")
	}
}

func TestRecordAIAction(t *testing.T) {
	engine := NewSECComplianceEngine("Entity")
	rec := &AIAgentOversightRecord{ID: "ai-1", AgentID: "agent1", Decision: "ALLOW"}
	err := engine.RecordAIAction(context.Background(), rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Timestamp.IsZero() {
		t.Error("timestamp should be auto-set")
	}
}

func TestReportSCIEvent(t *testing.T) {
	engine := NewSECComplianceEngine("Entity")
	ev := &SCIEvent{ID: "sci-1", EventType: "disruption", Impact: "material"}
	err := engine.ReportSCIEvent(context.Background(), ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.DetectedAt.IsZero() {
		t.Error("DetectedAt should be auto-set")
	}
}

func TestComplianceStatus_Compliant(t *testing.T) {
	engine := NewSECComplianceEngine("Entity")
	status := engine.GetComplianceStatus(context.Background())
	if !status.IsCompliant {
		t.Error("empty engine should be compliant")
	}
}

func TestComplianceStatus_UnreviewedHighRisk(t *testing.T) {
	engine := NewSECComplianceEngine("Entity")
	engine.RecordAIAction(context.Background(), &AIAgentOversightRecord{
		ID: "ai-1", RiskLevel: "HIGH", HumanReviewed: false,
	})
	status := engine.GetComplianceStatus(context.Background())
	if status.UnreviewedHighRisk != 1 {
		t.Errorf("expected 1 unreviewed high risk, got %d", status.UnreviewedHighRisk)
	}
	if status.IsCompliant {
		t.Error("should not be compliant with unreviewed high-risk AI actions")
	}
}

func TestComplianceStatus_ReviewedHighRiskOK(t *testing.T) {
	engine := NewSECComplianceEngine("Entity")
	engine.RecordAIAction(context.Background(), &AIAgentOversightRecord{
		ID: "ai-1", RiskLevel: "HIGH", HumanReviewed: true,
	})
	status := engine.GetComplianceStatus(context.Background())
	if status.UnreviewedHighRisk != 0 {
		t.Error("reviewed high-risk actions should not be flagged")
	}
}

func TestComplianceStatus_UnreportedMaterial(t *testing.T) {
	engine := NewSECComplianceEngine("Entity")
	engine.ReportSCIEvent(context.Background(), &SCIEvent{
		ID: "sci-1", Impact: "material", ReportedToSEC: false,
	})
	status := engine.GetComplianceStatus(context.Background())
	if status.UnreportedMaterial != 1 {
		t.Errorf("expected 1 unreported material event, got %d", status.UnreportedMaterial)
	}
}

func TestComplianceStatus_NonMaterialIgnored(t *testing.T) {
	engine := NewSECComplianceEngine("Entity")
	engine.ReportSCIEvent(context.Background(), &SCIEvent{
		ID: "sci-1", Impact: "non_material", ReportedToSEC: false,
	})
	status := engine.GetComplianceStatus(context.Background())
	if status.UnreportedMaterial != 0 {
		t.Error("non-material events should not affect compliance")
	}
}

func TestGenerateAuditReport_Hash(t *testing.T) {
	engine := NewSECComplianceEngine("Entity")
	now := time.Now()
	report, err := engine.GenerateAuditReport(context.Background(), now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if report.Hash == "" {
		t.Error("audit report hash should not be empty")
	}
	if report.Entity != "Entity" {
		t.Errorf("expected entity 'Entity', got %q", report.Entity)
	}
}

func TestGenerateAuditReport_FiltersByPeriod(t *testing.T) {
	engine := NewSECComplianceEngine("Entity")
	ctx := context.Background()
	now := time.Now()
	engine.RetainRecord(ctx, &RetentionRecord{ID: "r-in", Category: RecordTrade, CreatedAt: now})
	engine.RecordAIAction(ctx, &AIAgentOversightRecord{ID: "ai-in", Timestamp: now})
	engine.ReportSCIEvent(ctx, &SCIEvent{ID: "sci-in", DetectedAt: now})
	report, _ := engine.GenerateAuditReport(ctx, now.Add(-time.Hour), now.Add(time.Hour))
	if len(report.RetentionRecords) != 1 {
		t.Errorf("expected 1 retention record, got %d", len(report.RetentionRecords))
	}
	if len(report.AIActions) != 1 {
		t.Errorf("expected 1 AI action, got %d", len(report.AIActions))
	}
	if len(report.SCIEvents) != 1 {
		t.Errorf("expected 1 SCI event, got %d", len(report.SCIEvents))
	}
}

func TestRecordCategories(t *testing.T) {
	cats := []RecordCategory{RecordTrade, RecordCommunication, RecordOrder, RecordCompliance, RecordAIDecision}
	if len(cats) != 5 {
		t.Fatalf("expected 5 record categories, got %d", len(cats))
	}
}
