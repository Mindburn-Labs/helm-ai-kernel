package sec

import (
	"context"
	"testing"
	"time"
)

func TestSECEngine_RetainRecord_WORM(t *testing.T) {
	engine := NewSECComplianceEngine("TestEntity")
	ctx := context.Background()

	err := engine.RetainRecord(ctx, &RetentionRecord{
		ID:       "rec-001",
		Category: RecordTrade,
		Description: "Trade execution record",
	})
	if err != nil {
		t.Fatal(err)
	}

	engine.mu.RLock()
	r := engine.records["rec-001"]
	engine.mu.RUnlock()

	if !r.Immutable {
		t.Error("WORM: record should be marked immutable")
	}
	if r.RetainUntil.IsZero() {
		t.Error("RetainUntil should be set automatically")
	}
	// Default retention: 6 years
	minRetain := time.Now().AddDate(5, 11, 0)
	if r.RetainUntil.Before(minRetain) {
		t.Error("RetainUntil should be at least ~6 years from now")
	}
}

func TestSECEngine_RecordAIAction(t *testing.T) {
	engine := NewSECComplianceEngine("TestEntity")
	ctx := context.Background()

	err := engine.RecordAIAction(ctx, &AIAgentOversightRecord{
		ID:        "ai-001",
		AgentID:   "agent-001",
		Action:    "place_order",
		Decision:  "ALLOW",
		RiskLevel: "HIGH",
		ReceiptID: "rcpt-001",
	})
	if err != nil {
		t.Fatal(err)
	}

	engine.mu.RLock()
	a := engine.aiOversight["ai-001"]
	engine.mu.RUnlock()

	if a.Timestamp.IsZero() {
		t.Error("Timestamp should be auto-set")
	}
}

func TestSECEngine_ComplianceStatus_HighRiskUnreviewed(t *testing.T) {
	engine := NewSECComplianceEngine("TestEntity")
	ctx := context.Background()

	engine.RecordAIAction(ctx, &AIAgentOversightRecord{
		ID:            "ai-001",
		RiskLevel:     "HIGH",
		HumanReviewed: false,
	})
	engine.RecordAIAction(ctx, &AIAgentOversightRecord{
		ID:            "ai-002",
		RiskLevel:     "LOW",
		HumanReviewed: false,
	})

	status := engine.GetComplianceStatus(ctx)
	if status.UnreviewedHighRisk != 1 {
		t.Errorf("expected 1 unreviewed high-risk, got %d", status.UnreviewedHighRisk)
	}
	if status.IsCompliant {
		t.Error("should NOT be compliant with unreviewed high-risk actions")
	}
}

func TestSECEngine_ComplianceStatus_UnreportedMaterial(t *testing.T) {
	engine := NewSECComplianceEngine("TestEntity")
	ctx := context.Background()

	engine.ReportSCIEvent(ctx, &SCIEvent{
		ID:            "sci-001",
		Impact:        "material",
		ReportedToSEC: false,
	})

	status := engine.GetComplianceStatus(ctx)
	if status.UnreportedMaterial != 1 {
		t.Errorf("expected 1 unreported material event, got %d", status.UnreportedMaterial)
	}
	if status.IsCompliant {
		t.Error("should NOT be compliant with unreported material SCI events")
	}
}

func TestSECEngine_ComplianceStatus_AllClear(t *testing.T) {
	engine := NewSECComplianceEngine("TestEntity")
	ctx := context.Background()

	engine.RecordAIAction(ctx, &AIAgentOversightRecord{
		ID:            "ai-001",
		RiskLevel:     "HIGH",
		HumanReviewed: true,
	})

	status := engine.GetComplianceStatus(ctx)
	if !status.IsCompliant {
		t.Error("should be compliant when all high-risk reviewed and no unreported events")
	}
}

func TestSECEngine_GenerateAuditReport(t *testing.T) {
	engine := NewSECComplianceEngine("TestEntity")
	ctx := context.Background()

	now := time.Now()
	engine.RetainRecord(ctx, &RetentionRecord{ID: "rec-001", Category: RecordTrade, Description: "test"})
	engine.RecordAIAction(ctx, &AIAgentOversightRecord{ID: "ai-001", AgentID: "agent-001"})
	engine.ReportSCIEvent(ctx, &SCIEvent{ID: "sci-001", Impact: "non_material"})

	report, err := engine.GenerateAuditReport(ctx, now.Add(-1*time.Hour), now.Add(1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if report.Entity != "TestEntity" {
		t.Errorf("expected entity 'TestEntity', got %q", report.Entity)
	}
	if len(report.RetentionRecords) != 1 {
		t.Errorf("expected 1 retention record, got %d", len(report.RetentionRecords))
	}
	if len(report.AIActions) != 1 {
		t.Errorf("expected 1 AI action, got %d", len(report.AIActions))
	}
	if len(report.SCIEvents) != 1 {
		t.Errorf("expected 1 SCI event, got %d", len(report.SCIEvents))
	}
	if report.Hash == "" {
		t.Error("audit report hash should not be empty")
	}
}

func TestSECEngine_GenerateAuditReport_FiltersByPeriod(t *testing.T) {
	engine := NewSECComplianceEngine("TestEntity")
	ctx := context.Background()

	now := time.Now()
	engine.RecordAIAction(ctx, &AIAgentOversightRecord{ID: "ai-001"})

	// Query a period in the past that won't include the record
	report, err := engine.GenerateAuditReport(ctx, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AIActions) != 0 {
		t.Errorf("expected 0 AI actions in past period, got %d", len(report.AIActions))
	}
}
