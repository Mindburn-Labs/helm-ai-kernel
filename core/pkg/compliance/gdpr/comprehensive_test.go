package gdpr

import (
	"context"
	"testing"
	"time"
)

func TestGDPREngine_Init(t *testing.T) {
	engine := NewGDPREngine("dpo@example.com")
	status := engine.GetStatus()
	if status["dpo"].(string) != "dpo@example.com" {
		t.Errorf("unexpected DPO: %v", status["dpo"])
	}
}

func TestRegisterProcessingActivity_ValidActivity(t *testing.T) {
	engine := NewGDPREngine("dpo")
	err := engine.RegisterProcessingActivity(context.Background(), &ProcessingActivity{
		ID: "pa-1", Purpose: "marketing", LawfulBasis: BasisConsent,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegisterProcessingActivity_NoPurposeError(t *testing.T) {
	engine := NewGDPREngine("dpo")
	err := engine.RegisterProcessingActivity(context.Background(), &ProcessingActivity{
		ID: "pa-1", LawfulBasis: BasisConsent,
	})
	if err == nil {
		t.Error("expected error for missing purpose")
	}
}

func TestRegisterProcessingActivity_NoBasisError(t *testing.T) {
	engine := NewGDPREngine("dpo")
	err := engine.RegisterProcessingActivity(context.Background(), &ProcessingActivity{
		ID: "pa-1", Purpose: "analytics",
	})
	if err == nil {
		t.Error("expected error for missing lawful basis")
	}
}

func TestHandleSubjectRequest_SetsReceived(t *testing.T) {
	engine := NewGDPREngine("dpo")
	req := &SubjectRequest{
		ID: "sr-1", SubjectID: "user-1", Right: RightAccess,
		ReceivedAt: time.Now(),
	}
	err := engine.HandleSubjectRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Status != "RECEIVED" {
		t.Errorf("expected status RECEIVED, got %s", req.Status)
	}
}

func TestHandleSubjectRequest_Sets30DayDeadline(t *testing.T) {
	engine := NewGDPREngine("dpo")
	received := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	req := &SubjectRequest{
		ID: "sr-1", SubjectID: "user-1", Right: RightErasure, ReceivedAt: received,
	}
	engine.HandleSubjectRequest(context.Background(), req)
	expected := received.Add(30 * 24 * time.Hour)
	if !req.Deadline.Equal(expected) {
		t.Errorf("expected deadline %v, got %v", expected, req.Deadline)
	}
}

func TestHandleSubjectRequest_NoSubjectIDError(t *testing.T) {
	engine := NewGDPREngine("dpo")
	err := engine.HandleSubjectRequest(context.Background(), &SubjectRequest{
		ID: "sr-1", Right: RightAccess,
	})
	if err == nil {
		t.Error("expected error for missing subject ID")
	}
}

func TestGetStatus_OpenRequests(t *testing.T) {
	engine := NewGDPREngine("dpo")
	ctx := context.Background()
	engine.HandleSubjectRequest(ctx, &SubjectRequest{
		ID: "sr-1", SubjectID: "u1", Right: RightAccess, ReceivedAt: time.Now(),
	})
	engine.HandleSubjectRequest(ctx, &SubjectRequest{
		ID: "sr-2", SubjectID: "u2", Right: RightErasure, ReceivedAt: time.Now(),
	})
	status := engine.GetStatus()
	if status["open_subject_requests"].(int) != 2 {
		t.Errorf("expected 2 open requests, got %d", status["open_subject_requests"].(int))
	}
}

func TestGetStatus_CompletedRequestNotCounted(t *testing.T) {
	engine := NewGDPREngine("dpo")
	engine.HandleSubjectRequest(context.Background(), &SubjectRequest{
		ID: "sr-1", SubjectID: "u1", Right: RightAccess, ReceivedAt: time.Now(),
	})
	engine.mu.Lock()
	engine.requests["sr-1"].Status = "COMPLETED"
	engine.mu.Unlock()
	status := engine.GetStatus()
	if status["open_subject_requests"].(int) != 0 {
		t.Error("completed requests should not be counted as open")
	}
}

func TestGetStatus_PendingDPIACount(t *testing.T) {
	engine := NewGDPREngine("dpo")
	engine.RegisterProcessingActivity(context.Background(), &ProcessingActivity{
		ID: "pa-1", Purpose: "profiling", LawfulBasis: BasisLegitimateInterest,
	})
	status := engine.GetStatus()
	if status["pending_dpias"].(int) != 1 {
		t.Errorf("expected 1 pending DPIA (nil), got %d", status["pending_dpias"].(int))
	}
}

func TestGetStatus_CompletedDPIANotPending(t *testing.T) {
	engine := NewGDPREngine("dpo")
	engine.RegisterProcessingActivity(context.Background(), &ProcessingActivity{
		ID: "pa-1", Purpose: "profiling", LawfulBasis: BasisConsent,
		DPIA: &DPIARecord{ID: "dpia-1", Status: "COMPLETED"},
	})
	status := engine.GetStatus()
	if status["pending_dpias"].(int) != 0 {
		t.Error("completed DPIA should not be counted as pending")
	}
}

func TestLawfulBasis_AllSixBases(t *testing.T) {
	bases := []LawfulBasis{
		BasisConsent, BasisContract, BasisLegalObligation,
		BasisVitalInterest, BasisPublicInterest, BasisLegitimateInterest,
	}
	if len(bases) != 6 {
		t.Fatalf("expected 6 lawful bases, got %d", len(bases))
	}
}

func TestDataSubjectRight_AllSevenRights(t *testing.T) {
	rights := []DataSubjectRight{
		RightAccess, RightRectify, RightErasure, RightRestrict,
		RightPortability, RightObject, RightAutomated,
	}
	if len(rights) != 7 {
		t.Fatalf("expected 7 data subject rights, got %d", len(rights))
	}
}

func TestGetStatus_BreachNotifications(t *testing.T) {
	engine := NewGDPREngine("dpo")
	engine.mu.Lock()
	engine.breaches = append(engine.breaches, BreachNotification{
		ID: "bn-1", AffectedCount: 100, RiskLevel: "HIGH",
	})
	engine.mu.Unlock()
	status := engine.GetStatus()
	if status["breach_notifications"].(int) != 1 {
		t.Errorf("expected 1 breach notification, got %d", status["breach_notifications"].(int))
	}
}
