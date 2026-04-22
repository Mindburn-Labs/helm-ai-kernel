package gdpr

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewGDPREngine(t *testing.T) {
	engine := NewGDPREngine("dpo@example.com")
	require.NotNil(t, engine)

	status := engine.GetStatus()
	require.Equal(t, "dpo@example.com", status["dpo"])
}

func TestRegisterProcessingActivity(t *testing.T) {
	engine := NewGDPREngine("dpo@example.com")
	ctx := context.Background()

	act := &ProcessingActivity{
		ID:             "ropa-1",
		Purpose:        "User analytics",
		LawfulBasis:    BasisLegitimateInterest,
		DataCategories: []string{"browsing_history", "device_info"},
		DataSubjects:   []string{"website_visitors"},
		Retention:      "24 months",
		CreatedAt:      time.Now(),
	}

	err := engine.RegisterProcessingActivity(ctx, act)
	require.NoError(t, err)

	status := engine.GetStatus()
	require.Equal(t, 1, status["processing_activities"])
}

func TestRegisterProcessingActivity_EmptyPurpose(t *testing.T) {
	engine := NewGDPREngine("dpo")
	err := engine.RegisterProcessingActivity(context.Background(), &ProcessingActivity{
		ID: "bad", LawfulBasis: BasisConsent,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "purpose")
}

func TestRegisterProcessingActivity_EmptyBasis(t *testing.T) {
	engine := NewGDPREngine("dpo")
	err := engine.RegisterProcessingActivity(context.Background(), &ProcessingActivity{
		ID: "bad", Purpose: "test",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "lawful basis")
}

func TestHandleSubjectRequest(t *testing.T) {
	engine := NewGDPREngine("dpo@example.com")
	ctx := context.Background()

	req := &SubjectRequest{
		ID:         "dsar-1",
		SubjectID:  "user-123",
		Right:      RightAccess,
		ReceivedAt: time.Now(),
	}

	err := engine.HandleSubjectRequest(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "RECEIVED", req.Status)
	require.False(t, req.Deadline.IsZero())

	// Deadline should be 30 days from receipt
	expectedDeadline := req.ReceivedAt.Add(30 * 24 * time.Hour)
	require.Equal(t, expectedDeadline, req.Deadline)

	status := engine.GetStatus()
	require.Equal(t, 1, status["open_subject_requests"])
}

func TestHandleSubjectRequest_EmptySubjectID(t *testing.T) {
	engine := NewGDPREngine("dpo")
	err := engine.HandleSubjectRequest(context.Background(), &SubjectRequest{
		ID: "bad", Right: RightErasure,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "subject ID")
}

func TestGetStatus_PendingDPIA(t *testing.T) {
	engine := NewGDPREngine("dpo@example.com")
	ctx := context.Background()

	// Activity without DPIA
	_ = engine.RegisterProcessingActivity(ctx, &ProcessingActivity{
		ID: "ropa-1", Purpose: "AI profiling", LawfulBasis: BasisConsent,
	})

	// Activity with completed DPIA
	_ = engine.RegisterProcessingActivity(ctx, &ProcessingActivity{
		ID: "ropa-2", Purpose: "Marketing", LawfulBasis: BasisLegitimateInterest,
		DPIA: &DPIARecord{ID: "dpia-1", Status: "COMPLETED"},
	})

	status := engine.GetStatus()
	require.Equal(t, 1, status["pending_dpias"])
}

func TestLawfulBasisConstants(t *testing.T) {
	require.Equal(t, LawfulBasis("CONSENT"), BasisConsent)
	require.Equal(t, LawfulBasis("CONTRACT"), BasisContract)
	require.Equal(t, LawfulBasis("LEGAL_OBLIGATION"), BasisLegalObligation)
	require.Equal(t, LawfulBasis("VITAL_INTEREST"), BasisVitalInterest)
	require.Equal(t, LawfulBasis("PUBLIC_INTEREST"), BasisPublicInterest)
	require.Equal(t, LawfulBasis("LEGITIMATE_INTEREST"), BasisLegitimateInterest)
}

func TestDataSubjectRightConstants(t *testing.T) {
	require.Equal(t, DataSubjectRight("ACCESS"), RightAccess)
	require.Equal(t, DataSubjectRight("RECTIFICATION"), RightRectify)
	require.Equal(t, DataSubjectRight("ERASURE"), RightErasure)
	require.Equal(t, DataSubjectRight("RESTRICTION"), RightRestrict)
	require.Equal(t, DataSubjectRight("PORTABILITY"), RightPortability)
	require.Equal(t, DataSubjectRight("OBJECTION"), RightObject)
	require.Equal(t, DataSubjectRight("AUTOMATED_DECISION"), RightAutomated)
}
