package kernel

import (
	"context"
	"testing"
	"time"
)

// mockPDPEvaluator for testing
type mockPDPEvaluator struct {
	decision   string
	decisionID string
	err        error
}

func (m *mockPDPEvaluator) Evaluate(ctx context.Context, req *EffectRequest) (string, string, error) {
	return m.decision, m.decisionID, m.err
}

//nolint:gocognit,gocyclo // test complexity is acceptable
func TestInMemoryEffectBoundary(t *testing.T) {
	t.Run("Submit effect", func(t *testing.T) {
		boundary := NewInMemoryEffectBoundary(nil, nil)

		req := &EffectRequest{
			EffectType: EffectTypeDataWrite,
			Subject: EffectSubject{
				SubjectID:   "user-123",
				SubjectType: "human",
			},
			Payload: EffectPayload{
				Data: map[string]interface{}{"key": "value"},
			},
		}

		lifecycle, err := boundary.Submit(context.Background(), req)
		if err != nil {
			t.Fatalf("Submit failed: %v", err)
		}
		if lifecycle.State != "pending" {
			t.Errorf("State = %q, want 'pending'", lifecycle.State)
		}
		if req.EffectID == "" {
			t.Error("EffectID should be generated")
		}
	})

	t.Run("Submit validates required fields", func(t *testing.T) {
		boundary := NewInMemoryEffectBoundary(nil, nil)

		// Missing effect type
		req := &EffectRequest{
			Subject: EffectSubject{SubjectID: "user-123"},
		}
		_, err := boundary.Submit(context.Background(), req)
		if err == nil {
			t.Error("Should fail without effect_type")
		}

		// Missing subject ID
		req = &EffectRequest{
			EffectType: EffectTypeDataWrite,
		}
		_, err = boundary.Submit(context.Background(), req)
		if err == nil {
			t.Error("Should fail without subject_id")
		}
	})

	t.Run("Idempotency", func(t *testing.T) {
		boundary := NewInMemoryEffectBoundary(nil, nil)

		req := &EffectRequest{
			EffectType: EffectTypeDataWrite,
			Subject:    EffectSubject{SubjectID: "user-123"},
			Idempotency: &IdempotencyConfig{
				Key: "unique-key-1",
			},
		}

		// First submission
		lifecycle1, _ := boundary.Submit(context.Background(), req)
		effectID := req.EffectID

		// Second submission with same key
		req2 := &EffectRequest{
			EffectType: EffectTypeDataWrite,
			Subject:    EffectSubject{SubjectID: "user-456"},
			Idempotency: &IdempotencyConfig{
				Key: "unique-key-1",
			},
		}
		lifecycle2, _ := boundary.Submit(context.Background(), req2)

		// Should return the same lifecycle
		if lifecycle1 != lifecycle2 {
			t.Error("Idempotent requests should return same lifecycle")
		}

		// Check idempotency lookup
		exists, storedID, _ := boundary.CheckIdempotency(context.Background(), "unique-key-1")
		if !exists {
			t.Error("Key should exist")
		}
		if storedID != effectID {
			t.Errorf("StoredID = %q, want %q", storedID, effectID)
		}
	})

	t.Run("Approve effect", func(t *testing.T) {
		boundary := NewInMemoryEffectBoundary(nil, nil)

		req := &EffectRequest{
			EffectType: EffectTypeDataWrite,
			Subject:    EffectSubject{SubjectID: "user-123"},
		}
		_, _ = boundary.Submit(context.Background(), req)

		err := boundary.Approve(context.Background(), req.EffectID, "decision-1")
		if err != nil {
			t.Fatalf("Approve failed: %v", err)
		}

		lifecycle, _ := boundary.GetLifecycle(context.Background(), req.EffectID)
		if lifecycle.State != "approved" {
			t.Errorf("State = %q, want 'approved'", lifecycle.State)
		}
	})

	t.Run("Deny effect", func(t *testing.T) {
		boundary := NewInMemoryEffectBoundary(nil, nil)

		req := &EffectRequest{
			EffectType: EffectTypeDataWrite,
			Subject:    EffectSubject{SubjectID: "user-123"},
		}
		_, _ = boundary.Submit(context.Background(), req)

		err := boundary.Deny(context.Background(), req.EffectID, "decision-1", "policy violation")
		if err != nil {
			t.Fatalf("Deny failed: %v", err)
		}

		lifecycle, _ := boundary.GetLifecycle(context.Background(), req.EffectID)
		if lifecycle.State != "denied" {
			t.Errorf("State = %q, want 'denied'", lifecycle.State)
		}
	})

	t.Run("Execute and Complete lifecycle", func(t *testing.T) {
		boundary := NewInMemoryEffectBoundary(nil, nil)

		req := &EffectRequest{
			EffectType: EffectTypeDataWrite,
			Subject:    EffectSubject{SubjectID: "user-123"},
		}
		_, _ = boundary.Submit(context.Background(), req)
		_ = boundary.Approve(context.Background(), req.EffectID, "decision-1")

		// Execute
		err := boundary.Execute(context.Background(), req.EffectID)
		if err != nil {
			t.Fatalf("Execute failed: %v", err)
		}

		lifecycle, _ := boundary.GetLifecycle(context.Background(), req.EffectID)
		if lifecycle.State != "executing" {
			t.Errorf("State = %q, want 'executing'", lifecycle.State)
		}
		if lifecycle.ExecutedAt.IsZero() {
			t.Error("ExecutedAt should be set")
		}

		// Complete
		err = boundary.Complete(context.Background(), req.EffectID, "evidence-pack-1")
		if err != nil {
			t.Fatalf("Complete failed: %v", err)
		}

		lifecycle, _ = boundary.GetLifecycle(context.Background(), req.EffectID)
		if lifecycle.State != "completed" {
			t.Errorf("State = %q, want 'completed'", lifecycle.State)
		}
		if lifecycle.CompletedAt.IsZero() {
			t.Error("CompletedAt should be set")
		}
		if lifecycle.EvidencePackID != "evidence-pack-1" {
			t.Errorf("EvidencePackID = %q, want 'evidence-pack-1'", lifecycle.EvidencePackID)
		}
	})

	t.Run("Execute requires approved state", func(t *testing.T) {
		boundary := NewInMemoryEffectBoundary(nil, nil)

		req := &EffectRequest{
			EffectType: EffectTypeDataWrite,
			Subject:    EffectSubject{SubjectID: "user-123"},
		}
		_, _ = boundary.Submit(context.Background(), req) // pending state

		err := boundary.Execute(context.Background(), req.EffectID)
		if err == nil {
			t.Error("Should fail to execute from pending state")
		}
	})

	t.Run("Not found errors", func(t *testing.T) {
		boundary := NewInMemoryEffectBoundary(nil, nil)
		ctx := context.Background()

		// GetLifecycle
		_, err := boundary.GetLifecycle(ctx, "nonexistent")
		if err == nil {
			t.Error("GetLifecycle should error for nonexistent effect")
		}

		// Approve
		err = boundary.Approve(ctx, "nonexistent", "decision")
		if err == nil {
			t.Error("Approve should error for nonexistent effect")
		}

		// Deny
		err = boundary.Deny(ctx, "nonexistent", "decision", "reason")
		if err == nil {
			t.Error("Deny should error for nonexistent effect")
		}

		// Execute
		err = boundary.Execute(ctx, "nonexistent")
		if err == nil {
			t.Error("Execute should error for nonexistent effect")
		}

		// Complete
		err = boundary.Complete(ctx, "nonexistent", "evidence")
		if err == nil {
			t.Error("Complete should error for nonexistent effect")
		}
	})

	t.Run("With PDP evaluator", func(t *testing.T) {
		pdp := &mockPDPEvaluator{
			decision:   "ALLOW",
			decisionID: "pdp-decision-1",
		}
		boundary := NewInMemoryEffectBoundary(pdp, nil)

		req := &EffectRequest{
			EffectType: EffectTypeDataWrite,
			Subject:    EffectSubject{SubjectID: "user-123"},
		}

		lifecycle, err := boundary.Submit(context.Background(), req)
		if err != nil {
			t.Fatalf("Submit failed: %v", err)
		}
		if lifecycle.State != "approved" {
			t.Errorf("State = %q, want 'approved'", lifecycle.State)
		}
		if lifecycle.PDPDecisionID != "pdp-decision-1" {
			t.Error("PDPDecisionID not set")
		}
	})

	t.Run("Submission sets timestamp", func(t *testing.T) {
		boundary := NewInMemoryEffectBoundary(nil, nil)

		before := time.Now().UTC()
		req := &EffectRequest{
			EffectType: EffectTypeDataWrite,
			Subject:    EffectSubject{SubjectID: "user-123"},
		}
		_, _ = boundary.Submit(context.Background(), req)
		after := time.Now().UTC()

		if req.SubmittedAt.Before(before) || req.SubmittedAt.After(after) {
			t.Error("SubmittedAt not set correctly")
		}
	})
}

func TestComputePayloadHash(t *testing.T) {
	data := map[string]interface{}{
		"key": "value",
	}

	hash, err := computePayloadHash(data)
	if err != nil {
		t.Fatalf("computePayloadHash failed: %v", err)
	}
	if hash == "" {
		t.Error("Hash should not be empty")
	}
	if hash[:7] != "sha256:" {
		t.Error("Hash should start with 'sha256:'")
	}
}
