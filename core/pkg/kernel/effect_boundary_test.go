package kernel

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// TestInMemoryEffectBoundaryConcurrentSameKey exercises the idempotency
// check-and-reserve under concurrent submissions of the same key. Run with
// -race: an unsynchronized boundary either data-races on the maps or admits
// more than one effect for the shared key.
func TestInMemoryEffectBoundaryConcurrentSameKey(t *testing.T) {
	boundary := NewInMemoryEffectBoundary(nil, nil)

	const goroutines = 32
	var wg sync.WaitGroup
	ids := make([]string, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			req := &EffectRequest{
				EffectType: EffectTypeDataWrite,
				Subject:    EffectSubject{SubjectID: "user-1", SubjectType: "human"},
				Payload:    EffectPayload{Data: map[string]interface{}{"n": idx}},
				Idempotency: &IdempotencyConfig{
					Key:           "shared-key",
					KeyDerivation: "client_provided",
				},
			}
			if _, err := boundary.Submit(context.Background(), req); err != nil {
				t.Errorf("Submit failed: %v", err)
				return
			}
			ids[idx] = req.EffectID
		}(i)
	}
	wg.Wait()

	// Exactly one effect may be reserved for the shared idempotency key.
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	if got := len(boundary.effects); got != 1 {
		t.Fatalf("idempotency admitted %d effects for one key, want 1", got)
	}
	if got := len(boundary.idempotencyLog); got != 1 {
		t.Fatalf("idempotencyLog has %d entries, want 1", got)
	}
}

// mockPDPEvaluator for testing
type mockPDPEvaluator struct {
	decision   string
	decisionID string
	err        error
	calls      int
}

func (m *mockPDPEvaluator) Evaluate(ctx context.Context, req *EffectRequest) (string, string, error) {
	m.calls++
	return m.decision, m.decisionID, m.err
}

func TestInMemoryEffectBoundaryRejectsLaunchPreviewBeforeStorageOrPDP(t *testing.T) {
	pdp := &mockPDPEvaluator{decision: "ALLOW", decisionID: "must-not-run"}
	boundary := NewInMemoryEffectBoundary(pdp, nil)

	for _, preview := range contracts.LaunchMissionEffectCatalogPreview().EffectTypes {
		req := &EffectRequest{
			EffectType: EffectType(preview.TypeID),
			Subject:    EffectSubject{SubjectID: "user-1", SubjectType: "human"},
			Payload:    EffectPayload{Data: map[string]interface{}{"mission_id": "mission-1"}},
		}
		if _, err := boundary.Submit(context.Background(), req); err == nil {
			t.Errorf("preview effect %s reached the production boundary", preview.TypeID)
		}
	}
	if pdp.calls != 0 {
		t.Fatalf("PDP evaluated %d rejected preview effects", pdp.calls)
	}
	if len(boundary.effects) != 0 || len(boundary.lifecycles) != 0 {
		t.Fatalf("rejected preview effects were stored: effects=%d lifecycles=%d", len(boundary.effects), len(boundary.lifecycles))
	}
}

func TestExecutableEffectTypeAllowlistRejectsUnknown(t *testing.T) {
	if !IsExecutableEffectType(EffectTypeDataWrite) {
		t.Fatal("known runtime effect was removed from the executable allowlist")
	}
	for _, definition := range contracts.DefaultEffectCatalog().EffectTypes {
		if !IsExecutableEffectType(EffectType(definition.TypeID)) {
			t.Errorf("production catalog effect %s was removed from the boundary", definition.TypeID)
		}
	}
	if IsExecutableEffectType(EffectType("UNKNOWN_EFFECT")) {
		t.Fatal("unknown effect entered the executable allowlist")
	}
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
