package kernel

import (
	"context"
	"testing"
)

func TestEventLog_AppendAndGet(t *testing.T) {
	log := NewInMemoryEventLog()
	ctx := context.Background()

	event := &EventEnvelope{
		EventID:   "evt-001",
		EventType: "test.event",
		Payload: map[string]interface{}{
			"key": "value",
		},
	}

	seq, err := log.Append(ctx, event)
	if err != nil {
		t.Fatalf("failed to append event: %v", err)
	}

	if seq != 1 {
		t.Errorf("expected sequence 1, got %d", seq)
	}

	retrieved, err := log.Get(ctx, seq)
	if err != nil {
		t.Fatalf("failed to get event: %v", err)
	}

	if retrieved.EventID != event.EventID {
		t.Errorf("event ID mismatch: got %s, want %s", retrieved.EventID, event.EventID)
	}

	if retrieved.PayloadHash == "" {
		t.Error("payload hash should be computed")
	}

	if log.Hash() == "" {
		t.Error("cumulative hash should be computed")
	}
}

func TestEventLog_CanonicalHashDeterminism(t *testing.T) {
	// Create two logs with same events
	log1 := NewInMemoryEventLog()
	log2 := NewInMemoryEventLog()
	ctx := context.Background()

	event := &EventEnvelope{
		EventID:   "evt-001",
		EventType: "test.event",
		Payload: map[string]interface{}{
			"b": "second",
			"a": "first",
			"c": "third",
		},
	}

	_, _ = log1.Append(ctx, event)
	_, _ = log2.Append(ctx, event)

	// Same events should produce same hash regardless of internal ordering
	if log1.Hash() != log2.Hash() {
		t.Errorf("determinism violation: log1.Hash=%s, log2.Hash=%s", log1.Hash(), log2.Hash())
	}
}

func TestReducer_DeterministicConflictResolution(t *testing.T) {
	reducer := NewDeterministicReducer(ConflictPolicyFirstSuccess)
	ctx := context.Background()

	inputs := []ReducerInput{
		{SequenceNumber: 1, Key: "x", Value: "first", SortKey: "1"},
		{SequenceNumber: 2, Key: "x", Value: "second", SortKey: "2"},
		{SequenceNumber: 3, Key: "y", Value: "only", SortKey: "3"},
	}

	output, err := reducer.Reduce(ctx, inputs)
	if err != nil {
		t.Fatalf("reduce failed: %v", err)
	}

	// First success policy: first write wins
	if output.State["x"] != "first" {
		t.Errorf("expected x=first, got %v", output.State["x"])
	}

	if output.State["y"] != "only" {
		t.Errorf("expected y=only, got %v", output.State["y"])
	}

	if len(output.Conflicts) != 1 {
		t.Errorf("expected 1 conflict, got %d", len(output.Conflicts))
	}
}

func TestReducer_Confluence(t *testing.T) {
	inputs := []ReducerInput{
		{SequenceNumber: 1, Key: "a", Value: 1, SortKey: "001"},
		{SequenceNumber: 2, Key: "b", Value: 2, SortKey: "002"},
		{SequenceNumber: 3, Key: "c", Value: 3, SortKey: "003"},
	}

	reducer := NewDeterministicReducer(ConflictPolicyFirstSuccess)
	confluent, err := TestReducerConfluence(reducer, inputs, 5)
	if err != nil {
		t.Fatalf("confluence test failed: %v", err)
	}

	if !confluent {
		t.Error("reducer should be confluent")
	}
}

func TestEffectBoundary_IdempotencyEnforcement(t *testing.T) {
	boundary := NewInMemoryEffectBoundary(nil, nil)
	ctx := context.Background()

	req := &EffectRequest{
		EffectType: EffectTypeDataWrite,
		Subject:    EffectSubject{SubjectID: "user-1", SubjectType: "human"},
		Idempotency: &IdempotencyConfig{
			Key:           "unique-key-123",
			KeyDerivation: "client_provided",
		},
	}

	// First submission
	lifecycle1, err := boundary.Submit(ctx, req)
	if err != nil {
		t.Fatalf("first submit failed: %v", err)
	}

	effectID1 := req.EffectID

	// Second submission with same idempotency key
	req2 := &EffectRequest{
		EffectType: EffectTypeDataWrite,
		Subject:    EffectSubject{SubjectID: "user-1", SubjectType: "human"},
		Idempotency: &IdempotencyConfig{
			Key:           "unique-key-123",
			KeyDerivation: "client_provided",
		},
	}

	lifecycle2, err := boundary.Submit(ctx, req2)
	if err != nil {
		t.Fatalf("second submit failed: %v", err)
	}

	// Should return same lifecycle (idempotent)
	if lifecycle1.State != lifecycle2.State {
		t.Error("idempotent submissions should return same lifecycle")
	}

	// Check idempotency detection
	exists, foundID, _ := boundary.CheckIdempotency(ctx, "unique-key-123")
	if !exists {
		t.Error("idempotency key should exist")
	}
	if foundID != effectID1 {
		t.Errorf("idempotency key should map to first effect ID, got %s want %s", foundID, effectID1)
	}
}

func TestPRNG_Determinism(t *testing.T) {
	seed := []byte("12345678901234567890123456789012") // 32 bytes

	prng1, _ := NewDeterministicPRNG(DefaultPRNGConfig(), seed, "loop-1", nil)
	prng2, _ := NewDeterministicPRNG(DefaultPRNGConfig(), seed, "loop-1", nil)

	// Same seed should produce same sequence
	for i := 0; i < 100; i++ {
		v1 := prng1.Uint64()
		v2 := prng2.Uint64()
		if v1 != v2 {
			t.Errorf("determinism violation at step %d: %d != %d", i, v1, v2)
			break
		}
	}
}

func TestPRNG_SeedDerivation(t *testing.T) {
	rootSeed := []byte("12345678901234567890123456789012")

	seed1 := SeedFromLoopID(rootSeed, "loop-A")
	seed2 := SeedFromLoopID(rootSeed, "loop-B")
	seed1Again := SeedFromLoopID(rootSeed, "loop-A")

	// Different loops should have different seeds
	if string(seed1) == string(seed2) {
		t.Error("different loops should have different seeds")
	}

	// Same loop should derive same seed
	if string(seed1) != string(seed1Again) {
		t.Error("same loop should derive same seed")
	}
}
