package kernel

import (
	"context"
	"encoding/json"
	"testing"
)

func TestInMemoryTotalOrderLogBasics(t *testing.T) {
	log := NewInMemoryTotalOrderLog()
	ctx := context.Background()

	// Len of empty log
	if log.Len() != 0 {
		t.Error("Empty log should have length 0")
	}

	// Head of empty log
	_, err := log.Head(ctx)
	if err == nil {
		t.Error("Head of empty log should error")
	}

	// Commit first entry
	event := json.RawMessage(`{"key": "value"}`)
	toe, err := log.Commit(ctx, event, "loop-1")
	if err != nil {
		t.Fatal(err)
	}
	if toe == nil {
		t.Fatal("Commit returned nil")
	}
	if toe.OrderPosition != 0 {
		t.Errorf("First event position = %d, want 0", toe.OrderPosition)
	}

	// Len should be 1
	if log.Len() != 1 {
		t.Error("Len should be 1")
	}

	// Head should return the entry
	head, err := log.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head.CommitHash != toe.CommitHash {
		t.Error("Head should match committed event")
	}

	// Get should return the entry
	got, err := log.Get(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.CommitHash != toe.CommitHash {
		t.Error("Get should return committed event")
	}

	// Get non-existent
	_, err = log.Get(ctx, 999)
	if err == nil {
		t.Error("Get non-existent should error")
	}
}

func TestInMemoryTotalOrderLogRange(t *testing.T) {
	log := NewInMemoryTotalOrderLog()
	ctx := context.Background()

	// Add multiple entries
	for i := 0; i < 5; i++ {
		event := json.RawMessage(`{"index": ` + string(rune('0'+i)) + `}`)
		_, _ = log.Commit(ctx, event, "loop-test")
	}

	// Range entire log
	entries, err := log.Range(ctx, 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Errorf("Range(0,5) = %d entries, want 5", len(entries))
	}

	// Range partial
	entries, err = log.Range(ctx, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Errorf("Range(1,4) = %d entries, want 3", len(entries))
	}

	// Range out of bounds
	entries, err = log.Range(ctx, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Error("Range out of bounds should return empty")
	}
}

func TestInMemoryTotalOrderLogVerify(t *testing.T) {
	log := NewInMemoryTotalOrderLog()
	ctx := context.Background()

	// Add entries
	for i := 0; i < 3; i++ {
		event := json.RawMessage(`{"seq": ` + string(rune('0'+i)) + `}`)
		_, _ = log.Commit(ctx, event, "loop-1")
	}

	// Verify should pass
	valid, err := log.Verify(ctx, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("Log should be valid")
	}

	// Verify empty range
	valid, err = log.Verify(ctx, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("Empty range should be valid")
	}
}

func TestComputeCommitHashDeterminism(t *testing.T) {
	events := []json.RawMessage{
		json.RawMessage(`{"event": 1}`),
		json.RawMessage(`{"event": 2}`),
		json.RawMessage(`{"event": 3}`),
	}

	result := CommitSemanticsDeterminismTest(events)
	if !result {
		t.Error("Commit semantics should maintain structure")
	}
}
