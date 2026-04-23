package kernel

import (
	"context"
	"testing"
	"time"
)

func TestInMemoryIOCaptureStore(t *testing.T) {
	t.Run("Record and Get", func(t *testing.T) {
		store := NewInMemoryIOCaptureStore()
		ctx := context.Background()

		record := &IORecord{
			RecordID:      "rec-1",
			OperationType: "HTTP_REQUEST",
			Timestamp:     time.Now(),
			EffectID:      "effect-1",
			LoopID:        "loop-1",
		}

		err := store.Record(ctx, record)
		if err != nil {
			t.Fatalf("Record failed: %v", err)
		}

		retrieved, err := store.Get(ctx, "rec-1")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if retrieved.RecordID != "rec-1" {
			t.Error("Retrieved record doesn't match")
		}
	})

	t.Run("Get nonexistent", func(t *testing.T) {
		store := NewInMemoryIOCaptureStore()

		record, err := store.Get(context.Background(), "nonexistent")
		if err != nil {
			t.Errorf("Get should not error: %v", err)
		}
		if record != nil {
			t.Error("Record should be nil for nonexistent")
		}
	})

	t.Run("ListByEffect", func(t *testing.T) {
		store := NewInMemoryIOCaptureStore()
		ctx := context.Background()

		_ = store.Record(ctx, &IORecord{RecordID: "rec-1", EffectID: "effect-1"})
		_ = store.Record(ctx, &IORecord{RecordID: "rec-2", EffectID: "effect-1"})
		_ = store.Record(ctx, &IORecord{RecordID: "rec-3", EffectID: "effect-2"})

		records, err := store.ListByEffect(ctx, "effect-1")
		if err != nil {
			t.Fatalf("ListByEffect failed: %v", err)
		}
		if len(records) != 2 {
			t.Errorf("ListByEffect length = %d, want 2", len(records))
		}
	})

	t.Run("ListByLoop", func(t *testing.T) {
		store := NewInMemoryIOCaptureStore()
		ctx := context.Background()

		_ = store.Record(ctx, &IORecord{RecordID: "rec-1", LoopID: "loop-1"})
		_ = store.Record(ctx, &IORecord{RecordID: "rec-2", LoopID: "loop-1"})
		_ = store.Record(ctx, &IORecord{RecordID: "rec-3", LoopID: "loop-2"})

		records, err := store.ListByLoop(ctx, "loop-1")
		if err != nil {
			t.Fatalf("ListByLoop failed: %v", err)
		}
		if len(records) != 2 {
			t.Errorf("ListByLoop length = %d, want 2", len(records))
		}
	})
}

func TestIOInterceptor(t *testing.T) {
	t.Run("CaptureRequest", func(t *testing.T) {
		store := NewInMemoryIOCaptureStore()
		interceptor := NewIOInterceptor(store, nil)
		ctx := context.Background()

		req := &HTTPRequestCapture{
			Method: "POST",
			URL:    "https://api.example.com/resource",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		}

		record, err := interceptor.CaptureRequest(ctx, "rec-1", "effect-1", "loop-1", req)
		if err != nil {
			t.Fatalf("CaptureRequest failed: %v", err)
		}
		if record.RecordID != "rec-1" {
			t.Error("RecordID not set")
		}
		if record.OperationType != "http_request" {
			t.Errorf("OperationType = %q, want 'http_request'", record.OperationType)
		}
	})

	t.Run("CaptureResponse", func(t *testing.T) {
		store := NewInMemoryIOCaptureStore()
		interceptor := NewIOInterceptor(store, nil)
		ctx := context.Background()

		req := &HTTPRequestCapture{Method: "GET", URL: "https://api.example.com"}
		record, _ := interceptor.CaptureRequest(ctx, "rec-1", "effect-1", "", req)

		resp := &HTTPResponseCapture{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
		}

		err := interceptor.CaptureResponse(ctx, record, resp, 150)
		if err != nil {
			t.Fatalf("CaptureResponse failed: %v", err)
		}
		if record.DurationMs != 150 {
			t.Errorf("DurationMs = %d, want 150", record.DurationMs)
		}
	})

	t.Run("CaptureRetry", func(t *testing.T) {
		store := NewInMemoryIOCaptureStore()
		interceptor := NewIOInterceptor(store, nil)
		ctx := context.Background()

		req := &HTTPRequestCapture{Method: "GET", URL: "https://api.example.com"}
		record, _ := interceptor.CaptureRequest(ctx, "rec-1", "effect-1", "", req)

		err := interceptor.CaptureRetry(ctx, record, 1, 100*time.Millisecond, "timeout")
		if err != nil {
			t.Fatalf("CaptureRetry failed: %v", err)
		}
	})

	t.Run("RedactAndCommit", func(t *testing.T) {
		store := NewInMemoryIOCaptureStore()
		interceptor := NewIOInterceptor(store, nil)

		record := &IORecord{RecordID: "rec-1"}
		originalData := map[string]interface{}{
			"password": "secret123",
			"username": "user",
		}

		commitment := interceptor.RedactAndCommit(record, []string{"password"}, originalData)
		if commitment == "" {
			t.Error("Commitment should not be empty")
		}
		if record.RedactionCommitment != commitment {
			t.Error("RedactionCommitment not set on record")
		}
	})
}
