package kernel

import "testing"

func TestNondeterminismCapture(t *testing.T) {
	tr := NewNondeterminismTracker()
	b := tr.Capture("run-1", NDSourceLLM, "GPT-4 response", "sha256:in", "sha256:out", "")
	if b.BoundID == "" {
		t.Fatal("expected bound ID")
	}
	if b.Source != NDSourceLLM {
		t.Fatal("expected LLM source")
	}
	if b.ContentHash == "" {
		t.Fatal("expected content hash")
	}
}

func TestNondeterminismMultipleSources(t *testing.T) {
	tr := NewNondeterminismTracker()
	tr.Capture("run-1", NDSourceLLM, "llm", "h1", "h2", "")
	tr.Capture("run-1", NDSourceNetwork, "api call", "h3", "h4", "")
	tr.Capture("run-1", NDSourceRandom, "seed", "h5", "h6", "seed-42")

	bounds := tr.BoundsForRun("run-1")
	if len(bounds) != 3 {
		t.Fatalf("expected 3 bounds, got %d", len(bounds))
	}
}

func TestNondeterminismReceipt(t *testing.T) {
	tr := NewNondeterminismTracker()
	tr.Capture("run-1", NDSourceLLM, "test", "h1", "h2", "")

	receipt, err := tr.Receipt("run-1")
	if err != nil {
		t.Fatal(err)
	}
	if receipt.TotalBounds != 1 {
		t.Fatalf("expected 1 bound, got %d", receipt.TotalBounds)
	}
	if receipt.ContentHash == "" {
		t.Fatal("expected content hash")
	}
}

func TestNondeterminismReceiptNotFound(t *testing.T) {
	tr := NewNondeterminismTracker()
	_, err := tr.Receipt("nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNondeterminismSeedCapture(t *testing.T) {
	tr := NewNondeterminismTracker()
	b := tr.Capture("run-1", NDSourceRandom, "rng", "", "", "seed-123")
	if b.Seed != "seed-123" {
		t.Fatal("expected seed preserved")
	}
}
