package evidencepack

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func TestStreamBuilder_BasicRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "pack-1", "did:helm:test", "intent-1", "sha256:policy123")
	sb.WithCreatedAt(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	if err := sb.AddEntry("data/file1.txt", []byte("hello"), "text/plain"); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	if err := sb.AddEntry("data/file2.txt", []byte("world"), "text/plain"); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}

	manifest, err := sb.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	if manifest.PackID != "pack-1" {
		t.Errorf("expected pack-1, got %s", manifest.PackID)
	}
	if len(manifest.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(manifest.Entries))
	}
	if manifest.ManifestHash == "" {
		t.Error("manifest hash should be non-empty")
	}

	// Read back with StreamReader
	sr := NewStreamReader(bytes.NewReader(buf.Bytes()))
	entries, err := sr.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	// 2 data entries + 1 manifest = 3 total
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (2 data + manifest), got %d", len(entries))
	}

	// Verify manifest was parsed
	readManifest := sr.Manifest()
	if readManifest == nil {
		t.Fatal("manifest should be parsed after ReadAll")
	}
	if readManifest.PackID != "pack-1" {
		t.Errorf("expected pack-1, got %s", readManifest.PackID)
	}
}

func TestStreamBuilder_AddReceipt(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "pack-2", "did:helm:test", "intent-2", "sha256:pol")

	receipt := map[string]string{"id": "rcpt-1", "verdict": "ALLOW"}
	if err := sb.AddReceipt("rcpt-1", receipt); err != nil {
		t.Fatalf("AddReceipt: %v", err)
	}

	manifest, err := sb.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	if len(manifest.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(manifest.Entries))
	}
	if manifest.Entries[0].Path != "receipts/rcpt-1.json" {
		t.Errorf("expected receipts/rcpt-1.json, got %s", manifest.Entries[0].Path)
	}
	if manifest.Entries[0].ContentType != "application/json" {
		t.Errorf("expected application/json, got %s", manifest.Entries[0].ContentType)
	}
}

func TestStreamBuilder_EntriesSorted(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "pack-3", "did:helm:test", "intent-3", "sha256:pol")

	// Add in reverse order
	sb.AddEntry("z_last.txt", []byte("z"), "text/plain")
	sb.AddEntry("a_first.txt", []byte("a"), "text/plain")
	sb.AddEntry("m_middle.txt", []byte("m"), "text/plain")

	manifest, err := sb.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	// Manifest entries should be sorted
	if manifest.Entries[0].Path != "a_first.txt" {
		t.Errorf("expected first entry a_first.txt, got %s", manifest.Entries[0].Path)
	}
	if manifest.Entries[1].Path != "m_middle.txt" {
		t.Errorf("expected second entry m_middle.txt, got %s", manifest.Entries[1].Path)
	}
	if manifest.Entries[2].Path != "z_last.txt" {
		t.Errorf("expected third entry z_last.txt, got %s", manifest.Entries[2].Path)
	}
}

func TestStreamBuilder_FinalizedTwice(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "pack-4", "did:helm:test", "intent-4", "sha256:pol")
	sb.AddEntry("test.txt", []byte("data"), "text/plain")
	sb.Finalize()

	// Adding after finalize should fail
	err := sb.AddEntry("another.txt", []byte("more"), "text/plain")
	if err == nil {
		t.Error("expected error adding entry after finalize")
	}

	// Finalizing again should fail
	_, err = sb.Finalize()
	if err == nil {
		t.Error("expected error finalizing twice")
	}
}

func TestStreamBuilder_ContentHashes(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "pack-5", "did:helm:test", "intent-5", "sha256:pol")

	sb.AddEntry("test.txt", []byte("hello world"), "text/plain")
	manifest, err := sb.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	// Content hash should be SHA-256 of "hello world"
	entry := manifest.Entries[0]
	if entry.ContentHash == "" {
		t.Error("content hash should be non-empty")
	}
	if len(entry.ContentHash) != 71 { // "sha256:" + 64 hex chars
		t.Errorf("unexpected content hash length: %d", len(entry.ContentHash))
	}
}

func TestStreamReader_Iterative(t *testing.T) {
	// Build a pack
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "pack-6", "did:helm:test", "intent-6", "sha256:pol")
	sb.AddEntry("a.txt", []byte("aaa"), "text/plain")
	sb.AddEntry("b.txt", []byte("bbb"), "text/plain")
	sb.Finalize()

	// Read iteratively
	sr := NewStreamReader(bytes.NewReader(buf.Bytes()))
	count := 0
	for {
		_, err := sr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		count++
	}

	if count != 3 { // 2 entries + manifest
		t.Errorf("expected 3 entries, got %d", count)
	}
}

func TestStreamBuilder_EntryCount(t *testing.T) {
	var buf bytes.Buffer
	sb := NewStreamBuilder(&buf, "pack-7", "did:helm:test", "intent-7", "sha256:pol")

	if sb.EntryCount() != 0 {
		t.Errorf("expected 0, got %d", sb.EntryCount())
	}

	sb.AddEntry("a.txt", []byte("a"), "text/plain")
	if sb.EntryCount() != 1 {
		t.Errorf("expected 1, got %d", sb.EntryCount())
	}

	sb.AddEntry("b.txt", []byte("b"), "text/plain")
	if sb.EntryCount() != 2 {
		t.Errorf("expected 2, got %d", sb.EntryCount())
	}
}
