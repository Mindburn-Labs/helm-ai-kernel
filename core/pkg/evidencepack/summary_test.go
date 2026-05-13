package evidencepack_test

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
)

func newTestManifest() *evidencepack.Manifest {
	return &evidencepack.Manifest{
		Version:    evidencepack.ManifestVersion,
		PackID:     "pack-summary-1",
		CreatedAt:  time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC),
		ActorDID:   "did:helm:actor-1",
		IntentID:   "intent-1",
		PolicyHash: "sha256:policyabc",
		Entries: []evidencepack.ManifestEntry{
			{
				Path:        "receipts/decision-1.json",
				ContentHash: "sha256:aaa111",
				Size:        1024,
				ContentType: "application/json",
			},
			{
				Path:        "policy/gate-1.json",
				ContentHash: "sha256:bbb222",
				Size:        512,
				ContentType: "application/json",
			},
			{
				Path:        "transcripts/tool-exec.json",
				ContentHash: "sha256:ccc333",
				Size:        2048,
				ContentType: "application/json",
			},
			{
				Path:        "signatures/signer-1.sig",
				ContentHash: "sha256:ddd444",
				Size:        256,
				ContentType: "application/octet-stream",
			},
		},
		ManifestHash: "sha256:manifest-hash-fixture",
	}
}

func TestGenerateSummary(t *testing.T) {
	manifest := newTestManifest()

	summary, err := evidencepack.GenerateSummary(manifest)
	if err != nil {
		t.Fatalf("GenerateSummary failed: %v", err)
	}

	if summary.PackID != manifest.PackID {
		t.Errorf("PackID = %s, want %s", summary.PackID, manifest.PackID)
	}
	if summary.ManifestHash != manifest.ManifestHash {
		t.Errorf("ManifestHash = %s, want %s", summary.ManifestHash, manifest.ManifestHash)
	}
	if summary.EntryCount != 4 {
		t.Errorf("EntryCount = %d, want 4", summary.EntryCount)
	}
	if summary.TotalBytes != 1024+512+2048+256 {
		t.Errorf("TotalBytes = %d, want %d", summary.TotalBytes, 1024+512+2048+256)
	}
	if summary.PolicyHash != manifest.PolicyHash {
		t.Errorf("PolicyHash = %s, want %s", summary.PolicyHash, manifest.PolicyHash)
	}
	if summary.SummaryHash == "" {
		t.Error("SummaryHash should not be empty")
	}
	if summary.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should be set")
	}
	if summary.SignatureCount != 1 {
		t.Errorf("SignatureCount = %d, want 1", summary.SignatureCount)
	}
}

func TestGenerateSummary_NilManifest(t *testing.T) {
	_, err := evidencepack.GenerateSummary(nil)
	if err == nil {
		t.Fatal("expected error for nil manifest")
	}
}

func TestSummary_Verify(t *testing.T) {
	manifest := newTestManifest()

	summary, err := evidencepack.GenerateSummary(manifest)
	if err != nil {
		t.Fatalf("GenerateSummary failed: %v", err)
	}

	if err := summary.Verify(); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

func TestSummary_Verify_TamperDetection(t *testing.T) {
	manifest := newTestManifest()

	summary, err := evidencepack.GenerateSummary(manifest)
	if err != nil {
		t.Fatalf("GenerateSummary failed: %v", err)
	}

	// Tamper with the entry count.
	summary.EntryCount = 999

	if err := summary.Verify(); err == nil {
		t.Fatal("expected verification failure after tampering with EntryCount")
	}
}

func TestSummary_Verify_TamperPackID(t *testing.T) {
	manifest := newTestManifest()

	summary, err := evidencepack.GenerateSummary(manifest)
	if err != nil {
		t.Fatalf("GenerateSummary failed: %v", err)
	}

	// Tamper with the pack ID.
	summary.PackID = "tampered-pack"

	if err := summary.Verify(); err == nil {
		t.Fatal("expected verification failure after tampering with PackID")
	}
}

func TestSummary_Verify_EmptyHash(t *testing.T) {
	summary := &evidencepack.EvidenceSummary{
		PackID:      "test",
		SummaryHash: "",
	}

	if err := summary.Verify(); err == nil {
		t.Fatal("expected error for empty summary hash")
	}
}

func TestSummary_HasNodeType(t *testing.T) {
	manifest := newTestManifest()

	summary, err := evidencepack.GenerateSummary(manifest)
	if err != nil {
		t.Fatalf("GenerateSummary failed: %v", err)
	}

	// receipts/ maps to ATTESTATION.
	if !summary.HasNodeType("ATTESTATION") {
		t.Error("expected ATTESTATION node type")
	}

	// policy/ maps to INTENT.
	if !summary.HasNodeType("INTENT") {
		t.Error("expected INTENT node type")
	}

	// transcripts/ maps to EFFECT.
	if !summary.HasNodeType("EFFECT") {
		t.Error("expected EFFECT node type")
	}

	// Should NOT have TRUST_EVENT (no secrets/ entries).
	if summary.HasNodeType("MERGE_DECISION") {
		t.Error("did not expect MERGE_DECISION node type")
	}
}

func TestSummary_Duration(t *testing.T) {
	manifest := newTestManifest()

	summary, err := evidencepack.GenerateSummary(manifest)
	if err != nil {
		t.Fatalf("GenerateSummary failed: %v", err)
	}

	// FirstEvent and LastEvent both derive from manifest CreatedAt,
	// so duration is zero for a single-manifest summary.
	if summary.Duration() != 0 {
		t.Errorf("Duration = %v, want 0", summary.Duration())
	}
}

func TestSummary_Duration_WithSpan(t *testing.T) {
	manifest := newTestManifest()

	summary, err := evidencepack.GenerateSummary(manifest)
	if err != nil {
		t.Fatalf("GenerateSummary failed: %v", err)
	}

	// Simulate a span by adjusting timestamps before hash computation.
	// This tests the Duration method directly.
	summary.FirstEvent = time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC)
	summary.LastEvent = time.Date(2026, 4, 10, 14, 30, 0, 0, time.UTC)

	expected := 2*time.Hour + 30*time.Minute
	if summary.Duration() != expected {
		t.Errorf("Duration = %v, want %v", summary.Duration(), expected)
	}
}

func TestGenerateSummary_EmptyManifest(t *testing.T) {
	manifest := &evidencepack.Manifest{
		Version:      evidencepack.ManifestVersion,
		PackID:       "empty-pack",
		CreatedAt:    time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC),
		ActorDID:     "did:helm:actor-1",
		IntentID:     "intent-1",
		PolicyHash:   "sha256:empty",
		Entries:      []evidencepack.ManifestEntry{},
		ManifestHash: "sha256:empty-manifest",
	}

	summary, err := evidencepack.GenerateSummary(manifest)
	if err != nil {
		t.Fatalf("GenerateSummary failed for empty manifest: %v", err)
	}

	if summary.EntryCount != 0 {
		t.Errorf("EntryCount = %d, want 0", summary.EntryCount)
	}
	if summary.TotalBytes != 0 {
		t.Errorf("TotalBytes = %d, want 0", summary.TotalBytes)
	}
	if len(summary.NodeTypes) != 0 {
		t.Errorf("NodeTypes = %v, want empty", summary.NodeTypes)
	}
	if summary.SignatureCount != 0 {
		t.Errorf("SignatureCount = %d, want 0", summary.SignatureCount)
	}
	if summary.SummaryHash == "" {
		t.Error("SummaryHash should be set even for empty manifest")
	}

	// Should still verify.
	if err := summary.Verify(); err != nil {
		t.Fatalf("Verify failed for empty manifest summary: %v", err)
	}
}

func TestGenerateSummary_NodeTypeDeduplicated(t *testing.T) {
	manifest := &evidencepack.Manifest{
		Version:    evidencepack.ManifestVersion,
		PackID:     "dedup-pack",
		CreatedAt:  time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC),
		ActorDID:   "did:helm:actor-1",
		IntentID:   "intent-1",
		PolicyHash: "sha256:dedup",
		Entries: []evidencepack.ManifestEntry{
			{Path: "receipts/r1.json", ContentHash: "sha256:r1", Size: 100, ContentType: "application/json"},
			{Path: "receipts/r2.json", ContentHash: "sha256:r2", Size: 200, ContentType: "application/json"},
			{Path: "receipts/r3.json", ContentHash: "sha256:r3", Size: 300, ContentType: "application/json"},
		},
		ManifestHash: "sha256:dedup-hash",
	}

	summary, err := evidencepack.GenerateSummary(manifest)
	if err != nil {
		t.Fatalf("GenerateSummary failed: %v", err)
	}

	// All three receipts map to ATTESTATION, but should be deduplicated.
	if len(summary.NodeTypes) != 1 {
		t.Errorf("len(NodeTypes) = %d, want 1 (deduplicated)", len(summary.NodeTypes))
	}
	if !summary.HasNodeType("ATTESTATION") {
		t.Error("expected ATTESTATION node type")
	}
}

func TestGenerateSummary_Deterministic(t *testing.T) {
	manifest := newTestManifest()

	s1, err := evidencepack.GenerateSummary(manifest)
	if err != nil {
		t.Fatalf("first GenerateSummary failed: %v", err)
	}

	// Generate again — GeneratedAt will differ, so hashes differ.
	// But pack_id, manifest_hash, counts, etc. are the same.
	s2, err := evidencepack.GenerateSummary(manifest)
	if err != nil {
		t.Fatalf("second GenerateSummary failed: %v", err)
	}

	if s1.PackID != s2.PackID {
		t.Error("PackID should be deterministic")
	}
	if s1.EntryCount != s2.EntryCount {
		t.Error("EntryCount should be deterministic")
	}
	if s1.TotalBytes != s2.TotalBytes {
		t.Error("TotalBytes should be deterministic")
	}
}
