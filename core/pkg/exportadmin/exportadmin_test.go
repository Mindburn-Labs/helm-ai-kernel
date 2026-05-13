package exportadmin

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

func TestRequestExport_CreatesINTENTNode(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryExportStore()
	graph := proofgraph.NewGraph()
	admin := NewExportAdmin(store, graph)

	req := &ExportRequest{
		RequestID:   "exp-001",
		TenantID:    "t-001",
		Format:      "evidence_pack",
		DateFrom:    time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		DateTo:      time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
		RequestedBy: "user-admin",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}

	if err := admin.RequestExport(ctx, req); err != nil {
		t.Fatalf("RequestExport failed: %v", err)
	}

	// Verify INTENT node was created.
	if graph.Len() != 1 {
		t.Fatalf("expected 1 proofgraph node, got %d", graph.Len())
	}

	nodes := graph.AllNodes()
	if nodes[0].Kind != proofgraph.NodeTypeIntent {
		t.Errorf("expected INTENT node, got %s", nodes[0].Kind)
	}

	// Verify request was stored.
	got, err := admin.GetExport(ctx, "exp-001")
	if err != nil {
		t.Fatalf("GetExport failed: %v", err)
	}
	if got.Status != StatusPending {
		t.Errorf("expected status PENDING, got %s", got.Status)
	}
}

func TestCompleteExport_CreatesEFFECTNode(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryExportStore()
	graph := proofgraph.NewGraph()
	admin := NewExportAdmin(store, graph)

	req := &ExportRequest{
		RequestID:   "exp-002",
		TenantID:    "t-001",
		Format:      "audit_log",
		DateFrom:    time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		DateTo:      time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
		RequestedBy: "user-admin",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}

	if err := admin.RequestExport(ctx, req); err != nil {
		t.Fatalf("RequestExport failed: %v", err)
	}

	manifest := &ExportManifest{
		RequestID:     "exp-002",
		TenantID:      "t-001",
		Format:        "audit_log",
		EntryCount:    42,
		ContentHash:   "sha256:abc123",
		SignatureHash: "sha256:sig456",
		Entries:       []string{"entry-1.json", "entry-2.json"},
	}

	if err := admin.CompleteExport(ctx, "exp-002", manifest); err != nil {
		t.Fatalf("CompleteExport failed: %v", err)
	}

	// Verify EFFECT node was created (INTENT + EFFECT = 2 nodes).
	if graph.Len() != 2 {
		t.Fatalf("expected 2 proofgraph nodes, got %d", graph.Len())
	}

	// Verify request status updated.
	got, _ := admin.GetExport(ctx, "exp-002")
	if got.Status != StatusReady {
		t.Errorf("expected status READY, got %s", got.Status)
	}

	// Verify manifest stored with ProofGraph node reference.
	m, err := admin.GetManifest(ctx, "exp-002")
	if err != nil {
		t.Fatalf("GetManifest failed: %v", err)
	}
	if m.ProofGraphNode == "" {
		t.Error("manifest should have ProofGraph node reference")
	}
	if m.ContentHash != "sha256:abc123" {
		t.Errorf("content hash = %s, want sha256:abc123", m.ContentHash)
	}
}

func TestListExports_ByTenant(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryExportStore()
	graph := proofgraph.NewGraph()
	admin := NewExportAdmin(store, graph)

	// Create exports for two tenants.
	for _, id := range []string{"exp-t1-a", "exp-t1-b"} {
		admin.RequestExport(ctx, &ExportRequest{
			RequestID:   id,
			TenantID:    "t-001",
			Format:      "evidence_pack",
			DateFrom:    time.Now(),
			DateTo:      time.Now(),
			RequestedBy: "user-1",
			ExpiresAt:   time.Now().Add(time.Hour),
		})
	}
	admin.RequestExport(ctx, &ExportRequest{
		RequestID:   "exp-t2-a",
		TenantID:    "t-002",
		Format:      "audit_log",
		DateFrom:    time.Now(),
		DateTo:      time.Now(),
		RequestedBy: "user-2",
		ExpiresAt:   time.Now().Add(time.Hour),
	})

	list, err := admin.ListExports(ctx, "t-001")
	if err != nil {
		t.Fatalf("ListExports failed: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 exports for t-001, got %d", len(list))
	}

	list, err = admin.ListExports(ctx, "t-002")
	if err != nil {
		t.Fatalf("ListExports failed: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 export for t-002, got %d", len(list))
	}
}

func TestRequestExport_ValidationErrors(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryExportStore()
	graph := proofgraph.NewGraph()
	admin := NewExportAdmin(store, graph)

	// Missing request ID.
	err := admin.RequestExport(ctx, &ExportRequest{
		TenantID: "t-001",
	})
	if err == nil {
		t.Error("missing request_id should fail")
	}

	// Missing tenant ID.
	err = admin.RequestExport(ctx, &ExportRequest{
		RequestID: "exp-001",
	})
	if err == nil {
		t.Error("missing tenant_id should fail")
	}
}

func TestExportManifest_ContentHashVerification(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryExportStore()
	graph := proofgraph.NewGraph()
	admin := NewExportAdmin(store, graph)

	admin.RequestExport(ctx, &ExportRequest{
		RequestID:   "exp-hash",
		TenantID:    "t-001",
		Format:      "evidence_pack",
		DateFrom:    time.Now(),
		DateTo:      time.Now(),
		RequestedBy: "user-1",
		ExpiresAt:   time.Now().Add(time.Hour),
	})

	manifest := &ExportManifest{
		RequestID:     "exp-hash",
		TenantID:      "t-001",
		Format:        "evidence_pack",
		EntryCount:    10,
		ContentHash:   "sha256:deterministic_content_hash_here",
		SignatureHash: "sha256:signature_hash_here",
		Entries:       []string{"a.json", "b.json"},
	}

	admin.CompleteExport(ctx, "exp-hash", manifest)

	got, _ := admin.GetManifest(ctx, "exp-hash")
	if got.ContentHash != manifest.ContentHash {
		t.Errorf("content hash mismatch: got %s, want %s", got.ContentHash, manifest.ContentHash)
	}
	if got.EntryCount != 10 {
		t.Errorf("entry count = %d, want 10", got.EntryCount)
	}
}

func TestCompleteExport_NonexistentRequest(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryExportStore()
	graph := proofgraph.NewGraph()
	admin := NewExportAdmin(store, graph)

	err := admin.CompleteExport(ctx, "nonexistent", &ExportManifest{})
	if err == nil {
		t.Error("completing nonexistent request should fail")
	}
}
