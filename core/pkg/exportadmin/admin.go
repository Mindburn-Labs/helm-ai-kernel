package exportadmin

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

// ExportAdmin manages evidence export requests with ProofGraph attestation.
// Every request creates an INTENT node; every completion creates an EFFECT node.
type ExportAdmin struct {
	store ExportStore
	graph *proofgraph.Graph
	clock func() time.Time
}

// NewExportAdmin creates a new export admin service.
func NewExportAdmin(store ExportStore, graph *proofgraph.Graph) *ExportAdmin {
	return &ExportAdmin{
		store: store,
		graph: graph,
		clock: time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (a *ExportAdmin) WithClock(clock func() time.Time) *ExportAdmin {
	a.clock = clock
	return a
}

// RequestExport creates a new export request and records an INTENT node in the ProofGraph.
func (a *ExportAdmin) RequestExport(ctx context.Context, req *ExportRequest) error {
	if req.RequestID == "" {
		return fmt.Errorf("request_id is required")
	}
	if req.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}

	req.Status = StatusPending
	req.CreatedAt = a.clock().UTC()

	// Create INTENT node in ProofGraph.
	payload, err := json.Marshal(struct {
		Action    string `json:"action"`
		RequestID string `json:"request_id"`
		TenantID  string `json:"tenant_id"`
		Format    string `json:"format"`
	}{
		Action:    "export_request",
		RequestID: req.RequestID,
		TenantID:  req.TenantID,
		Format:    req.Format,
	})
	if err != nil {
		return fmt.Errorf("marshal intent payload: %w", err)
	}

	_, err = a.graph.Append(proofgraph.NodeTypeIntent, payload, req.RequestedBy, 0)
	if err != nil {
		return fmt.Errorf("append INTENT node: %w", err)
	}

	return a.store.Create(ctx, req)
}

// CompleteExport marks an export as ready with its manifest and records an EFFECT node.
func (a *ExportAdmin) CompleteExport(ctx context.Context, requestID string, manifest *ExportManifest) error {
	req, err := a.store.Get(ctx, requestID)
	if err != nil {
		return fmt.Errorf("get export request: %w", err)
	}

	// Create EFFECT node in ProofGraph.
	payload, err := json.Marshal(struct {
		Action      string `json:"action"`
		RequestID   string `json:"request_id"`
		TenantID    string `json:"tenant_id"`
		ContentHash string `json:"content_hash"`
		EntryCount  int    `json:"entry_count"`
	}{
		Action:      "export_complete",
		RequestID:   requestID,
		TenantID:    req.TenantID,
		ContentHash: manifest.ContentHash,
		EntryCount:  manifest.EntryCount,
	})
	if err != nil {
		return fmt.Errorf("marshal effect payload: %w", err)
	}

	node, err := a.graph.Append(proofgraph.NodeTypeEffect, payload, req.RequestedBy, 0)
	if err != nil {
		return fmt.Errorf("append EFFECT node: %w", err)
	}

	// Record the ProofGraph node reference in the manifest.
	manifest.ProofGraphNode = node.NodeHash

	now := a.clock().UTC()
	req.Status = StatusReady
	req.CompletedAt = &now
	req.OutputHash = manifest.ContentHash

	if err := a.store.UpdateStatus(ctx, requestID, StatusReady); err != nil {
		return fmt.Errorf("update status: %w", err)
	}

	return a.store.SetManifest(ctx, requestID, manifest)
}

// GetExport retrieves an export request.
func (a *ExportAdmin) GetExport(ctx context.Context, requestID string) (*ExportRequest, error) {
	return a.store.Get(ctx, requestID)
}

// ListExports lists exports for a tenant.
func (a *ExportAdmin) ListExports(ctx context.Context, tenantID string) ([]*ExportRequest, error) {
	return a.store.List(ctx, tenantID)
}

// GetManifest retrieves the manifest for a completed export.
func (a *ExportAdmin) GetManifest(ctx context.Context, requestID string) (*ExportManifest, error) {
	return a.store.GetManifest(ctx, requestID)
}
