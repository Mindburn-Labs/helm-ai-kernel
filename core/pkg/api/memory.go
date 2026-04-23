package api

import (
	"context"
	"fmt"
	"time"
)

// MemoryService is the OSS kernel memory API boundary.
// Full memory/ingestion pipelines are outside the kernel TCB.
type MemoryService struct{}

// NewMemoryService creates the bounded kernel memory service.
func NewMemoryService() *MemoryService {
	return &MemoryService{}
}

// IngestRequest represents a request to ingest data from a source.
type IngestRequest struct {
	TenantID string `json:"tenant_id"`
	SourceID string `json:"source_id"`
}

// IngestResponse represents the result of an ingestion request.
type IngestResponse struct {
	BatchID     string `json:"batch_id"`
	ReceiptID   string `json:"receipt_id"`
	EntityCount int    `json:"entity_count"`
	ChunkCount  int    `json:"chunk_count"`
	MerkleRoot  string `json:"merkle_root"`
	DecisionID  string `json:"decision_id"`
}

// Ingest reports that the full ingestion pipeline is outside OSS kernel scope.
func (s *MemoryService) Ingest(ctx context.Context, req IngestRequest) (*IngestResponse, error) {
	return nil, fmt.Errorf("ingestion pipeline not available in OSS kernel mode")
}

// ContextResult represents a search result.
type ContextResult struct {
	QueryID string `json:"query_id"`
}

// Search creates a kernel-scoped query handle for callers that need a receiptable boundary.
func (s *MemoryService) Search(ctx context.Context, query, tenantID string, maxResults int) (*ContextResult, error) {
	return &ContextResult{
		QueryID: fmt.Sprintf("q-%d", time.Now().UnixNano()),
	}, nil
}
