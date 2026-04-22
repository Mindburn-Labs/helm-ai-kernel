package api

import (
	"context"
	"fmt"
	"time"
)

// MemoryService is the public API for the memory architecture.
// In OSS kernel mode, this is a stub that returns empty results.
// Full memory/ingestion pipelines are not part of the kernel TCB.
type MemoryService struct{}

// NewMemoryService creates a new memory service stub.
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

// Ingest is a stub — full ingestion pipeline is not part of kernel TCB.
func (s *MemoryService) Ingest(ctx context.Context, req IngestRequest) (*IngestResponse, error) {
	return nil, fmt.Errorf("ingestion pipeline not available in OSS kernel mode")
}

// ContextResult represents a search result.
type ContextResult struct {
	QueryID string `json:"query_id"`
}

// Search is a stub — full memory search is not part of kernel TCB.
func (s *MemoryService) Search(ctx context.Context, query, tenantID string, maxResults int) (*ContextResult, error) {
	return &ContextResult{
		QueryID: fmt.Sprintf("q-%d", time.Now().UnixNano()),
	}, nil
}
