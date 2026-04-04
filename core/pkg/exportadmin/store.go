package exportadmin

import (
	"context"
	"fmt"
	"sync"
)

// ExportStore manages export request persistence.
type ExportStore interface {
	Create(ctx context.Context, req *ExportRequest) error
	Get(ctx context.Context, requestID string) (*ExportRequest, error)
	List(ctx context.Context, tenantID string) ([]*ExportRequest, error)
	UpdateStatus(ctx context.Context, requestID, status string) error
	SetManifest(ctx context.Context, requestID string, manifest *ExportManifest) error
	GetManifest(ctx context.Context, requestID string) (*ExportManifest, error)
}

// InMemoryExportStore is a thread-safe in-memory implementation of ExportStore.
type InMemoryExportStore struct {
	mu        sync.RWMutex
	requests  map[string]*ExportRequest
	manifests map[string]*ExportManifest
}

// NewInMemoryExportStore creates a new in-memory export store.
func NewInMemoryExportStore() *InMemoryExportStore {
	return &InMemoryExportStore{
		requests:  make(map[string]*ExportRequest),
		manifests: make(map[string]*ExportManifest),
	}
}

func (s *InMemoryExportStore) Create(_ context.Context, req *ExportRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.requests[req.RequestID]; exists {
		return fmt.Errorf("export request %s already exists", req.RequestID)
	}
	s.requests[req.RequestID] = req
	return nil
}

func (s *InMemoryExportStore) Get(_ context.Context, requestID string) (*ExportRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.requests[requestID]
	if !ok {
		return nil, fmt.Errorf("export request %s not found", requestID)
	}
	return r, nil
}

func (s *InMemoryExportStore) List(_ context.Context, tenantID string) ([]*ExportRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*ExportRequest
	for _, r := range s.requests {
		if r.TenantID == tenantID {
			result = append(result, r)
		}
	}
	return result, nil
}

func (s *InMemoryExportStore) UpdateStatus(_ context.Context, requestID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.requests[requestID]
	if !ok {
		return fmt.Errorf("export request %s not found", requestID)
	}
	r.Status = status
	return nil
}

func (s *InMemoryExportStore) SetManifest(_ context.Context, requestID string, manifest *ExportManifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.requests[requestID]; !ok {
		return fmt.Errorf("export request %s not found", requestID)
	}
	s.manifests[requestID] = manifest
	return nil
}

func (s *InMemoryExportStore) GetManifest(_ context.Context, requestID string) (*ExportManifest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.manifests[requestID]
	if !ok {
		return nil, fmt.Errorf("manifest for request %s not found", requestID)
	}
	return m, nil
}
