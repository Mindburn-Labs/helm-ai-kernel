package anchor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Service orchestrates periodic anchoring of the ProofGraph to transparency logs.
// It maintains anchor state and supports multiple backends with failover.
type Service struct {
	mu sync.RWMutex

	// backends are the transparency log backends, tried in priority order.
	backends []AnchorBackend

	// store persists anchor receipts.
	store ReceiptStore

	// interval is the time between automatic anchoring cycles.
	interval time.Duration

	// lastAnchoredLamport tracks the last successfully anchored Lamport clock value.
	lastAnchoredLamport uint64

	// logger for structured logging.
	logger *slog.Logger
}

// ReceiptStore persists anchor receipts.
type ReceiptStore interface {
	StoreReceipt(ctx context.Context, receipt *AnchorReceipt) error
	GetLatestReceipt(ctx context.Context) (*AnchorReceipt, error)
	GetReceiptByLamportRange(ctx context.Context, from, to uint64) ([]*AnchorReceipt, error)
}

// ServiceConfig configures the anchoring service.
type ServiceConfig struct {
	// Backends are the transparency log backends, tried in priority order.
	Backends []AnchorBackend

	// Store persists anchor receipts.
	Store ReceiptStore

	// Interval between automatic anchoring cycles. Default: 5 minutes.
	Interval time.Duration

	// Logger for structured logging.
	Logger *slog.Logger
}

// NewService creates a new anchoring service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if len(cfg.Backends) == 0 {
		return nil, errors.New("anchor: at least one backend required")
	}
	if cfg.Store == nil {
		return nil, errors.New("anchor: receipt store required")
	}

	interval := cfg.Interval
	if interval == 0 {
		interval = 5 * time.Minute
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Service{
		backends: cfg.Backends,
		store:    cfg.Store,
		interval: interval,
		logger:   logger,
	}, nil
}

// AnchorNow triggers an immediate anchoring cycle.
// It tries each backend in order until one succeeds (failover).
func (s *Service) AnchorNow(ctx context.Context, req AnchorRequest) (*AnchorReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req.MerkleRoot == "" {
		return nil, errors.New("anchor: empty merkle root")
	}

	var lastErr error
	for _, backend := range s.backends {
		s.logger.Info("anchoring to transparency log",
			"backend", backend.Name(),
			"merkle_root", req.MerkleRoot,
			"from_lamport", req.FromLamport,
			"to_lamport", req.ToLamport,
			"node_count", req.NodeCount,
		)

		receipt, err := backend.Anchor(ctx, req)
		if err != nil {
			s.logger.Warn("anchor backend failed, trying next",
				"backend", backend.Name(),
				"error", err,
			)
			lastErr = err
			continue
		}

		// Persist the receipt.
		if err := s.store.StoreReceipt(ctx, receipt); err != nil {
			return nil, fmt.Errorf("anchor: store receipt: %w", err)
		}

		s.lastAnchoredLamport = req.ToLamport

		s.logger.Info("anchoring succeeded",
			"backend", backend.Name(),
			"log_index", receipt.LogIndex,
			"integrated_time", receipt.IntegratedTime,
			"receipt_hash", receipt.ReceiptHash,
		)

		return receipt, nil
	}

	return nil, fmt.Errorf("anchor: all backends failed, last error: %w", lastErr)
}

// LastAnchoredLamport returns the Lamport clock value of the last successful anchor.
func (s *Service) LastAnchoredLamport() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastAnchoredLamport
}

// VerifyReceipt verifies an anchor receipt against its transparency log.
func (s *Service) VerifyReceipt(ctx context.Context, receipt *AnchorReceipt) error {
	for _, backend := range s.backends {
		if backend.Name() == receipt.Backend {
			return backend.Verify(ctx, receipt)
		}
	}
	return fmt.Errorf("anchor: unknown backend %s", receipt.Backend)
}

// InMemoryReceiptStore is a simple in-memory receipt store for testing.
type InMemoryReceiptStore struct {
	mu       sync.RWMutex
	receipts []*AnchorReceipt
}

// NewInMemoryReceiptStore creates a new in-memory receipt store.
func NewInMemoryReceiptStore() *InMemoryReceiptStore {
	return &InMemoryReceiptStore{}
}

func (s *InMemoryReceiptStore) StoreReceipt(_ context.Context, receipt *AnchorReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receipts = append(s.receipts, receipt)
	return nil
}

func (s *InMemoryReceiptStore) GetLatestReceipt(_ context.Context) (*AnchorReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.receipts) == 0 {
		return nil, errors.New("no anchor receipts")
	}
	return s.receipts[len(s.receipts)-1], nil
}

func (s *InMemoryReceiptStore) GetReceiptByLamportRange(_ context.Context, from, to uint64) ([]*AnchorReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*AnchorReceipt
	for _, r := range s.receipts {
		if r.Request.FromLamport >= from && r.Request.ToLamport <= to {
			result = append(result, r)
		}
	}
	return result, nil
}
