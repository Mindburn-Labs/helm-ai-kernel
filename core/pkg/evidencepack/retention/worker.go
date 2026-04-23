// Package retention implements evidence pack retention policies.
// This worker runs as part of the helm-worker process and handles
// expiration, archival, and cleanup of old evidence packs.
package retention

import (
	"context"
	"log/slog"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/store/objstore"
)

// Policy defines retention rules for evidence packs.
type Policy struct {
	// MaxAge is the maximum age of evidence packs before archival.
	MaxAge time.Duration `json:"max_age"`

	// ArchiveAge is the age at which packs are moved to cold storage.
	ArchiveAge time.Duration `json:"archive_age"`

	// DeleteAge is the age at which packs are permanently deleted.
	// Must be >= ArchiveAge. Set to 0 to never delete.
	DeleteAge time.Duration `json:"delete_age"`

	// MinRetainCount is the minimum number of packs to retain regardless of age.
	MinRetainCount int `json:"min_retain_count"`
}

// DefaultPolicy returns production retention defaults.
func DefaultPolicy() Policy {
	return Policy{
		MaxAge:         90 * 24 * time.Hour,  // 90 days active
		ArchiveAge:     30 * 24 * time.Hour,  // 30 days before archive
		DeleteAge:      365 * 24 * time.Hour, // 1 year before delete
		MinRetainCount: 1000,
	}
}

// Worker runs evidence retention on a schedule.
type Worker struct {
	store  objstore.ObjectStore
	policy Policy
	logger *slog.Logger
	ticker *time.Ticker
	stopCh chan struct{}
}

// NewWorker creates a new retention worker.
func NewWorker(store objstore.ObjectStore, policy Policy, logger *slog.Logger) *Worker {
	return &Worker{
		store:  store,
		policy: policy,
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

// Start begins the retention worker loop.
func (w *Worker) Start(ctx context.Context, interval time.Duration) {
	w.ticker = time.NewTicker(interval)
	w.logger.Info("retention worker started",
		"interval", interval,
		"max_age", w.policy.MaxAge,
		"archive_age", w.policy.ArchiveAge,
	)

	go func() {
		for {
			select {
			case <-ctx.Done():
				w.logger.Info("retention worker stopping: context cancelled")
				return
			case <-w.stopCh:
				w.logger.Info("retention worker stopping: stop signal")
				return
			case <-w.ticker.C:
				if err := w.RunOnce(ctx); err != nil {
					w.logger.Error("retention cycle failed", "error", err)
				}
			}
		}
	}()
}

// Stop signals the worker to stop.
func (w *Worker) Stop() {
	close(w.stopCh)
	if w.ticker != nil {
		w.ticker.Stop()
	}
}

// RunOnce executes a single retention cycle.
func (w *Worker) RunOnce(ctx context.Context) error {
	w.logger.Info("retention cycle starting")
	start := time.Now()

	hashes, err := w.store.List(ctx, "")
	if err != nil {
		return err
	}

	// In a full implementation, we would:
	// 1. Load pack metadata to get creation timestamps
	// 2. Apply retention policy (archive/delete based on age)
	// 3. Respect MinRetainCount
	// 4. Emit retention receipts
	// For now, log basic statistics.

	w.logger.Info("retention cycle complete",
		"total_objects", len(hashes),
		"duration", time.Since(start),
	)

	return nil
}
