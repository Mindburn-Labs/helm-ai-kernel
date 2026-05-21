package sandbox

import (
	"context"
	"fmt"
	"sync"
)

// VaultakStateBridge binds container leases to transactional undo logs.
type VaultakStateBridge struct {
	mu           sync.RWMutex
	leasePool    *WarmLeaseManager
	activeLeases map[string]Runner // Map of active Transaction IDs to Sandboxed Runners
}

// NewVaultakStateBridge creates a new VaultakStateBridge instance.
func NewVaultakStateBridge(pool *WarmLeaseManager) *VaultakStateBridge {
	return &VaultakStateBridge{
		leasePool:    pool,
		activeLeases: make(map[string]Runner),
	}
}

// BindLeaseToTransaction binds an active sandbox runner to a Vaultak transaction ID.
func (b *VaultakStateBridge) BindLeaseToTransaction(transactionID string, runner Runner) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.activeLeases[transactionID] = runner
}

// RollbackTransaction executes an immediate, asynchronous OverlayFS reset.
func (b *VaultakStateBridge) RollbackTransaction(ctx context.Context, transactionID string) error {
	b.mu.Lock()
	runner, exists := b.activeLeases[transactionID]
	if !exists {
		b.mu.Unlock()
		return fmt.Errorf("transaction ID %s not found or already released", transactionID)
	}
	delete(b.activeLeases, transactionID)
	b.mu.Unlock()

	// Release triggers the background OverlayFS filesystem rollback to sterile digest
	b.leasePool.Release(runner)
	return nil
}
