package sandbox

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultakOverlayRollbackSpeed(t *testing.T) {
	poolSize := 3
	pool := NewWarmLeaseManager(poolSize, "sha256:sterile-digest", true)
	bridge := NewVaultakStateBridge(pool)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	spec := &SandboxSpec{Image: "sha256:sterile-digest"}

	// 1. Acquire warm lease runner
	runner, err := pool.Acquire(ctx, spec)
	require.NoError(t, err)
	assert.NotNil(t, runner)
	assert.Equal(t, poolSize-1, len(pool.idleRunners))

	// 2. Bind lease to transaction
	txID := "tx_vaultak_999"
	bridge.BindLeaseToTransaction(txID, runner)

	// Check mapping is correct
	bridge.mu.RLock()
	mappedRunner, exists := bridge.activeLeases[txID]
	bridge.mu.RUnlock()
	assert.True(t, exists)
	assert.Equal(t, runner, mappedRunner)

	// 3. Rollback transaction and measure speed
	start := time.Now()
	err = bridge.RollbackTransaction(ctx, txID)
	duration := time.Since(start)

	assert.NoError(t, err)

	// Verify it was unmapped
	bridge.mu.RLock()
	_, exists = bridge.activeLeases[txID]
	bridge.mu.RUnlock()
	assert.False(t, exists)

	// Timing assertion: the rollback trigger itself must execute sub-millisecond (less than 5ms)
	assert.Less(t, duration, 5*time.Millisecond, "OverlayFS rollback trigger took too long: %v", duration)

	// Wait for the async cleanup routine inside WarmLeaseManager to complete and return the runner to the pool
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, poolSize, len(pool.idleRunners))
}
