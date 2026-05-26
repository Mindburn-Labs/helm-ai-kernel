package sandbox

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWarmLeaseManager_PreWarmAndCycle(t *testing.T) {
	poolSize := 3
	mgr := NewWarmLeaseManager(poolSize, "sha256:test-digest", true)

	assert.Equal(t, poolSize, len(mgr.idleRunners))

	// Acquire one
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	spec := &SandboxSpec{Image: "sha256:test-digest"}
	runner, err := mgr.Acquire(ctx, spec)
	require.NoError(t, err)
	assert.NotNil(t, runner)

	// Length should drop
	assert.Equal(t, poolSize-1, len(mgr.idleRunners))

	// Release it
	mgr.Release(runner)

	// Wait briefly for the async overlay recycling loop to return it to the idle queue
	assert.Eventually(t, func() bool {
		return len(mgr.idleRunners) == poolSize
	}, 1*time.Second, 5*time.Millisecond)
}

func TestWarmLeaseManager_DynamicFallback(t *testing.T) {
	// Pool size 0 will default to 4 internally, but let's test a fully depleted pool
	mgr := NewWarmLeaseManager(1, "sha256:test-digest", true)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	spec := &SandboxSpec{Image: "sha256:test-digest"}

	// First acquisition exhausts the pool
	r1, err := mgr.Acquire(ctx, spec)
	require.NoError(t, err)
	assert.NotNil(t, r1)
	assert.Equal(t, 0, len(mgr.idleRunners))

	// Second acquisition triggers the dynamic on-demand mock runner fallback immediately without blocking
	r2, err := mgr.Acquire(ctx, spec)
	require.NoError(t, err)
	assert.NotNil(t, r2)
}

func BenchmarkWarmAcquisitionSpeed(b *testing.B) {
	mgr := NewWarmLeaseManager(100, "sha256:test-digest", true)
	spec := &SandboxSpec{Image: "sha256:test-digest"}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runner, err := mgr.Acquire(ctx, spec)
		if err != nil {
			b.Fatalf("failed to acquire runner: %v", err)
		}
		// Return back immediately so the pool is not exhausted
		mgr.Release(runner)
	}
}

func BenchmarkColdAcquisitionSpeedMock(b *testing.B) {
	// A "cold start" creates a runner on demand without using the warm pool channel
	spec := &SandboxSpec{Image: "sha256:test-digest"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulating direct/cold construction of sandbox runner
		runner := &MockRunner{id: fmt.Sprintf("mock-cold-%d", i)}
		_, _, err := runner.Run(spec)
		if err != nil {
			b.Fatalf("failed mock cold run: %v", err)
		}
	}
}
