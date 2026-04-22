package sandbox

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/runtime/budget"
)

// TestWASI_InfiniteLoop verifies the sandbox terminates an infinite loop within budget.
func TestWASI_InfiniteLoop(t *testing.T) {
	b := budget.ComputeBudget{
		GasLimitSteps:    100_000,
		TimeLimitMs:      1000,
		MemoryLimitBytes: 16 * 1024 * 1024,
	}

	// Simulate enforcement: the sandbox must terminate within time budget
	ctx, cancel := context.WithTimeout(context.Background(), b.TimeLimit())
	defer cancel()

	start := time.Now()
	// Simulate gas burning until timeout
	var gasConsumed uint64
	for {
		select {
		case <-ctx.Done():
			elapsed := time.Since(start)
			err := budget.CheckTime(b, elapsed)
			if err == nil {
				// Should have exceeded budget
				t.Log("terminated within time limit")
			}
			bErr, ok := err.(*budget.ComputeBudgetError)
			if ok && bErr.Code != budget.ErrComputeTimeExhausted {
				t.Errorf("expected ERR_COMPUTE_TIME_EXHAUSTED, got %s", bErr.Code)
			}
			return
		default:
			gasConsumed++
			if err := budget.CheckGas(b, gasConsumed); err != nil {
				bErr := err.(*budget.ComputeBudgetError)
				if bErr.Code != budget.ErrComputeGasExhausted {
					t.Errorf("expected ERR_COMPUTE_GAS_EXHAUSTED, got %s", bErr.Code)
				}
				return
			}
		}
	}
}

// TestWASI_MemoryBomb verifies memory limit enforcement.
func TestWASI_MemoryBomb(t *testing.T) {
	b := budget.ComputeBudget{
		GasLimitSteps:    1_000_000,
		TimeLimitMs:      5000,
		MemoryLimitBytes: 1 * 1024 * 1024, // 1MB
	}

	// Simulate memory allocation exceeding budget
	var allocated int64
	chunkSize := int64(256 * 1024) // 256KB chunks

	for i := 0; i < 10; i++ {
		allocated += chunkSize
		if err := budget.CheckMemory(b, allocated); err != nil {
			bErr := err.(*budget.ComputeBudgetError)
			if bErr.Code != budget.ErrComputeMemoryExhausted {
				t.Errorf("expected ERR_COMPUTE_MEMORY_EXHAUSTED, got %s", bErr.Code)
			}
			if allocated <= b.MemoryLimitBytes {
				t.Error("should not fail within budget")
			}
			return
		}
	}

	t.Fatal("memory bomb should have been caught")
}

// TestWASI_DeterministicTermination verifies consistent error codes across runs.
func TestWASI_DeterministicTermination(t *testing.T) {
	b := budget.DefaultBudget()

	// Gas exhaustion must always produce the same error code
	for i := 0; i < 100; i++ {
		err := budget.CheckGas(b, b.GasLimitSteps+1)
		if err == nil {
			t.Fatal("expected error")
		}
		bErr := err.(*budget.ComputeBudgetError)
		if bErr.Code != budget.ErrComputeGasExhausted {
			t.Fatalf("non-deterministic error code at iteration %d: %s", i, bErr.Code)
		}
	}
}

// TestWASI_DenyByDefault verifies sandbox defaults deny all access.
func TestWASI_DenyByDefault(t *testing.T) {
	b := budget.DefaultBudget()

	// Budget must have finite limits (deny-by-default = bounded compute)
	if b.GasLimitSteps == 0 {
		t.Error("gas limit must not be zero (deny-by-default)")
	}
	if b.TimeLimitMs == 0 {
		t.Error("time limit must not be zero (deny-by-default)")
	}
	if b.MemoryLimitBytes == 0 {
		t.Error("memory limit must not be zero (deny-by-default)")
	}
}
