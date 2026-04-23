// Package budget provides compute budget types and enforcement for WASI sandbox execution.
package budget

import (
	"fmt"
	"time"
)

// Deterministic error codes for compute budget violations.
const (
	ErrComputeGasExhausted    = "ERR_COMPUTE_GAS_EXHAUSTED"
	ErrComputeTimeExhausted   = "ERR_COMPUTE_TIME_EXHAUSTED"
	ErrComputeMemoryExhausted = "ERR_COMPUTE_MEMORY_EXHAUSTED"
)

// ComputeBudget defines resource limits for a single sandbox execution.
type ComputeBudget struct {
	GasLimitSteps    uint64 `json:"gas_limit_steps"`
	TimeLimitMs      int64  `json:"time_limit_ms"`
	MemoryLimitBytes int64  `json:"memory_limit_bytes"`
}

// DefaultBudget returns a conservative default compute budget.
func DefaultBudget() ComputeBudget {
	return ComputeBudget{
		GasLimitSteps:    1_000_000,
		TimeLimitMs:      5000,
		MemoryLimitBytes: 64 * 1024 * 1024, // 64MB
	}
}

// TimeLimit returns the time limit as a Duration.
func (b ComputeBudget) TimeLimit() time.Duration {
	return time.Duration(b.TimeLimitMs) * time.Millisecond
}

// ComputeBudgetError is a typed budget violation error.
type ComputeBudgetError struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Limit    int64  `json:"limit"`
	Consumed int64  `json:"consumed"`
}

func (e *ComputeBudgetError) Error() string {
	return fmt.Sprintf("%s: %s (limit=%d, consumed=%d)", e.Code, e.Message, e.Limit, e.Consumed)
}

// CheckGas returns a budget error if gas is exhausted.
func CheckGas(budget ComputeBudget, consumed uint64) error {
	if consumed > budget.GasLimitSteps {
		return &ComputeBudgetError{
			Code:     ErrComputeGasExhausted,
			Message:  "gas step limit exceeded",
			Limit:    int64(budget.GasLimitSteps),
			Consumed: int64(consumed),
		}
	}
	return nil
}

// CheckTime returns a budget error if time is exhausted.
func CheckTime(budget ComputeBudget, elapsed time.Duration) error {
	if elapsed.Milliseconds() > budget.TimeLimitMs {
		return &ComputeBudgetError{
			Code:     ErrComputeTimeExhausted,
			Message:  "time limit exceeded",
			Limit:    budget.TimeLimitMs,
			Consumed: elapsed.Milliseconds(),
		}
	}
	return nil
}

// CheckMemory returns a budget error if memory is exhausted.
func CheckMemory(budget ComputeBudget, usedBytes int64) error {
	if usedBytes > budget.MemoryLimitBytes {
		return &ComputeBudgetError{
			Code:     ErrComputeMemoryExhausted,
			Message:  "memory limit exceeded",
			Limit:    budget.MemoryLimitBytes,
			Consumed: usedBytes,
		}
	}
	return nil
}
