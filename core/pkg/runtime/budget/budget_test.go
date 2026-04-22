package budget

import (
	"testing"
	"time"
)

func TestCheckGas_WithinBudget(t *testing.T) {
	b := DefaultBudget()
	if err := CheckGas(b, 500_000); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckGas_Exceeded(t *testing.T) {
	b := DefaultBudget()
	err := CheckGas(b, 2_000_000)
	if err == nil {
		t.Fatal("expected gas exhaustion error")
	}
	bErr := err.(*ComputeBudgetError)
	if bErr.Code != ErrComputeGasExhausted {
		t.Errorf("code = %s, want %s", bErr.Code, ErrComputeGasExhausted)
	}
}

func TestCheckTime_WithinBudget(t *testing.T) {
	b := DefaultBudget()
	if err := CheckTime(b, 100*time.Millisecond); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckTime_Exceeded(t *testing.T) {
	b := DefaultBudget()
	err := CheckTime(b, 10*time.Second)
	if err == nil {
		t.Fatal("expected time exhaustion error")
	}
	bErr := err.(*ComputeBudgetError)
	if bErr.Code != ErrComputeTimeExhausted {
		t.Errorf("code = %s, want %s", bErr.Code, ErrComputeTimeExhausted)
	}
}

func TestCheckMemory_WithinBudget(t *testing.T) {
	b := DefaultBudget()
	if err := CheckMemory(b, 32*1024*1024); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckMemory_Exceeded(t *testing.T) {
	b := DefaultBudget()
	err := CheckMemory(b, 128*1024*1024)
	if err == nil {
		t.Fatal("expected memory exhaustion error")
	}
	bErr := err.(*ComputeBudgetError)
	if bErr.Code != ErrComputeMemoryExhausted {
		t.Errorf("code = %s, want %s", bErr.Code, ErrComputeMemoryExhausted)
	}
}

func TestDefaultBudget(t *testing.T) {
	b := DefaultBudget()
	if b.GasLimitSteps == 0 {
		t.Error("gas limit should not be zero")
	}
	if b.TimeLimitMs == 0 {
		t.Error("time limit should not be zero")
	}
	if b.MemoryLimitBytes == 0 {
		t.Error("memory limit should not be zero")
	}
	if b.TimeLimit() != 5*time.Second {
		t.Errorf("TimeLimit() = %v, want 5s", b.TimeLimit())
	}
}
