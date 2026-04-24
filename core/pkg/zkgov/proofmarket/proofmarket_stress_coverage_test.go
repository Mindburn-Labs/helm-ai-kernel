package proofmarket

import (
	"context"
	"fmt"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/zkgov"
)

func TestStress_ProofMarket20Tasks(t *testing.T) {
	lp := NewLocalProver("node-local")
	for i := 0; i < 20; i++ {
		task := &ProofTask{
			TaskID:    fmt.Sprintf("task-%d", i),
			Algorithm: zkgov.Algorithm,
			ProofRequest: map[string]interface{}{
				"decision_id":   fmt.Sprintf("d-%d", i),
				"policy_hash":   "sha256:policy",
				"verdict":       "ALLOW",
				"decision_hash": "sha256:dec",
			},
		}
		err := lp.Submit(context.Background(), task)
		if err != nil {
			t.Fatalf("submit task %d: %v", i, err)
		}
		result, _ := lp.Poll(context.Background(), task.TaskID)
		if result == nil || result.Proof == "" {
			t.Fatalf("task %d: no result", i)
		}
	}
}

func TestStress_ProofMarketPollMissing(t *testing.T) {
	lp := NewLocalProver("node-local")
	result, err := lp.Poll(context.Background(), "missing-task")
	if err != nil || result != nil {
		t.Fatal("expected nil for missing task")
	}
}

func TestStress_ProofMarketNilTask(t *testing.T) {
	lp := NewLocalProver("node-local")
	err := lp.Submit(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil task")
	}
}

func TestStress_ProofMarketEmptyTaskID(t *testing.T) {
	lp := NewLocalProver("node-local")
	err := lp.Submit(context.Background(), &ProofTask{})
	if err == nil {
		t.Fatal("expected error for empty task_id")
	}
}

func TestStress_ProofMarketNetwork(t *testing.T) {
	lp := NewLocalProver("n1")
	if lp.Network() != NetworkLocal {
		t.Fatal("expected LOCAL network")
	}
}

func TestStress_TaskStatusConstants(t *testing.T) {
	if TaskPending != "PENDING" || TaskProving != "PROVING" || TaskCompleted != "COMPLETED" || TaskFailed != "FAILED" || TaskExpired != "EXPIRED" {
		t.Fatal("task status constants mismatch")
	}
}

func TestStress_NetworkConstants(t *testing.T) {
	if NetworkLocal != "LOCAL" || NetworkSPN != "SPN" || NetworkBoundless != "BOUNDLESS" || NetworkCustom != "CUSTOM" {
		t.Fatal("network constants mismatch")
	}
}
