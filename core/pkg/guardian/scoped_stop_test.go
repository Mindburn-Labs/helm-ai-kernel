package guardian

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
)

type scopedStopReaderStub struct {
	state  kernel.FenceState
	fenced bool
	err    error
	calls  int
}

func (s *scopedStopReaderStub) IsFenced(_ context.Context, _ kernel.StopScope) (kernel.FenceState, bool, error) {
	s.calls++
	return s.state, s.fenced, s.err
}

func TestScopedStopFenceDeniesExplicitlyScopedDispatch(t *testing.T) {
	reader := &scopedStopReaderStub{
		fenced: true,
		state: kernel.FenceState{
			StopScope:   kernel.StopScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"},
			CommandID:   "stop-command-7",
			Epoch:       7,
			ReceiptHash: "sha256:ack-7",
		},
	}
	g := newMinimalGuardian(WithScopedStopReader(reader))
	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal:   "agent-a",
		Action:      "EXECUTE_TOOL",
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != string(contracts.VerdictDeny) || decision.ReasonCode != string(contracts.ReasonEmergencyStopFenced) {
		t.Fatalf("decision = %+v, want EMERGENCY_STOP_FENCED deny", decision)
	}
	if reader.calls != 1 {
		t.Fatalf("reader calls = %d, want 1", reader.calls)
	}
	if decision.EffectDigest == "" {
		t.Fatal("fenced denial must bind emergency-stop provenance into its signed effect digest")
	}
	if decision.InputContext["emergency_stop_command_id"] != "stop-command-7" || decision.InputContext["emergency_stop_epoch"] != uint64(7) || decision.InputContext["emergency_stop_receipt_hash"] != "sha256:ack-7" {
		t.Fatalf("fenced denial missing acknowledgement provenance: %+v", decision.InputContext)
	}
}

func TestScopedStopReaderFailureFailsClosedForScopedDispatch(t *testing.T) {
	reader := &scopedStopReaderStub{err: errors.New("store unavailable")}
	g := newMinimalGuardian(WithScopedStopReader(reader))
	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal:   "agent-a",
		Action:      "EXECUTE_TOOL",
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != string(contracts.VerdictDeny) || decision.ReasonCode != string(contracts.ReasonEmergencyStopUnverified) {
		t.Fatalf("decision = %+v, want EMERGENCY_STOP_UNVERIFIED deny", decision)
	}
}

func TestScopedStopReaderDeniesUnscopedEvaluationToPreventFenceBypass(t *testing.T) {
	reader := &scopedStopReaderStub{fenced: true, state: kernel.FenceState{Epoch: 1, FencedAt: time.Now().UTC()}}
	g := newMinimalGuardian(WithScopedStopReader(reader))
	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{Principal: "agent-a", Action: "EXECUTE_TOOL"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != string(contracts.VerdictDeny) || decision.ReasonCode != string(contracts.ReasonEmergencyStopScopeRequired) {
		t.Fatalf("decision = %+v, want EMERGENCY_STOP_SCOPE_REQUIRED deny", decision)
	}
	if reader.calls != 0 {
		t.Fatalf("reader calls = %d, want 0 without a complete scope", reader.calls)
	}
}
