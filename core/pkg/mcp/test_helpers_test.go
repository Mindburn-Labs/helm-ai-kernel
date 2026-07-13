package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
)

// seedVerifiedApprovalFixture represents a completed approval verification
// from a trusted external verifier. It exists only in test code so downstream
// firewall tests can exercise approved-state behavior without making opaque
// ApprovalDecision fields executable in production.
func seedVerifiedApprovalFixture(t testing.TB, registry *QuarantineRegistry, decision ApprovalDecision) ServerQuarantineRecord {
	t.Helper()
	if decision.ServerID == "" {
		t.Fatal("fixture approval requires server id")
	}
	if decision.ApproverID == "" || decision.ApprovalReceiptID == "" {
		t.Fatal("fixture approval requires verified approver and receipt")
	}
	if len(decision.ToolNames) == 0 {
		t.Fatal("fixture approval requires tools")
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	record, ok := registry.records[decision.ServerID]
	if !ok {
		t.Fatalf("fixture approval server %q is not discovered", decision.ServerID)
	}
	if record.State == QuarantineRevoked {
		t.Fatalf("fixture approval server %q is revoked", decision.ServerID)
	}
	approvedAt := decision.ApprovedAt
	if approvedAt.IsZero() {
		approvedAt = time.Now().UTC()
	}
	effects := append([]string(nil), decision.Effects...)
	if len(effects) == 0 {
		effects = []string{"read"}
	}
	record.State = QuarantineApproved
	record.ApprovedAt = approvedAt
	record.ApprovedBy = decision.ApproverID
	record.ApprovalReceiptID = decision.ApprovalReceiptID
	record.ExpiresAt = decision.ExpiresAt
	record.Reason = decision.Reason
	record.ApprovedToolNames = append([]string(nil), decision.ToolNames...)
	record.ApprovedEffects = effects
	registry.records[decision.ServerID] = record
	return record
}

type mockEvaluator struct {
	verdict string
	reason  string
	err     error
}

func (m *mockEvaluator) EvaluateDecision(_ context.Context, _ guardian.DecisionRequest) (*contracts.DecisionRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &contracts.DecisionRecord{
		ID:      "test-decision",
		Verdict: m.verdict,
		Reason:  m.reason,
	}, nil
}

type smartMockEvaluator struct {
	decisions map[string]string
}

func (m *smartMockEvaluator) EvaluateDecision(_ context.Context, req guardian.DecisionRequest) (*contracts.DecisionRecord, error) {
	verdict, ok := m.decisions[req.Resource]
	if !ok {
		verdict = string(contracts.VerdictAllow)
	}
	return &contracts.DecisionRecord{Verdict: verdict}, nil
}
