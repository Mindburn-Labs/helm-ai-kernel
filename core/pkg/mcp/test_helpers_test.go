package mcp

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
)

// seedVerifiedApprovalFixture is test-only setup for callers that need to
// exercise enforcement after an external verifier has established authority.
// Production code must never use local metadata to make this state.
func seedVerifiedApprovalFixture(t testing.TB, registry *QuarantineRegistry, decision ApprovalDecision) ServerQuarantineRecord {
	t.Helper()
	if registry == nil {
		t.Fatal("verified approval fixture requires a registry")
	}
	if strings.TrimSpace(decision.ServerID) == "" || strings.TrimSpace(decision.ApproverID) == "" || strings.TrimSpace(decision.ApprovalReceiptID) == "" {
		t.Fatal("verified approval fixture requires server, approver, and receipt ids")
	}
	if len(decision.ToolNames) == 0 {
		t.Fatal("verified approval fixture requires approved tools")
	}

	tools := append([]string(nil), decision.ToolNames...)
	effects := append([]string(nil), decision.Effects...)
	sort.Strings(tools)
	sort.Strings(effects)
	if len(effects) == 0 {
		effects = []string{"read"}
	}
	now := decision.ApprovedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	reason := strings.TrimSpace(decision.Reason)
	if reason == "" {
		reason = "verified test fixture"
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	record, ok := registry.records[decision.ServerID]
	if !ok {
		t.Fatalf("verified approval fixture server %q is not discovered", decision.ServerID)
	}
	if record.State == QuarantineRevoked {
		t.Fatalf("verified approval fixture server %q is revoked", decision.ServerID)
	}
	record.State = QuarantineApproved
	record.ApprovedAt = now
	record.ApprovedBy = decision.ApproverID
	record.ApprovalReceiptID = decision.ApprovalReceiptID
	record.ExpiresAt = decision.ExpiresAt
	record.Reason = reason
	record.ApprovedToolNames = tools
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
