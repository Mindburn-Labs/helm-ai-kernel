package guardian

import (
	"context"
	"strings"
	"testing"

	pkg_artifact "github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
)

func TestEvaluateDecision_Persistence(t *testing.T) {
	// 1. Setup Dependencies (using mocks from guardian_test.go)
	mockStore := NewMockStore()
	registry := pkg_artifact.NewRegistry(mockStore, nil)
	signer := &MockSigner{}
	ruleGraph := prg.NewGraph() // Valid but empty PRG

	// 2. Setup Guardian
	g := NewGuardian(signer, ruleGraph, registry)

	// 3. Inject AuditLog
	memLog := NewAuditLog() // Uses in-memory implementation by default
	g.SetAuditLog(memLog)

	// 4. Evaluate a Decision (Request blocked by default denying PRG/Policy)
	req := DecisionRequest{
		Principal: "test-user",
		Action:    "EXECUTE_TOOL",
		Resource:  "rogue_tool", // Unknown tool -> Fail
		Context:   map[string]interface{}{"msg": "hello"},
	}

	decision, err := g.EvaluateDecision(context.Background(), req)

	// Expecting NO error from EvaluateDecision itself (it handles policy failures gracefully)
	// But check if it returns nil (it shouldn't)
	if err != nil {
		t.Fatalf("EvaluateDecision returned error: %v", err)
	}
	if decision == nil {
		t.Fatal("Expected decision record, got nil")
	}

	// 5. Verify Persistence
	entries := memLog.Entries
	if len(entries) != 1 {
		t.Fatalf("Expected 1 audit entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Action != "DECISION_MADE" {
		t.Errorf("Expected action DECISION_MADE, got %s", entry.Action)
	}
	if entry.Actor != "guardian" {
		t.Errorf("Expected actor guardian, got %s", entry.Actor)
	}

	// Target should be the decision ID
	if entry.Target != decision.ID {
		t.Errorf("Expected target %s, got %s", decision.ID, entry.Target)
	}

	// Details should contain the JCS string of the decision
	if !strings.Contains(entry.Details, decision.ID) {
		t.Errorf("Details payload does not contain decision ID")
	}
	if !strings.Contains(entry.Details, "\"verdict\":\"DENY\"") {
		// Expect DENY because PRG is empty/default deny or "rogue_tool" has no policy
		t.Errorf("Details payload does not contain verdict DENY")
	}
}
