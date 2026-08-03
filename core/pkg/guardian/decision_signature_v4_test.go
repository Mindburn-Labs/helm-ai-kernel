package guardian

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// testDecisionAuthority makes legacy unit fixtures explicit about the
// authority tuple their direct SignDecision calls model. Production callers
// must provide the actual request tuple; they never receive these defaults.
func testDecisionAuthority(decision *contracts.DecisionRecord) *contracts.DecisionRecord {
	if decision == nil {
		return nil
	}
	if decision.SubjectID == "" {
		decision.SubjectID = "test:subject"
	}
	if decision.Action == "" {
		decision.Action = "TEST_ACTION"
	}
	if decision.Resource == "" {
		decision.Resource = "test:resource"
	}
	return decision
}

func TestBindDecisionRequestBindsOnlyExactEvaluatedAuthority(t *testing.T) {
	request := DecisionRequest{Principal: "agent:alice", Action: "EXECUTE_TOOL", Resource: "github.create_issue"}
	decision := &contracts.DecisionRecord{}
	if err := bindDecisionRequest(decision, request); err != nil {
		t.Fatal(err)
	}
	if decision.SubjectID != request.Principal || decision.Action != request.Action || decision.Resource != request.Resource {
		t.Fatalf("bound decision = %+v, want request authority", decision)
	}

	for name, decision := range map[string]*contracts.DecisionRecord{
		"mismatched subject":  {SubjectID: "agent:bob"},
		"mismatched action":   {Action: "DELETE"},
		"mismatched resource": {Resource: "billing.transfer"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := bindDecisionRequest(decision, request); err == nil || !strings.Contains(err.Error(), "does not match") {
				t.Fatalf("mismatched authority error = %v", err)
			}
		})
	}

	for name, request := range map[string]DecisionRequest{
		"missing principal": {Action: "EXECUTE_TOOL", Resource: "github.create_issue"},
		"missing action":    {Principal: "agent:alice", Resource: "github.create_issue"},
		"missing resource":  {Principal: "agent:alice", Action: "EXECUTE_TOOL"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := bindDecisionRequest(&contracts.DecisionRecord{}, request); err == nil || !strings.Contains(err.Error(), "is required") {
				t.Fatalf("incomplete authority error = %v", err)
			}
		})
	}
}
