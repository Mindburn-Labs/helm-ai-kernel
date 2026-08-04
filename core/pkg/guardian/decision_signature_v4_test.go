package guardian

import (
	"context"
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
	if decision.SignatureVersion == "" {
		decision.SignatureVersion = contracts.DecisionRecordSignatureV4
	}
	if decision.SignatureType == "" {
		decision.SignatureType = "test:signer"
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

func TestIssueExecutionIntentRequiresV4AuthorityBinding(t *testing.T) {
	g := newMinimalGuardian()
	effect := &contracts.Effect{
		EffectID:   "effect-v4-authority",
		EffectType: "EXECUTE_TOOL",
		Params:     map[string]any{"tool_name": "github.create_issue"},
	}
	effectDigest, err := canonicalEffectDigest(effect)
	if err != nil {
		t.Fatal(err)
	}
	base := &contracts.DecisionRecord{
		ID:            "decision-v4-authority",
		Verdict:       string(contracts.VerdictAllow),
		EffectDigest:  effectDigest,
		Signature:     "test_sig",
		SignatureType: "test:signer",
		SubjectID:     "agent:alice",
		Action:        "EXECUTE_TOOL",
		Resource:      "github.create_issue",
	}

	for _, legacyVersion := range []string{contracts.DecisionRecordSignatureV2, contracts.DecisionRecordSignatureV3} {
		t.Run(legacyVersion, func(t *testing.T) {
			legacy := *base
			legacy.SignatureVersion = legacyVersion
			if _, err := g.IssueExecutionIntent(context.Background(), &legacy, effect); err == nil || !strings.Contains(err.Error(), contracts.DecisionRecordSignatureV4) {
				t.Fatalf("legacy decision issued execution authority: %v", err)
			}
		})
	}

	for name, clear := range map[string]func(*contracts.DecisionRecord){
		"subject":        func(d *contracts.DecisionRecord) { d.SubjectID = "" },
		"action":         func(d *contracts.DecisionRecord) { d.Action = "" },
		"resource":       func(d *contracts.DecisionRecord) { d.Resource = "" },
		"signature type": func(d *contracts.DecisionRecord) { d.SignatureType = "" },
	} {
		t.Run(name, func(t *testing.T) {
			incomplete := *base
			incomplete.SignatureVersion = contracts.DecisionRecordSignatureV4
			clear(&incomplete)
			if _, err := g.IssueExecutionIntent(context.Background(), &incomplete, effect); err == nil || !strings.Contains(err.Error(), "execution authority missing") {
				t.Fatalf("incomplete V4 decision issued execution authority: %v", err)
			}
		})
	}

	allowed := *base
	allowed.SignatureVersion = contracts.DecisionRecordSignatureV4
	intent, err := g.IssueExecutionIntent(context.Background(), &allowed, effect)
	if err != nil {
		t.Fatalf("complete V4 authority could not issue intent: %v", err)
	}
	if intent.DecisionID != allowed.ID {
		t.Fatalf("intent decision ID = %q, want %q", intent.DecisionID, allowed.ID)
	}
}
