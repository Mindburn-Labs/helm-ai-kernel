package contracts

import (
	"encoding/json"
	"testing"
	"time"
)

func TestVerificationScopeSealDeterministic(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	scope := VerificationScope{
		VerificationScopeID: "scope-1",
		SubjectHash:         "sha256:subject",
		RiskClass:           "T2",
		ChecksPerformed:     []string{"unit", "replay"},
		VerifierHash:        "sha256:verifier",
		PolicyHash:          "sha256:policy",
		CreatedAt:           now,
	}
	sealed, err := scope.Seal()
	if err != nil {
		t.Fatal(err)
	}
	resealed, err := scope.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if sealed.ScopeHash == "" || sealed.ScopeHash != resealed.ScopeHash {
		t.Fatalf("scope hash not deterministic: %q vs %q", sealed.ScopeHash, resealed.ScopeHash)
	}
}

func TestPlanTransactionRequiresConflictPolicy(t *testing.T) {
	_, err := PlanTransaction{
		PlanTransactionID:       "txn-1",
		PlanHash:                "sha256:plan",
		ReadSet:                 []string{"artifact:a"},
		WriteSet:                []string{"artifact:b"},
		AssumptionSet:           []string{"artifact:a"},
		VerificationObligations: []string{"scope:scope-1"},
		ConflictPolicy:          "allow",
	}.Seal()
	if err == nil {
		t.Fatal("expected invalid conflict policy to fail")
	}
}

func TestHarnessChangeContractRequiresRegressionRefs(t *testing.T) {
	_, err := HarnessChangeContract{
		ChangeContractID:     "change-1",
		ComponentModified:    "connector_contract",
		FailureModeTargeted:  "schema drift",
		PredictedImprovement: "deny drifted schema",
		InvariantsPreserved:  []string{"fail closed"},
		SafetyProperties:     []string{"no dispatch on drift"},
		RollbackPlan:         json.RawMessage(`{"mode":"revert"}`),
		ApprovalRequired:     true,
		CreatedAt:            time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
	}.Seal()
	if err == nil {
		t.Fatal("expected missing regression refs to fail")
	}
}

func TestGUIActionReceiptRequiresPostconditionVerification(t *testing.T) {
	_, err := GUIActionReceipt{
		ReceiptID:             "gui-receipt-1",
		GroundedActionRef:     "grounded-1",
		ScreenshotHash:        "sha256:screenshot",
		DOMOrAXSnapshotHash:   "sha256:dom",
		TargetRef:             "button#save",
		BBoxOrElementID:       "button#save",
		ActionType:            "click",
		Precondition:          "form dirty",
		Postcondition:         "save toast visible",
		PostconditionRef:      "proof:postcondition:save-toast",
		PostconditionVerified: false,
		ProofGraphNodeRef:     "proofgraph:gui-action:1",
		VerificationScopeRef:  "scope-1",
		PolicyHash:            "sha256:policy",
		CreatedAt:             time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
	}.Seal()
	if err == nil {
		t.Fatal("expected unverified postcondition to fail")
	}
}

func TestExplicitReceiptRefsAreHashBound(t *testing.T) {
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		seal func([]string) (string, error)
	}{
		{
			name: "verification scope",
			seal: func(refs []string) (string, error) {
				sealed, err := (VerificationScope{VerificationScopeID: "scope-refs", ReceiptRefs: refs, SubjectHash: "sha256:subject", ChecksPerformed: []string{"hash"}, VerifierHash: "sha256:verifier", PolicyHash: "sha256:policy", CreatedAt: now}).Seal()
				return sealed.ScopeHash, err
			},
		},
		{
			name: "plan transaction",
			seal: func(refs []string) (string, error) {
				sealed, err := (PlanTransaction{PlanTransactionID: "tx-refs", ReceiptRefs: refs, PlanHash: "sha256:plan", ReadSet: []string{"artifact:read"}, WriteSet: []string{"artifact:write"}, AssumptionSet: []string{"assumption"}, VerificationObligations: []string{"verify"}, ConflictPolicy: "deny"}).Seal()
				return sealed.TransactionHash, err
			},
		},
		{
			name: "grounded action",
			seal: func(refs []string) (string, error) {
				sealed, err := (GroundedActionRef{GroundedActionID: "action-refs", ReceiptRefs: refs, ScreenshotHash: "sha256:screenshot", DOMOrAXSnapshotHash: "sha256:dom", TargetRef: "button#save", BBoxOrElementID: "button#save", ActionType: "click", Precondition: "form dirty", Postcondition: "saved", PostconditionRef: "proof:save", ProofGraphNodeRef: "proofgraph:save", VerificationScopeRef: "scope-refs", PolicyHash: "sha256:policy", CreatedAt: now}).Seal()
				return sealed.GroundingHash, err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first, err := tt.seal([]string{"rcpt-1"})
			if err != nil {
				t.Fatal(err)
			}
			second, err := tt.seal([]string{"rcpt-2"})
			if err != nil {
				t.Fatal(err)
			}
			if first == second {
				t.Fatalf("receipt refs did not change sealed hash: %q", first)
			}
			if _, err := tt.seal([]string{" "}); err == nil {
				t.Fatal("blank receipt ref should be rejected")
			}
		})
	}
}
