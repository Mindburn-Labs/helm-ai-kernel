package cpi

import (
	"context"
	"encoding/json"
	"testing"
)

func TestProofObligationValidation(t *testing.T) {
	obligation := validProofObligation()
	if err := obligation.Validate(); err != nil {
		t.Fatalf("valid obligation: %v", err)
	}

	obligation.AllowedToolchain = nil
	if err := obligation.Validate(); err == nil {
		t.Fatal("expected missing toolchain error")
	}
}

func TestDeterministicFormalVerifierStatuses(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ProofObligation)
		want   ProofStatus
	}{
		{"proved", nil, ProofStatusProved},
		{"refuted", func(o *ProofObligation) {
			o.Plan.Nodes = []ProofPlanNode{
				{NodeID: "send-money", SideEffect: true, EffectClass: "IRREVERSIBLE"},
				{NodeID: "approve", ApprovalCheckpoint: true},
			}
		}, ProofStatusRefuted},
		{"unknown", func(o *ProofObligation) {
			o.Invariant = "unsupported"
		}, ProofStatusUnknown},
		{"budget exhausted", func(o *ProofObligation) {
			o.Budget.MaxNodes = 1
		}, ProofStatusBudgetExhausted},
		{"toolchain error", func(o *ProofObligation) {
			o.AllowedToolchain = []string{"lean4"}
		}, ProofStatusToolchainError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obligation := validProofObligation()
			if tc.mutate != nil {
				tc.mutate(&obligation)
			}
			got, err := (DeterministicFormalVerifier{}).Verify(context.Background(), obligation)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if got.Status != tc.want {
				t.Fatalf("status = %s, want %s", got.Status, tc.want)
			}
			if got.ResultHash == "" || got.ProofArtifactHash == "" || got.VerifierLogHash == "" || got.ProofSearchMerkleRoot == "" {
				t.Fatalf("missing proof hashes: %+v", got)
			}
		})
	}
}

func TestProofResultHashDeterministic(t *testing.T) {
	obligation := validProofObligation()
	v := DeterministicFormalVerifier{}
	first, err := v.Verify(context.Background(), obligation)
	if err != nil {
		t.Fatal(err)
	}
	second, err := v.Verify(context.Background(), obligation)
	if err != nil {
		t.Fatal(err)
	}
	if first.ResultHash != second.ResultHash {
		t.Fatalf("result hash changed: %s vs %s", first.ResultHash, second.ResultHash)
	}
}

func TestProofStatusToCPI(t *testing.T) {
	cases := map[ProofStatus]string{
		ProofStatusProved:          "ALLOW",
		ProofStatusRefuted:         "DENY",
		ProofStatusUnknown:         "ESCALATE",
		ProofStatusBudgetExhausted: "ESCALATE",
		ProofStatusToolchainError:  "ESCALATE",
	}
	for status, want := range cases {
		if got := ProofStatusToCPI(status); got != want {
			t.Fatalf("ProofStatusToCPI(%s) = %s, want %s", status, got, want)
		}
	}
}

func TestEvaluateFormalProofUsesObligation(t *testing.T) {
	obligation := validProofObligation()
	data, _ := json.Marshal(obligation)
	ok, err := EvaluateFormalProof(context.Background(), nil, data)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected proved obligation")
	}

	obligation.Plan.Nodes = []ProofPlanNode{{NodeID: "delete", SideEffect: true, EffectClass: "E4"}}
	data, _ = json.Marshal(obligation)
	ok, err = EvaluateFormalProof(context.Background(), nil, data)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected refuted obligation")
	}
}

func validProofObligation() ProofObligation {
	return ProofObligation{
		ObligationID:       "obl-no-irrev-before-approval",
		SourceKind:         "PlanIR",
		Invariant:          ProofInvariantNoIrreversibleBeforeApproval,
		CanonicalInputHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RiskClass:          "T3",
		AllowedToolchain:   []string{ProofToolchainDeterministicV0},
		Budget:             ProofBudget{MaxNodes: 8},
		EvidenceRefs:       []string{"evidencepack:demo"},
		Plan: ProofPlanView{Nodes: []ProofPlanNode{
			{NodeID: "approve", ApprovalCheckpoint: true},
			{NodeID: "send-money", SideEffect: true, EffectClass: "IRREVERSIBLE"},
		}},
	}
}
