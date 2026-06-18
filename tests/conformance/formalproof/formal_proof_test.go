package formalproof

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/cpi"
)

func TestFormalProofWorkerVectors(t *testing.T) {
	vectors := []struct {
		name    string
		mutate  func(*cpi.ProofObligation)
		status  cpi.ProofStatus
		verdict string
	}{
		{"proof accepted", nil, cpi.ProofStatusProved, "ALLOW"},
		{"proof refuted", func(o *cpi.ProofObligation) {
			o.Plan.Nodes = []cpi.ProofPlanNode{
				{NodeID: "wire-funds", SideEffect: true, EffectClass: "IRREVERSIBLE"},
				{NodeID: "approval", ApprovalCheckpoint: true},
			}
		}, cpi.ProofStatusRefuted, "DENY"},
		{"budget exhausted", func(o *cpi.ProofObligation) {
			o.Budget.MaxNodes = 1
		}, cpi.ProofStatusBudgetExhausted, "ESCALATE"},
	}

	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			obligation := conformanceObligation()
			if vector.mutate != nil {
				vector.mutate(&obligation)
			}
			result, err := (cpi.DeterministicFormalVerifier{}).Verify(context.Background(), obligation)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if result.Status != vector.status {
				t.Fatalf("status = %s, want %s", result.Status, vector.status)
			}
			if got := cpi.ProofStatusToCPI(result.Status); got != vector.verdict {
				t.Fatalf("verdict = %s, want %s", got, vector.verdict)
			}
		})
	}
}

func conformanceObligation() cpi.ProofObligation {
	return cpi.ProofObligation{
		ObligationID:       "conformance-no-irrev-before-approval",
		SourceKind:         "PlanIR",
		Invariant:          cpi.ProofInvariantNoIrreversibleBeforeApproval,
		CanonicalInputHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		RiskClass:          "T3",
		AllowedToolchain:   []string{cpi.ProofToolchainDeterministicV0},
		Budget:             cpi.ProofBudget{MaxNodes: 4},
		Plan: cpi.ProofPlanView{Nodes: []cpi.ProofPlanNode{
			{NodeID: "approval", ApprovalCheckpoint: true},
			{NodeID: "wire-funds", SideEffect: true, EffectClass: "IRREVERSIBLE"},
		}},
	}
}
