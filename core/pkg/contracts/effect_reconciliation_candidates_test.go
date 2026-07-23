package contracts

import (
	"errors"
	"strings"
	"testing"
)

func TestEffectReconciliationCandidatesRejectAuthorityAndNonActiveStates(t *testing.T) {
	projection := effectReconciliationCandidatesFixture()
	if err := projection.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*EffectReconciliationCandidates){
		"effect authority":     func(p *EffectReconciliationCandidates) { p.ExecutionAuthority = "RECONCILE_SOURCE" },
		"admitted reservation": func(p *EffectReconciliationCandidates) { p.Candidates[0].ReservationState = "ADMITTED" },
		"missing successor":    func(p *EffectReconciliationCandidates) { p.Candidates[0].PreviousReceiptHash = "" },
		"mismatched fence":     func(p *EffectReconciliationCandidates) { p.Fence.CommandHash = "sha256:bad" },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := projection
			mutated.Candidates = append([]EffectReconciliationCandidate(nil), projection.Candidates...)
			mutate(&mutated)
			if err := mutated.Validate(); !errors.Is(err, ErrEffectReconciliationCandidatesInvalid) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func effectReconciliationCandidatesFixture() EffectReconciliationCandidates {
	return EffectReconciliationCandidates{
		SchemaVersion:      EffectReconciliationCandidatesSchemaV1,
		ContractVersion:    EffectReconciliationCandidatesContractV1,
		ExecutionAuthority: EffectDispositionExecutionAuthorityNone,
		TenantID:           "tenant-a", WorkspaceID: "workspace-a", Audience: "helm-data-plane",
		Fence: EffectReconciliationFence{
			CommandID: "fence-a", CommandHash: "sha256:" + strings.Repeat("1", 64), Epoch: 2,
			ReceiptHash: "sha256:" + strings.Repeat("2", 64),
		},
		Candidates: []EffectReconciliationCandidate{{
			AdmissionID: "admission-a", AttemptID: "attempt-a", ReservationSequence: 3,
			ReservationHeadHash: "sha256:" + strings.Repeat("3", 64), ReservationState: EffectClosePriorStateUncertain,
			ConnectorID: "github", ConnectorVersion: "1.0.0", ConnectorAction: "github.create_issue",
			ConnectorExecutionRef: "github-request-a", ProofSessionRef: "proof-a", IntentRef: "intent-a", EffectRef: "issue-a",
			IdempotencyKeyHash: "sha256:" + strings.Repeat("4", 64), EffectHash: "sha256:" + strings.Repeat("5", 64),
			NextDispositionSequence: 2, PreviousReceiptHash: "sha256:" + strings.Repeat("6", 64),
		}},
	}
}
