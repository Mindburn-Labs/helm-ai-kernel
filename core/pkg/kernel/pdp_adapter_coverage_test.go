package kernel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/governance"
)

func TestGovernancePDPAdapterMapsRequestAndDecisions(t *testing.T) {
	submittedAt := time.Date(2026, 6, 2, 10, 0, 0, 0, time.UTC)
	baseReq := &EffectRequest{
		EffectID:    "effect-1",
		EffectType:  EffectTypeFundsTransfer,
		SubmittedAt: submittedAt,
		Subject: EffectSubject{
			SubjectID:   "agent-1",
			SubjectType: "agent",
			SessionID:   "session-1",
		},
		Payload: EffectPayload{PayloadHash: "payload-hash"},
		Idempotency: &IdempotencyConfig{
			Key: "idempotency-key",
		},
		Context: &EffectContext{
			ModeID:        "mode-1",
			LoopID:        "loop-1",
			PhenotypeHash: "phenotype-hash",
			EnvironmentID: "environment-hash",
		},
	}

	cases := []struct {
		name         string
		pdpDecision  governance.Decision
		wantDecision string
	}{
		{"allow", governance.DecisionAllow, "ALLOW"},
		{"deny", governance.DecisionDeny, "DENY"},
		{"approval", governance.DecisionRequireApproval, "REQUIRE_APPROVAL"},
		{"evidence", governance.DecisionRequireEvidence, "REQUIRE_EVIDENCE"},
		{"defer", governance.DecisionDefer, "DEFER"},
		{"unknown defaults deny", governance.Decision("UNKNOWN"), "DENY"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pdp := &fakeGovernancePDP{
				decision:   tc.pdpDecision,
				decisionID: "decision-" + tc.name,
			}
			adapter := NewGovernancePDPAdapter(pdp)

			decision, decisionID, err := adapter.Evaluate(context.Background(), baseReq)
			if err != nil {
				t.Fatalf("Evaluate returned error: %v", err)
			}
			if decision != tc.wantDecision {
				t.Fatalf("decision mismatch: got %s want %s", decision, tc.wantDecision)
			}
			if decisionID != pdp.decisionID {
				t.Fatalf("decision ID mismatch: got %s want %s", decisionID, pdp.decisionID)
			}

			got := pdp.lastRequest
			if got.RequestID != baseReq.EffectID ||
				got.Effect.EffectID != baseReq.EffectID ||
				got.Effect.EffectType != string(baseReq.EffectType) ||
				got.Effect.EffectPayloadHash != baseReq.Payload.PayloadHash ||
				got.Effect.IdempotencyKey != baseReq.Idempotency.Key {
				t.Fatalf("effect mapping mismatch: %+v", got.Effect)
			}
			if got.Subject.ActorID != baseReq.Subject.SubjectID ||
				got.Subject.ActorType != baseReq.Subject.SubjectType ||
				got.Subject.AuthContext.SessionID != baseReq.Subject.SessionID {
				t.Fatalf("subject mapping mismatch: %+v", got.Subject)
			}
			if got.Context.ModeID != baseReq.Context.ModeID ||
				got.Context.LoopID != baseReq.Context.LoopID ||
				got.Context.PhenotypeHash != baseReq.Context.PhenotypeHash ||
				got.Context.EnvironmentSnapshotHash != baseReq.Context.EnvironmentID ||
				got.Context.Time.DecisionTimeSource != "observed_at" ||
				!got.Context.Time.Timestamp.Equal(submittedAt) {
				t.Fatalf("context mapping mismatch: %+v", got.Context)
			}
		})
	}
}

func TestGovernancePDPAdapterPropagatesErrors(t *testing.T) {
	wantErr := errors.New("pdp unavailable")
	adapter := NewGovernancePDPAdapter(&fakeGovernancePDP{err: wantErr})

	decision, decisionID, err := adapter.Evaluate(context.Background(), &EffectRequest{
		EffectID:   "effect-error",
		EffectType: EffectTypeNotify,
		Subject:    EffectSubject{SubjectID: "agent-1"},
		Payload:    EffectPayload{PayloadHash: "payload-hash"},
	})

	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped PDP error, got %v", err)
	}
	if decision != "DENY" || decisionID != "" {
		t.Fatalf("PDP errors should fail closed, got decision=%s decisionID=%s", decision, decisionID)
	}
}

func TestNewWiredEffectBoundarySubmitsThroughGovernancePDP(t *testing.T) {
	pdp := &fakeGovernancePDP{decision: governance.DecisionAllow, decisionID: "decision-allow"}
	log := NewInMemoryEventLog()

	boundary := NewWiredEffectBoundary(pdp, log)
	if boundary.InMemoryEffectBoundary == nil || boundary.pdpAdapter == nil {
		t.Fatalf("wired boundary missing components: %+v", boundary)
	}

	lifecycle, err := boundary.Submit(context.Background(), &EffectRequest{
		EffectID:   "effect-allow",
		EffectType: EffectTypeNotify,
		Subject:    EffectSubject{SubjectID: "agent-1", SubjectType: "agent"},
		Payload:    EffectPayload{PayloadHash: "payload-hash"},
	})
	if err != nil {
		t.Fatalf("Submit returned error: %v", err)
	}
	if lifecycle.State != "approved" || lifecycle.PDPDecisionID != "decision-allow" {
		t.Fatalf("unexpected lifecycle: %+v", lifecycle)
	}
	if log.LastSequence() != 1 {
		t.Fatalf("expected submitted event to be logged, got last sequence %d", log.LastSequence())
	}
}

type fakeGovernancePDP struct {
	decision    governance.Decision
	decisionID  string
	err         error
	lastRequest governance.PDPRequest
}

func (p *fakeGovernancePDP) Evaluate(_ context.Context, req governance.PDPRequest) (*governance.PDPResponse, error) {
	p.lastRequest = req
	if p.err != nil {
		return nil, p.err
	}
	return &governance.PDPResponse{
		Decision:   p.decision,
		DecisionID: p.decisionID,
	}, nil
}

func (p *fakeGovernancePDP) PolicyVersion() string {
	return "test-policy"
}
