package researchruntime

import (
	"testing"
	"time"
)

func TestBuildTraceHashDeterministic(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	trace := TracePack{
		Mission: MissionSpec{
			MissionID:        "mission-1",
			Title:            "Weekly paper",
			Thesis:           "Governed autonomy beats prompt loops.",
			Mode:             MissionModeEditorial,
			Class:            MissionClassWeeklyPaper,
			PublicationClass: PublicationClassExternalPaper,
			Trigger: MissionTrigger{
				Type:        MissionTriggerSchedule,
				Schedule:    "weekly",
				TriggeredAt: now,
			},
			CreatedAt: now,
		},
		WorkGraph: WorkGraph{
			MissionID: "mission-1",
			Version:   "v1",
			Nodes: []WorkNode{
				{ID: "plan", Role: WorkerPlanner, Title: "Plan", Required: true},
				{ID: "publish", Role: WorkerPublisher, Title: "Publish", DependsOn: []string{"plan"}, Required: true},
			},
			Edges: []WorkEdge{{From: "plan", To: "publish", Kind: "depends_on"}},
		},
	}
	hash1, err := BuildTraceHash(trace)
	if err != nil {
		t.Fatalf("hash1: %v", err)
	}
	hash2, err := BuildTraceHash(trace)
	if err != nil {
		t.Fatalf("hash2: %v", err)
	}
	if hash1 != hash2 {
		t.Fatalf("expected deterministic hash, got %q vs %q", hash1, hash2)
	}
}

func TestPromotionReceiptVerification(t *testing.T) {
	now := time.Unix(1_700_000_100, 0).UTC()
	receipt, err := BuildPromotionReceipt(PromotionReceipt{
		ReceiptID:        "rcpt-1",
		MissionID:        "mission-1",
		PublicationID:    "pub-1",
		PublicationState: PublicationStatePromoted,
		EvidencePackHash: "sha256:evidence",
		RequestedModel:   "openrouter/openai/gpt-5.4",
		ActualModel:      "openrouter/openai/gpt-5.4",
		PolicyDecision:   "ALLOW",
		CreatedAt:        now,
	})
	if err != nil {
		t.Fatalf("build receipt: %v", err)
	}
	if err := VerifyPromotionReceipt(receipt); err != nil {
		t.Fatalf("verify receipt: %v", err)
	}

	receipt.PolicyDecision = "DENY"
	if err := VerifyPromotionReceipt(receipt); err == nil {
		t.Fatal("expected verification failure after tamper")
	}
}

func TestPublicationStatesRemainCanonical(t *testing.T) {
	got := []PublicationState{
		PublicationStateDraft,
		PublicationStateScored,
		PublicationStateHeld,
		PublicationStateEligible,
		PublicationStatePromoted,
		PublicationStatePublished,
		PublicationStateSuperseded,
	}
	want := []PublicationState{"DRAFT", "SCORED", "HELD", "ELIGIBLE", "PROMOTED", "PUBLISHED", "SUPERSEDED"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("state %d mismatch: got %q want %q", i, got[i], want[i])
		}
	}
}
