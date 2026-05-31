package contracts

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEvidencePackEUAIActProfileIsOptionalAndRoundTrips(t *testing.T) {
	var legacy EvidencePack
	if err := json.Unmarshal([]byte(`{"pack_id":"ep-legacy","format_version":"1.0","created_at":"2026-05-31T00:00:00Z"}`), &legacy); err != nil {
		t.Fatalf("legacy unmarshal error = %v", err)
	}
	if legacy.EUAIActProfile != nil {
		t.Fatalf("legacy pack profile = %#v, want nil", legacy.EUAIActProfile)
	}

	pack := EvidencePack{
		PackID:        "ep-ai-act",
		FormatVersion: "1.0",
		CreatedAt:     time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC),
		EUAIActProfile: &EUAIActEvidenceProfile{
			ProfileID:                "eu-ai-act:hr:1",
			RiskCategory:             "high-risk Annex III employment",
			RelevantArticles:         []string{"Article 9", "Article 14", "Article 26", "Article 27"},
			ProviderOrDeployerRole:   "deployer",
			FRIARefs:                 []string{"fria:1"},
			HumanOversightRefs:       []string{"oversight:head-hr"},
			AffectedPersonNoticeRefs: []string{"notice:candidate"},
			RedactionProfile:         "employment_minimized",
			TimelineStatus:           "FINAL",
		},
	}
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("marshal error = %v", err)
	}
	var decoded EvidencePack
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal error = %v", err)
	}
	if decoded.EUAIActProfile == nil || decoded.EUAIActProfile.FRIARefs[0] != "fria:1" {
		t.Fatalf("decoded profile = %#v, want FRIA ref", decoded.EUAIActProfile)
	}
}
