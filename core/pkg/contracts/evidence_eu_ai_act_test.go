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

func TestValidateEUAIActEvidenceProfile(t *testing.T) {
	if issues := ValidateEUAIActEvidenceProfile(nil); len(issues) != 0 {
		t.Fatalf("nil profile issues = %v, want none", issues)
	}

	profile := completeEUAIActProfile()
	if issues := ValidateEUAIActEvidenceProfile(profile); len(issues) != 0 {
		t.Fatalf("complete profile issues = %v, want none", issues)
	}

	profile.HumanOversightRefs = nil
	profile.RedactionMetadata = map[string]string{"api_key": "redacted"}
	issues := ValidateEUAIActEvidenceProfile(profile)
	assertIssue(t, issues, "eu_ai_act_profile.human_oversight_refs is required for high-risk profiles")
	assertIssue(t, issues, "eu_ai_act_profile.redaction_metadata must not include raw secret-bearing keys")
}

func completeEUAIActProfile() *EUAIActEvidenceProfile {
	return &EUAIActEvidenceProfile{
		ProfileID:                           "eu-ai-act:hr:1",
		RoleMap:                             EUAIActRoleMap{Deployer: "Mindburn Labs"},
		RiskCategory:                        "high-risk Annex III employment",
		RelevantArticles:                    []string{"Article 9", "Article 10", "Article 12", "Article 14", "Article 26", "Article 27"},
		HighRiskReasons:                     []string{"employment and worker management"},
		ProviderOrDeployerRole:              "deployer",
		RiskManagementRefs:                  []string{"risk:1"},
		DataGovernanceRefs:                  []string{"data:1"},
		LogRecordRefs:                       []string{"logs:1"},
		TransparencyNoticeRefs:              []string{"instructions:1"},
		HumanOversightRefs:                  []string{"oversight:head-hr"},
		AccuracyRobustnessCybersecurityRefs: []string{"security:1"},
		FRIARefs:                            []string{"fria:1"},
		AffectedPersonNoticeRefs:            []string{"notice:1"},
		RegistrationRefs:                    []string{"registration:1"},
		RedactionProfile:                    "employment_minimized",
		RetentionProfile:                    "enterprise_hr_legal_hold",
		TimelineStatus:                      "FINAL",
		RedactionMetadata:                   map[string]string{"profile": "employment_minimized"},
	}
}

func assertIssue(t *testing.T, issues []string, want string) {
	t.Helper()
	for _, issue := range issues {
		if issue == want {
			return
		}
	}
	t.Fatalf("issues = %v, want %q", issues, want)
}
