package verification_test

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/verification"
)

// helper builds a SourceSnapshot with the given primary flag and provenance.
func src(primary bool, status researchruntime.ProvenanceStatus) researchruntime.SourceSnapshot {
	return researchruntime.SourceSnapshot{
		SourceID:         "s1",
		Primary:          primary,
		ProvenanceStatus: status,
	}
}

func defaultSources() []researchruntime.SourceSnapshot {
	return []researchruntime.SourceSnapshot{
		src(true, researchruntime.ProvenanceVerified),
		src(true, researchruntime.ProvenanceCaptured),
		src(false, researchruntime.ProvenanceVerified),
	}
}

func TestVerify_Allow_WhenAllCheckPass(t *testing.T) {
	svc := verification.New(verification.DefaultConfig())
	result := svc.Verify(context.Background(), &verification.VerifyInput{
		Draft:       &researchruntime.DraftManifest{DraftID: "d1"},
		Sources:     defaultSources(),
		EditorScore: 0.9,
	})

	if result.Verdict != "allow" {
		t.Errorf("expected allow, got %q (codes: %v)", result.Verdict, result.ReasonCodes)
	}
	if len(result.ReasonCodes) != 0 {
		t.Errorf("expected no reason codes, got %v", result.ReasonCodes)
	}
	if result.Score != 0.9 {
		t.Errorf("expected score 0.9, got %v", result.Score)
	}
}

func TestVerify_Allow_AtExactThreshold(t *testing.T) {
	svc := verification.New(verification.DefaultConfig())
	result := svc.Verify(context.Background(), &verification.VerifyInput{
		Draft:       &researchruntime.DraftManifest{DraftID: "d1"},
		Sources:     defaultSources(),
		EditorScore: 0.7, // exactly at threshold — should pass
	})

	if result.Verdict != "allow" {
		t.Errorf("expected allow at exact threshold, got %q (codes: %v)", result.Verdict, result.ReasonCodes)
	}
}

func TestVerify_Deny_PrimarySourceCountLow(t *testing.T) {
	svc := verification.New(verification.DefaultConfig())

	// Only one primary source — below the minimum of 2.
	sources := []researchruntime.SourceSnapshot{
		src(true, researchruntime.ProvenanceVerified),
		src(false, researchruntime.ProvenanceVerified),
	}

	result := svc.Verify(context.Background(), &verification.VerifyInput{
		Draft:       &researchruntime.DraftManifest{DraftID: "d1"},
		Sources:     sources,
		EditorScore: 0.9,
	})

	if result.Verdict != "deny" {
		t.Errorf("expected deny, got %q", result.Verdict)
	}
	if !containsCode(result.ReasonCodes, "ERR_PRIMARY_SOURCE_COUNT_LOW") {
		t.Errorf("expected ERR_PRIMARY_SOURCE_COUNT_LOW in %v", result.ReasonCodes)
	}
}

func TestVerify_Deny_NoPrimarySources(t *testing.T) {
	svc := verification.New(verification.DefaultConfig())

	sources := []researchruntime.SourceSnapshot{
		src(false, researchruntime.ProvenanceVerified),
		src(false, researchruntime.ProvenanceCaptured),
	}

	result := svc.Verify(context.Background(), &verification.VerifyInput{
		Draft:       &researchruntime.DraftManifest{DraftID: "d1"},
		Sources:     sources,
		EditorScore: 0.9,
	})

	if result.Verdict != "deny" {
		t.Errorf("expected deny, got %q", result.Verdict)
	}
	if !containsCode(result.ReasonCodes, "ERR_PRIMARY_SOURCE_COUNT_LOW") {
		t.Errorf("expected ERR_PRIMARY_SOURCE_COUNT_LOW in %v", result.ReasonCodes)
	}
}

func TestVerify_Deny_EditorScoreTooLow(t *testing.T) {
	svc := verification.New(verification.DefaultConfig())

	result := svc.Verify(context.Background(), &verification.VerifyInput{
		Draft:       &researchruntime.DraftManifest{DraftID: "d1"},
		Sources:     defaultSources(),
		EditorScore: 0.5,
	})

	if result.Verdict != "deny" {
		t.Errorf("expected deny, got %q", result.Verdict)
	}
	if !containsCode(result.ReasonCodes, "ERR_EDITOR_SCORE_TOO_LOW") {
		t.Errorf("expected ERR_EDITOR_SCORE_TOO_LOW in %v", result.ReasonCodes)
	}
}

func TestVerify_Deny_SourceWithDisputedStatus(t *testing.T) {
	svc := verification.New(verification.DefaultConfig())

	sources := []researchruntime.SourceSnapshot{
		src(true, researchruntime.ProvenanceVerified),
		src(true, researchruntime.ProvenanceDisputed), // rejected state
	}

	result := svc.Verify(context.Background(), &verification.VerifyInput{
		Draft:       &researchruntime.DraftManifest{DraftID: "d1"},
		Sources:     sources,
		EditorScore: 0.9,
	})

	if result.Verdict != "deny" {
		t.Errorf("expected deny, got %q", result.Verdict)
	}
	if !containsCode(result.ReasonCodes, "ERR_SOURCE_SNAPSHOT_MISSING") {
		t.Errorf("expected ERR_SOURCE_SNAPSHOT_MISSING in %v", result.ReasonCodes)
	}
}

func TestVerify_Deny_SourceWithDriftedStatus(t *testing.T) {
	svc := verification.New(verification.DefaultConfig())

	sources := []researchruntime.SourceSnapshot{
		src(true, researchruntime.ProvenanceVerified),
		src(true, researchruntime.ProvenanceDrifted),
	}

	result := svc.Verify(context.Background(), &verification.VerifyInput{
		Draft:       &researchruntime.DraftManifest{DraftID: "d1"},
		Sources:     sources,
		EditorScore: 0.9,
	})

	if result.Verdict != "deny" {
		t.Errorf("expected deny, got %q", result.Verdict)
	}
	if !containsCode(result.ReasonCodes, "ERR_SOURCE_SNAPSHOT_MISSING") {
		t.Errorf("expected ERR_SOURCE_SNAPSHOT_MISSING in %v", result.ReasonCodes)
	}
}

func TestVerify_Deny_SourceWithDiscoveredStatus(t *testing.T) {
	svc := verification.New(verification.DefaultConfig())

	sources := []researchruntime.SourceSnapshot{
		src(true, researchruntime.ProvenanceVerified),
		src(true, researchruntime.ProvenanceDiscovered), // not yet captured
	}

	result := svc.Verify(context.Background(), &verification.VerifyInput{
		Draft:       &researchruntime.DraftManifest{DraftID: "d1"},
		Sources:     sources,
		EditorScore: 0.9,
	})

	if result.Verdict != "deny" {
		t.Errorf("expected deny, got %q", result.Verdict)
	}
	if !containsCode(result.ReasonCodes, "ERR_SOURCE_SNAPSHOT_MISSING") {
		t.Errorf("expected ERR_SOURCE_SNAPSHOT_MISSING in %v", result.ReasonCodes)
	}
}

func TestVerify_Deny_MultipleReasonCodes(t *testing.T) {
	svc := verification.New(verification.DefaultConfig())

	// Both primary count low AND editor score low AND bad source provenance.
	sources := []researchruntime.SourceSnapshot{
		src(true, researchruntime.ProvenanceDisputed), // only 1 primary + bad provenance
	}

	result := svc.Verify(context.Background(), &verification.VerifyInput{
		Draft:       &researchruntime.DraftManifest{DraftID: "d1"},
		Sources:     sources,
		EditorScore: 0.3, // below 0.7
	})

	if result.Verdict != "deny" {
		t.Errorf("expected deny, got %q", result.Verdict)
	}
	if !containsCode(result.ReasonCodes, "ERR_PRIMARY_SOURCE_COUNT_LOW") {
		t.Errorf("expected ERR_PRIMARY_SOURCE_COUNT_LOW in %v", result.ReasonCodes)
	}
	if !containsCode(result.ReasonCodes, "ERR_SOURCE_SNAPSHOT_MISSING") {
		t.Errorf("expected ERR_SOURCE_SNAPSHOT_MISSING in %v", result.ReasonCodes)
	}
	if !containsCode(result.ReasonCodes, "ERR_EDITOR_SCORE_TOO_LOW") {
		t.Errorf("expected ERR_EDITOR_SCORE_TOO_LOW in %v", result.ReasonCodes)
	}
	if len(result.ReasonCodes) < 3 {
		t.Errorf("expected at least 3 reason codes, got %v", result.ReasonCodes)
	}
}

func TestVerify_SkipsSourceCheck_WhenRequireVerifiedFalse(t *testing.T) {
	cfg := verification.Config{
		MinPrimarySourceCount:     2,
		MinEditorScore:            0.7,
		RequireAllSourcesVerified: false,
	}
	svc := verification.New(cfg)

	sources := []researchruntime.SourceSnapshot{
		src(true, researchruntime.ProvenanceDisputed),
		src(true, researchruntime.ProvenanceDrifted),
	}

	result := svc.Verify(context.Background(), &verification.VerifyInput{
		Draft:       &researchruntime.DraftManifest{DraftID: "d1"},
		Sources:     sources,
		EditorScore: 0.9,
	})

	if result.Verdict != "allow" {
		t.Errorf("expected allow when RequireAllSourcesVerified=false, got %q (codes: %v)", result.Verdict, result.ReasonCodes)
	}
}

func TestVerify_ScoreEchoedInResult(t *testing.T) {
	svc := verification.New(verification.DefaultConfig())
	const score = 0.42
	result := svc.Verify(context.Background(), &verification.VerifyInput{
		Draft:       &researchruntime.DraftManifest{DraftID: "d1"},
		Sources:     defaultSources(),
		EditorScore: score,
	})
	if result.Score != score {
		t.Errorf("expected score %v echoed in result, got %v", score, result.Score)
	}
}

// containsCode is a small helper to avoid importing slices package.
func containsCode(codes []string, target string) bool {
	for _, c := range codes {
		if c == target {
			return true
		}
	}
	return false
}
