package ceremony

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func TestFinal_DefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	if p.MinTimelockMs != 2000 || p.MinHoldMs != 1000 {
		t.Fatal("default policy values")
	}
}

func TestFinal_StrictPolicy(t *testing.T) {
	p := StrictPolicy()
	if !p.RequireChallenge || p.MinTimelockMs != 5000 {
		t.Fatal("strict policy values")
	}
}

func TestFinal_CeremonyPolicyJSONRoundTrip(t *testing.T) {
	p := CeremonyPolicy{MinTimelockMs: 3000, DomainSeparation: "helm:v1"}
	data, _ := json.Marshal(p)
	var got CeremonyPolicy
	json.Unmarshal(data, &got)
	if got.MinTimelockMs != 3000 {
		t.Fatal("round-trip")
	}
}

func TestFinal_CeremonyRequestJSONRoundTrip(t *testing.T) {
	r := CeremonyRequest{DecisionID: "d1", TimelockMs: 5000, HoldMs: 3000, Signature: "sig"}
	data, _ := json.Marshal(r)
	var got CeremonyRequest
	json.Unmarshal(data, &got)
	if got.DecisionID != "d1" || got.TimelockMs != 5000 {
		t.Fatal("request round-trip")
	}
}

func TestFinal_CeremonyResultJSONRoundTrip(t *testing.T) {
	r := CeremonyResult{Valid: true, Reason: "all checks passed"}
	data, _ := json.Marshal(r)
	var got CeremonyResult
	json.Unmarshal(data, &got)
	if !got.Valid {
		t.Fatal("result round-trip")
	}
}

func TestFinal_ValidateCeremonySuccess(t *testing.T) {
	p := DefaultPolicy()
	req := CeremonyRequest{TimelockMs: 3000, HoldMs: 2000, UISummaryHash: "h", Signature: "sig"}
	result := ValidateCeremony(p, req)
	if !result.Valid {
		t.Fatalf("should be valid: %s", result.Reason)
	}
}

func TestFinal_ValidateCeremonyTimelockTooShort(t *testing.T) {
	p := DefaultPolicy()
	req := CeremonyRequest{TimelockMs: 100, HoldMs: 2000, UISummaryHash: "h", Signature: "sig"}
	result := ValidateCeremony(p, req)
	if result.Valid {
		t.Fatal("should fail on short timelock")
	}
}

func TestFinal_ValidateCeremonyHoldTooShort(t *testing.T) {
	p := DefaultPolicy()
	req := CeremonyRequest{TimelockMs: 3000, HoldMs: 100, UISummaryHash: "h", Signature: "sig"}
	result := ValidateCeremony(p, req)
	if result.Valid {
		t.Fatal("should fail on short hold")
	}
}

func TestFinal_ValidateCeremonyMissingUIHash(t *testing.T) {
	p := DefaultPolicy()
	req := CeremonyRequest{TimelockMs: 3000, HoldMs: 2000, Signature: "sig"}
	result := ValidateCeremony(p, req)
	if result.Valid {
		t.Fatal("should fail on missing UI hash")
	}
}

func TestFinal_ValidateCeremonyMissingSignature(t *testing.T) {
	p := DefaultPolicy()
	req := CeremonyRequest{TimelockMs: 3000, HoldMs: 2000, UISummaryHash: "h"}
	result := ValidateCeremony(p, req)
	if result.Valid {
		t.Fatal("should fail on missing signature")
	}
}

func TestFinal_ValidateCeremonyChallengeMissing(t *testing.T) {
	p := StrictPolicy()
	req := CeremonyRequest{TimelockMs: 6000, HoldMs: 4000, UISummaryHash: "h", Signature: "sig"}
	result := ValidateCeremony(p, req)
	if result.Valid {
		t.Fatal("should fail when challenge required but not provided")
	}
}

func TestFinal_ValidateCeremonyWithChallenge(t *testing.T) {
	p := StrictPolicy()
	req := CeremonyRequest{
		TimelockMs: 6000, HoldMs: 4000, UISummaryHash: "h",
		ChallengeHash: "ch", ResponseHash: "rh", Signature: "sig",
	}
	result := ValidateCeremony(p, req)
	if !result.Valid {
		t.Fatalf("should be valid: %s", result.Reason)
	}
}

func TestFinal_HashUISummaryDeterministic(t *testing.T) {
	h1 := HashUISummary("test summary")
	h2 := HashUISummary("test summary")
	if h1 != h2 {
		t.Fatal("not deterministic")
	}
}

func TestFinal_HashUISummaryDifferentInputs(t *testing.T) {
	h1 := HashUISummary("summary A")
	h2 := HashUISummary("summary B")
	if h1 == h2 {
		t.Fatal("different inputs should differ")
	}
}

func TestFinal_HashChallengeDeterministic(t *testing.T) {
	h1 := HashChallenge("challenge-1")
	h2 := HashChallenge("challenge-1")
	if h1 != h2 {
		t.Fatal("not deterministic")
	}
}

func TestFinal_HashChallengeDifferentInputs(t *testing.T) {
	h1 := HashChallenge("a")
	h2 := HashChallenge("b")
	if h1 == h2 {
		t.Fatal("different inputs")
	}
}

func TestFinal_HashUISummaryLength(t *testing.T) {
	h := HashUISummary("test")
	if len(h) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h))
	}
}

func TestFinal_DeriveGenesisChallenge(t *testing.T) {
	b := contracts.GenesisApprovalBinding{
		PolicyGenesisHash: "h1", MirrorTextHash: "h2",
		ImpactReportHash: "h3", P0CeilingHash: "h4",
	}
	c := DeriveGenesisChallenge(b)
	if c == "" || len(c) != 64 {
		t.Fatal("challenge should be 64 hex chars")
	}
}

func TestFinal_DeriveGenesisChallengeDeterministic(t *testing.T) {
	b := contracts.GenesisApprovalBinding{
		PolicyGenesisHash: "h1", MirrorTextHash: "h2",
		ImpactReportHash: "h3", P0CeilingHash: "h4",
	}
	c1 := DeriveGenesisChallenge(b)
	c2 := DeriveGenesisChallenge(b)
	if c1 != c2 {
		t.Fatal("not deterministic")
	}
}

func TestFinal_ValidateGenesisMissingPolicyHash(t *testing.T) {
	req := contracts.GenesisApprovalRequest{Binding: contracts.GenesisApprovalBinding{}}
	result := ValidateGenesisApproval(req)
	if result.Valid {
		t.Fatal("should fail on missing policy hash")
	}
}

func TestFinal_ValidateGenesisMissingSignatures(t *testing.T) {
	b := contracts.GenesisApprovalBinding{PolicyGenesisHash: "h1", MirrorTextHash: "h2", ImpactReportHash: "h3", P0CeilingHash: "h4"}
	req := contracts.GenesisApprovalRequest{
		Binding:          b,
		ChallengeHash:    DeriveGenesisChallenge(b),
		TimelockDuration: time.Minute,
	}
	result := ValidateGenesisApproval(req)
	if result.Valid {
		t.Fatal("should fail without signatures")
	}
}

func TestFinal_ValidateGenesisSuccess(t *testing.T) {
	b := contracts.GenesisApprovalBinding{PolicyGenesisHash: "h1", MirrorTextHash: "h2", ImpactReportHash: "h3", P0CeilingHash: "h4"}
	req := contracts.GenesisApprovalRequest{
		Binding:          b,
		ChallengeHash:    DeriveGenesisChallenge(b),
		TimelockDuration: time.Minute,
		ApproverKeyIDs:   []string{"key1"},
		Signatures:       []string{"sig1"},
		SubmittedAt:      time.Now(),
	}
	result := ValidateGenesisApproval(req)
	if !result.Valid {
		t.Fatalf("should be valid: %s", result.Reason)
	}
}

func TestFinal_ValidateGenesisQuorumNotMet(t *testing.T) {
	b := contracts.GenesisApprovalBinding{PolicyGenesisHash: "h1", MirrorTextHash: "h2", ImpactReportHash: "h3", P0CeilingHash: "h4"}
	req := contracts.GenesisApprovalRequest{
		Binding:          b,
		ChallengeHash:    DeriveGenesisChallenge(b),
		TimelockDuration: time.Minute,
		ApproverKeyIDs:   []string{"key1"},
		Signatures:       []string{"sig1"},
		Quorum:           3,
		SubmittedAt:      time.Now(),
	}
	result := ValidateGenesisApproval(req)
	if result.Valid {
		t.Fatal("should fail on unmet quorum")
	}
}

func TestFinal_ValidateGenesisEmergencyOverride(t *testing.T) {
	b := contracts.GenesisApprovalBinding{PolicyGenesisHash: "h1", MirrorTextHash: "h2", ImpactReportHash: "h3", P0CeilingHash: "h4"}
	req := contracts.GenesisApprovalRequest{
		Binding:           b,
		ChallengeHash:     DeriveGenesisChallenge(b),
		TimelockDuration:  time.Minute,
		ApproverKeyIDs:    []string{"key1"},
		Signatures:        []string{"sig1"},
		SubmittedAt:       time.Now(),
		EmergencyOverride: true,
	}
	result := ValidateGenesisApproval(req)
	if !result.ElevatedRisk {
		t.Fatal("emergency override should flag elevated risk")
	}
}

func TestFinal_ValidateGenesisChallengeMismatch(t *testing.T) {
	b := contracts.GenesisApprovalBinding{PolicyGenesisHash: "h1", MirrorTextHash: "h2", ImpactReportHash: "h3", P0CeilingHash: "h4"}
	req := contracts.GenesisApprovalRequest{
		Binding:          b,
		ChallengeHash:    "wrong",
		TimelockDuration: time.Minute,
		ApproverKeyIDs:   []string{"key1"},
		Signatures:       []string{"sig1"},
	}
	result := ValidateGenesisApproval(req)
	if result.Valid {
		t.Fatal("should fail on challenge mismatch")
	}
}

func TestFinal_TimelockRemainingFuture(t *testing.T) {
	req := contracts.GenesisApprovalRequest{
		SubmittedAt:      time.Now(),
		TimelockDuration: time.Hour,
	}
	remaining := TimelockRemaining(req)
	if remaining <= 0 {
		t.Fatal("should have remaining time")
	}
}

func TestFinal_TimelockRemainingPast(t *testing.T) {
	req := contracts.GenesisApprovalRequest{
		SubmittedAt:      time.Now().Add(-2 * time.Hour),
		TimelockDuration: time.Hour,
	}
	remaining := TimelockRemaining(req)
	if remaining != 0 {
		t.Fatal("should be 0")
	}
}

func TestFinal_DomainSeparationDefault(t *testing.T) {
	p := DefaultPolicy()
	if p.DomainSeparation != "helm:approval:v1" {
		t.Fatal("wrong domain separation")
	}
}

func TestFinal_DomainSeparationStrict(t *testing.T) {
	p := StrictPolicy()
	if p.DomainSeparation != "helm:approval:v1:strict" {
		t.Fatal("wrong domain separation")
	}
}

func TestFinal_ValidateGenesisTimelockZero(t *testing.T) {
	b := contracts.GenesisApprovalBinding{PolicyGenesisHash: "h1", MirrorTextHash: "h2", ImpactReportHash: "h3", P0CeilingHash: "h4"}
	req := contracts.GenesisApprovalRequest{
		Binding:          b,
		ChallengeHash:    DeriveGenesisChallenge(b),
		TimelockDuration: 0,
		ApproverKeyIDs:   []string{"key1"},
		Signatures:       []string{"sig1"},
	}
	result := ValidateGenesisApproval(req)
	if result.Valid {
		t.Fatal("should fail on zero timelock")
	}
}
