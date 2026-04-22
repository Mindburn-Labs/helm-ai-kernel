package ceremony

import (
	"testing"
)

func TestValidateCeremony_HappyPath(t *testing.T) {
	policy := DefaultPolicy()
	req := CeremonyRequest{
		DecisionID:    "dec-1",
		TimelockMs:    3000,
		HoldMs:        2000,
		UISummaryHash: HashUISummary("Delete production database?"),
		SignerKeyID:   "k-1",
		Signature:     "sig-placeholder",
		LamportHeight: 42,
	}

	result := ValidateCeremony(policy, req)
	if !result.Valid {
		t.Fatalf("expected valid, got: %s", result.Reason)
	}
}

func TestValidateCeremony_TimelockTooShort(t *testing.T) {
	policy := DefaultPolicy()
	req := CeremonyRequest{
		DecisionID:    "dec-1",
		TimelockMs:    500, // Below 2000ms minimum
		HoldMs:        2000,
		UISummaryHash: "hash",
		Signature:     "sig",
	}

	result := ValidateCeremony(policy, req)
	if result.Valid {
		t.Fatal("expected invalid for short timelock")
	}
}

func TestValidateCeremony_HoldTooShort(t *testing.T) {
	policy := DefaultPolicy()
	req := CeremonyRequest{
		DecisionID:    "dec-1",
		TimelockMs:    3000,
		HoldMs:        100, // Below 1000ms minimum
		UISummaryHash: "hash",
		Signature:     "sig",
	}

	result := ValidateCeremony(policy, req)
	if result.Valid {
		t.Fatal("expected invalid for short hold time")
	}
}

func TestValidateCeremony_StrictRequiresChallenge(t *testing.T) {
	policy := StrictPolicy()
	req := CeremonyRequest{
		DecisionID:    "dec-1",
		TimelockMs:    6000,
		HoldMs:        4000,
		UISummaryHash: "hash",
		Signature:     "sig",
		// Missing challenge/response
	}

	result := ValidateCeremony(policy, req)
	if result.Valid {
		t.Fatal("expected invalid when challenge/response missing in strict mode")
	}
}

func TestValidateCeremony_StrictWithChallenge(t *testing.T) {
	policy := StrictPolicy()
	req := CeremonyRequest{
		DecisionID:    "dec-1",
		TimelockMs:    6000,
		HoldMs:        4000,
		UISummaryHash: "hash",
		ChallengeHash: HashChallenge("type DELETE to confirm"),
		ResponseHash:  HashChallenge("DELETE"),
		Signature:     "sig",
	}

	result := ValidateCeremony(policy, req)
	if !result.Valid {
		t.Fatalf("expected valid, got: %s", result.Reason)
	}
}

func TestValidateCeremony_MissingSignature(t *testing.T) {
	policy := DefaultPolicy()
	req := CeremonyRequest{
		DecisionID:    "dec-1",
		TimelockMs:    3000,
		HoldMs:        2000,
		UISummaryHash: "hash",
	}

	result := ValidateCeremony(policy, req)
	if result.Valid {
		t.Fatal("expected invalid when signature missing")
	}
}

func TestHashUISummary_Deterministic(t *testing.T) {
	h1 := HashUISummary("Delete production database?")
	h2 := HashUISummary("Delete production database?")
	if h1 != h2 {
		t.Error("hash should be deterministic")
	}
	if h1 == "" {
		t.Error("hash should not be empty")
	}
}
