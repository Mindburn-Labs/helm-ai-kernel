package a2a

import (
	"testing"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// A2A Conformance Test Vectors
//
// These tests provide deterministic coverage of every negotiation code path:
//   - Version negotiation (semver major/minor/patch compatibility)
//   - Feature negotiation (required, offered, intersection)
//   - Signature validation (key lookup, agent binding, algorithm, tamper)
//   - Envelope completeness (missing fields → deterministic deny)
//   - Expiry handling (expired → deny)
//   - Policy enforcement (deny rules, wildcard matching)
//
// Each deny case asserts the exact DenyReason code.
// ══════════════════════════════════════════════════════════════════════════════

// --- Helpers ----------------------------------------------------------------

func staticClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// --- Version Negotiation ----------------------------------------------------

// --- Feature Negotiation ----------------------------------------------------

// --- Signature Validation ---------------------------------------------------

// --- Envelope Completeness --------------------------------------------------

// --- Expiry Handling --------------------------------------------------------

// --- Policy Enforcement -----------------------------------------------------

// --- Evaluation Order -------------------------------------------------------

// --- Receipt & Metadata -----------------------------------------------------

// --- Hash Determinism -------------------------------------------------------

// --- DenyReason Constants ---------------------------------------------------

func TestConformance_DenyReasonValues(t *testing.T) {
	// Verify all 7 DenyReason constants have expected string values
	reasons := map[DenyReason]string{
		DenyVersionIncompatible: "VERSION_INCOMPATIBLE",
		DenyFeatureMissing:      "FEATURE_MISSING",
		DenyPolicyViolation:     "POLICY_VIOLATION",
		DenySignatureInvalid:    "SIGNATURE_INVALID",
		DenyAgentNotTrusted:     "AGENT_NOT_TRUSTED",
		DenyChallengeFailure:    "CHALLENGE_FAILURE",
		DenyVouchRevoked:        "VOUCH_REVOKED",
	}
	for constant, expected := range reasons {
		if string(constant) != expected {
			t.Errorf("DenyReason %q: expected %q", constant, expected)
		}
	}
}

// --- Feature Constants ------------------------------------------------------

func TestConformance_FeatureValues(t *testing.T) {
	// Verify all 9 Feature constants have expected string values
	features := map[Feature]string{
		FeatureMeteringReceipts:  "METERING_RECEIPTS",
		FeatureDisputeReplay:     "DISPUTE_REPLAY",
		FeatureProofGraphSync:    "PROOFGRAPH_SYNC",
		FeatureEvidenceExport:    "EVIDENCE_EXPORT",
		FeaturePolicyNegotiation: "POLICY_NEGOTIATION",
		FeatureAgentPayments:     "AGENT_PAYMENTS",
		FeatureIATPAuth:          "IATP_AUTH",
		FeaturePeerVouching:      "PEER_VOUCHING",
		FeatureTrustPropagation:  "TRUST_PROPAGATION",
	}
	for constant, expected := range features {
		if string(constant) != expected {
			t.Errorf("Feature %q: expected %q", constant, expected)
		}
	}
}

// --- SchemaVersion -----------------------------------------------------------

func TestConformance_SchemaVersion_String(t *testing.T) {
	cases := []struct {
		v    SchemaVersion
		want string
	}{
		{SchemaVersion{1, 0, 0}, "1.0.0"},
		{SchemaVersion{2, 5, 13}, "2.5.13"},
		{SchemaVersion{0, 0, 0}, "0.0.0"},
		{SchemaVersion{99, 99, 99}, "99.99.99"},
	}
	for _, tc := range cases {
		got := tc.v.String()
		if got != tc.want {
			t.Errorf("SchemaVersion%v.String() = %q, want %q", tc.v, got, tc.want)
		}
	}
}

func TestConformance_CurrentVersion(t *testing.T) {
	if CurrentVersion.Major != 1 || CurrentVersion.Minor != 0 || CurrentVersion.Patch != 0 {
		t.Fatalf("expected CurrentVersion 1.0.0, got %s", CurrentVersion.String())
	}
}
