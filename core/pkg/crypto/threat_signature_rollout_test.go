package crypto

// quantum_posture: rollout tests cover classical, ML-DSA, and hybrid threat-v1
// signature profiles without making a post-quantum certification claim.

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type threatDecisionVerifier interface {
	VerifyDecision(*contracts.DecisionRecord) (bool, error)
}

func TestThreatDecisionSignatureRollingCompatibility(t *testing.T) {
	t.Run("ed25519", func(t *testing.T) {
		signer, err := NewEd25519Signer("rollout-ed")
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := NewEd25519Verifier(signer.PublicKeyBytes())
		if err != nil {
			t.Fatal(err)
		}
		exerciseThreatDecisionRollout(
			t,
			signer,
			verifier,
			SigPrefixEd25519+SigSeparator+"rollout-ed",
			SigPrefixEd25519ThreatV1+SigSeparator+"rollout-ed",
			func(message, signature string) (bool, error) {
				return Verify(signer.PublicKey(), signature, []byte(message))
			},
		)
	})

	t.Run("ml-dsa-65", func(t *testing.T) {
		signer, err := NewMLDSASigner("rollout-ml")
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := NewMLDSAVerifier(signer.PublicKeyBytes())
		if err != nil {
			t.Fatal(err)
		}
		exerciseThreatDecisionRollout(
			t,
			signer,
			verifier,
			SigPrefixMLDSA65+SigSeparator+"rollout-ml",
			SigPrefixMLDSA65ThreatV1+SigSeparator+"rollout-ml",
			func(message, signature string) (bool, error) {
				decoded, err := hex.DecodeString(signature)
				if err != nil {
					return false, err
				}
				return signer.Verify([]byte(message), decoded), nil
			},
		)
	})

	t.Run("hybrid", func(t *testing.T) {
		signer, err := NewHybridSigner("rollout-hybrid")
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := NewHybridVerifier(signer.Ed25519Signer().PublicKeyBytes(), signer.MLDSASigner().PublicKeyBytes())
		if err != nil {
			t.Fatal(err)
		}
		exerciseThreatDecisionRollout(
			t,
			signer,
			verifier,
			SigPrefixHybrid+SigSeparator+"rollout-hybrid",
			SigPrefixHybridThreatV1+SigSeparator+"rollout-hybrid",
			func(message, signature string) (bool, error) {
				return signer.Verify([]byte(message), signature)
			},
		)
	})
}

func exerciseThreatDecisionRollout(
	t *testing.T,
	signer Signer,
	verifier threatDecisionVerifier,
	wantPrimaryType string,
	wantThreatType string,
	legacyVerify func(message, signature string) (bool, error),
) {
	t.Helper()
	decision := threatRolloutDecision()
	if err := signer.SignDecision(decision); err != nil {
		t.Fatal(err)
	}
	if decision.SignatureType != wantPrimaryType {
		t.Fatalf("primary signature type = %q, want legacy profile %q", decision.SignatureType, wantPrimaryType)
	}
	if decision.ThreatScanSignatureType != wantThreatType {
		t.Fatalf("threat signature type = %q, want %q", decision.ThreatScanSignatureType, wantThreatType)
	}
	if decision.ThreatScanSignature == "" {
		t.Fatal("missing threat-v1 secondary signature")
	}
	if strings.Count(decision.Reason, decisionThreatReasonMarker) != 1 {
		t.Fatalf("signed reason does not contain exactly one threat marker: %q", decision.Reason)
	}

	// A pre-threat-scan verifier ignores the additive fields and verifies the
	// unchanged legacy profile over the primary signature.
	legacyValid, err := legacyVerify(legacyDecisionPayload(decision), decision.Signature)
	if err != nil || !legacyValid {
		t.Fatalf("legacy verifier rejected rolling-compatible primary signature: valid=%v err=%v", legacyValid, err)
	}
	valid, err := verifier.VerifyDecision(decision)
	if err != nil || !valid {
		t.Fatalf("upgraded verifier rejected dual-signed decision: valid=%v err=%v", valid, err)
	}

	// Re-signing the same record is deterministic in structure and must not
	// duplicate the reserved anti-stripping marker.
	if err := signer.SignDecision(decision); err != nil {
		t.Fatal(err)
	}
	if strings.Count(decision.Reason, decisionThreatReasonMarker) != 1 {
		t.Fatalf("re-signing duplicated the threat marker: %q", decision.Reason)
	}

	tampered := cloneThreatDecision(decision)
	tampered.ThreatScan.FindingCount++
	assertThreatDecisionRejected(t, verifier, tampered, "typed evidence tampering")

	wrongKey := cloneThreatDecision(decision)
	profile, _, ok := splitSignatureType(wrongKey.ThreatScanSignatureType)
	if !ok {
		t.Fatalf("invalid test threat signature type %q", wrongKey.ThreatScanSignatureType)
	}
	wrongKey.ThreatScanSignatureType = profile + SigSeparator + "different-key"
	assertThreatDecisionRejected(t, verifier, wrongKey, "secondary key mismatch")

	stripped := cloneThreatDecision(decision)
	stripped.ThreatScan = nil
	stripped.ThreatScanSignature = ""
	stripped.ThreatScanSignatureType = ""
	assertThreatDecisionRejected(t, verifier, stripped, "additive field stripping")

	// The legacy preimage uses colon delimiters. Relocating one delimiter into
	// the marker can move marker fragments across fields without changing a
	// single signed byte. Upgraded verification scans the reconstructed legacy
	// preimage and therefore still detects the reserved marker.
	relocated := cloneThreatDecision(stripped)
	markerIndex := strings.Index(relocated.Reason, decisionThreatReasonMarker)
	if markerIndex < 0 {
		t.Fatalf("test decision is missing threat marker: %q", relocated.Reason)
	}
	marker := relocated.Reason[markerIndex:]
	relocatedDelimiter := strings.Index(marker, SigSeparator)
	if relocatedDelimiter < 0 {
		t.Fatalf("test marker has no relocatable delimiter: %q", marker)
	}
	relocated.Reason = relocated.Reason[:markerIndex] + marker[:relocatedDelimiter]
	relocated.PhenotypeHash = marker[relocatedDelimiter+1:] + SigSeparator + relocated.PhenotypeHash
	if legacyDecisionPayload(relocated) != legacyDecisionPayload(decision) {
		t.Fatal("test boundary relocation did not preserve the legacy signature preimage")
	}
	legacyValid, err = legacyVerify(legacyDecisionPayload(relocated), relocated.Signature)
	if err != nil || !legacyValid {
		t.Fatalf("legacy verifier should accept the preserved relocation preimage: valid=%v err=%v", legacyValid, err)
	}
	assertThreatDecisionRejected(t, verifier, relocated, "marker boundary relocation")

	// Removing the signed marker as well cannot recover a valid legacy record:
	// the marker was part of the primary signature preimage.
	unmarked := cloneThreatDecision(stripped)
	markerIndex = strings.Index(unmarked.Reason, decisionThreatReasonMarker)
	if markerIndex < 0 {
		t.Fatalf("test decision is missing threat marker: %q", unmarked.Reason)
	}
	unmarked.Reason = unmarked.Reason[:markerIndex]
	legacyValid, err = legacyVerify(legacyDecisionPayload(unmarked), unmarked.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if legacyValid {
		t.Fatal("legacy verifier accepted a record after the anti-stripping marker was removed")
	}
	assertThreatDecisionRejected(t, verifier, unmarked, "evidence and marker stripping")
}

func threatRolloutDecision() *contracts.DecisionRecord {
	return &contracts.DecisionRecord{
		ID:                "decision-rollout",
		Verdict:           "ALLOW",
		Reason:            "policy matched",
		PhenotypeHash:     "sha256:phenotype",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      "sha256:effect",
		ThreatScan: &contracts.ThreatScanRef{
			ScanID:       "scan-rollout",
			MaxSeverity:  contracts.ThreatSeverityInfo,
			FindingCount: 1,
			TrustLevel:   contracts.InputTrustTrusted,
			InputHash:    "sha256:input",
		},
	}
}

func cloneThreatDecision(source *contracts.DecisionRecord) *contracts.DecisionRecord {
	clone := *source
	if source.ThreatScan != nil {
		threatClone := *source.ThreatScan
		clone.ThreatScan = &threatClone
	}
	return &clone
}

func assertThreatDecisionRejected(t *testing.T, verifier threatDecisionVerifier, decision *contracts.DecisionRecord, caseName string) {
	t.Helper()
	valid, err := verifier.VerifyDecision(decision)
	if err == nil && valid {
		t.Fatalf("upgraded verifier accepted %s", caseName)
	}
}
