// quantum_posture: these signer tests cover classical Ed25519 receipt keys
// only and do not claim post-quantum protection.
package workstation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"path/filepath"
	"testing"
)

func workstationTestSigningSeed() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func workstationTestImportOptions() ImportOptions {
	return ImportOptions{SigningSeed: workstationTestSigningSeed()}
}

func workstationTestDecisionOptions() DecisionOptions {
	return DecisionOptions{SigningSeed: workstationTestSigningSeed()}
}

func workstationTestPublicKey() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(workstationTestSigningSeed()).Public().(ed25519.PublicKey)
}

func TestReceiptSigningRequiresExplicitSeedAndTrustedKey(t *testing.T) {
	profile := DefaultObserveDraftProfile()
	request := decisionRequest("network", "https://forbidden.example")
	if _, err := Decide(profile, request, DecisionOptions{}); err == nil {
		t.Fatal("expected zero signing seed decision to fail")
	}
	if _, err := ImportArtifactDir(filepath.Join(repoRoot(t), "fixtures", "workstation", "allowed-observe"), ImportOptions{}); err == nil {
		t.Fatal("expected zero signing seed import to fail")
	}

	receipt, err := Decide(profile, request, workstationTestDecisionOptions())
	if err != nil {
		t.Fatalf("sign trusted decision: %v", err)
	}
	if ok, err := VerifyDecisionReceiptWithTrustedKey(receipt, workstationTestPublicKey()); err != nil || !ok {
		t.Fatalf("trusted decision verification = %v/%v, want true/nil", ok, err)
	}

	attackerSeed := []byte("fedcba9876543210fedcba9876543210")
	forged, err := Decide(profile, request, DecisionOptions{SigningSeed: attackerSeed})
	if err != nil {
		t.Fatalf("sign attacker decision: %v", err)
	}
	if ok, err := VerifyDecisionReceiptSignature(forged); err != nil || !ok {
		t.Fatalf("attacker receipt self-integrity = %v/%v, want true/nil", ok, err)
	}
	if ok, err := VerifyDecisionReceiptWithTrustedKey(forged, workstationTestPublicKey()); err != nil || ok {
		t.Fatalf("attacker receipt trusted verification = %v/%v, want false/nil", ok, err)
	}

	legacySeed := sha256.Sum256([]byte("helm-workstation-observe-only-agent-run-receipt-v1"))
	legacyKey := ed25519.NewKeyFromSeed(legacySeed[:]).Public().(ed25519.PublicKey)
	if got := ed25519SignerKeyID(legacyKey); got != retiredObserveOnlySignerKeyID {
		t.Fatalf("legacy signer key ID = %q, want %q", got, retiredObserveOnlySignerKeyID)
	}
	legacy, err := Decide(profile, request, DecisionOptions{SigningSeed: legacySeed[:]})
	if err != nil {
		t.Fatalf("sign legacy fixture decision: %v", err)
	}
	if ok, err := VerifyDecisionReceiptSignature(legacy); err != nil || !ok {
		t.Fatalf("legacy receipt self-integrity = %v/%v, want true/nil", ok, err)
	}
	if ok, err := VerifyDecisionReceiptWithTrustedKey(legacy, legacyKey); err != nil || ok {
		t.Fatalf("legacy receipt must remain untrusted = %v/%v, want false/nil", ok, err)
	}
}

func TestAgentRunReceiptTrustedKeyVerification(t *testing.T) {
	result, err := ImportArtifactDir(filepath.Join(repoRoot(t), "fixtures", "workstation", "allowed-observe"), workstationTestImportOptions())
	if err != nil {
		t.Fatalf("import fixture: %v", err)
	}
	if ok, err := VerifyReceiptWithTrustedKey(result.Receipt, workstationTestPublicKey()); err != nil || !ok {
		t.Fatalf("trusted receipt verification = %v/%v, want true/nil", ok, err)
	}
	wrong := ed25519.NewKeyFromSeed([]byte("fedcba9876543210fedcba9876543210")).Public().(ed25519.PublicKey)
	if ok, err := VerifyReceiptWithTrustedKey(result.Receipt, wrong); err != nil || ok {
		t.Fatalf("wrong trusted receipt key = %v/%v, want false/nil", ok, err)
	}

	legacySeed := sha256.Sum256([]byte("helm-workstation-observe-only-agent-run-receipt-v1"))
	legacyKey := ed25519.NewKeyFromSeed(legacySeed[:]).Public().(ed25519.PublicKey)
	legacyResult, err := ImportArtifactDir(filepath.Join(repoRoot(t), "fixtures", "workstation", "allowed-observe"), ImportOptions{SigningSeed: legacySeed[:]})
	if err != nil {
		t.Fatalf("import legacy fixture: %v", err)
	}
	if ok, err := VerifyReceiptSignature(legacyResult.Receipt); err != nil || !ok {
		t.Fatalf("legacy receipt self-integrity = %v/%v, want true/nil", ok, err)
	}
	if ok, err := VerifyReceiptWithTrustedKey(legacyResult.Receipt, legacyKey); err != nil || ok {
		t.Fatalf("legacy agent receipt must remain untrusted = %v/%v, want false/nil", ok, err)
	}
}
