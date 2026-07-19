// quantum_posture: these signer tests cover classical Ed25519 receipt keys
// only and do not claim post-quantum protection.
package workstation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
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

func TestMAMAFixtureDecisionReceiptRequiresFixtureTrustAnchor(t *testing.T) {
	fixtureDir := filepath.Join(repoRoot(t), "fixtures", "workstation", "mama-receipt-bound-execution")
	mama, err := ImportArtifactDir(fixtureDir, workstationTestImportOptions())
	if err != nil {
		t.Fatalf("import MAMA fixture: %v", err)
	}
	decision, err := loadReferencedDecisionReceipt(fixtureDir, mama.Receipt, "evt_mama_deploy_publish", mamaFixtureDecisionSigner)
	if err != nil {
		t.Fatalf("verify MAMA fixture trust anchor: %v", err)
	}
	if got := decision.SignerKeyID; got == retiredObserveOnlySignerKeyID {
		t.Fatalf("MAMA fixture still uses retired signer %q", got)
	}

	forged := *decision
	if err := signDecisionReceipt(&forged, []byte("fedcba9876543210fedcba9876543210")); err != nil {
		t.Fatalf("sign forged MAMA receipt: %v", err)
	}
	forgedDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(forgedDir, "receipts"), 0o755); err != nil {
		t.Fatalf("make forged receipt directory: %v", err)
	}
	data, err := json.Marshal(&forged)
	if err != nil {
		t.Fatalf("marshal forged MAMA receipt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(forgedDir, "receipts", forged.DecisionID+".json"), data, 0o600); err != nil {
		t.Fatalf("write forged MAMA receipt: %v", err)
	}
	if _, err := loadReferencedDecisionReceipt(forgedDir, mama.Receipt, "evt_mama_deploy_publish", mamaFixtureDecisionSigner); err == nil {
		t.Fatal("expected untrusted MAMA receipt signer to be rejected")
	}
}
