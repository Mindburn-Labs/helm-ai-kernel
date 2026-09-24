package evidence

// quantum_posture: these tests exercise classical Ed25519 EvidencePack seal
// trust-root selection only; they do not assert post-quantum resistance.

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	proofanchor "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph/anchor"
)

func clearEvidenceTrustEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"HELM_EVIDENCE_TRUST_CONFIG",
		"HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX",
		"HELM_EVIDENCE_SIGNER_PUBLIC_KEY_HEX",
		"HELM_ALLOW_SELF_ATTESTED_EVIDENCE",
		"HELM_EVIDENCE_SIGNER",
	} {
		t.Setenv(key, "")
	}
}

// writeShippedPack reproduces the verifier PoC for audit 13-01 (VC ship2): an
// attacker seals a pack with their own file-dev key and ships it beside a
// helm/helm.yaml that names that key as trusted at the team profile. It
// returns the ship directory; the pack is at <ship>/pack.
func writeShippedPack(t *testing.T) string {
	t.Helper()
	attackerData := t.TempDir()
	shipDir := t.TempDir()
	packDir := filepath.Join(shipDir, "pack")
	if err := os.MkdirAll(filepath.Join(packDir, "07_ATTESTATIONS"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "01_SCORE.json"), []byte(`{"pass":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSealTestIndex(t, packDir, []string{"01_SCORE.json"})
	if _, err := SealEvidencePack(context.Background(), packDir, SealEvidencePackOptions{
		DataDir:  attackerData,
		SignedAt: fixedSealTime(),
	}); err != nil {
		t.Fatal(err)
	}
	signer, err := NewFileDevEvidenceSigner(attackerData)
	if err != nil {
		t.Fatal(err)
	}
	cfg := EvidencePackTrustConfig{
		ActiveProfile: EvidenceTrustProfileTeam,
		Signer:        EvidencePackTrustSigner{Type: "file-dev", KeyID: signer.KeyID(), PublicKey: signer.PublicKeyHex()},
		TrustedKeys:   map[string]string{signer.KeyID(): signer.PublicKeyHex()},
	}
	if _, err := SaveEvidencePackTrustConfigWithPath(filepath.Join(shipDir, "helm", "helm.yaml"), attackerData, cfg); err != nil {
		t.Fatal(err)
	}
	return shipDir
}

func TestLoadEvidencePackTrustConfigNeverReadsWorkingDirectory(t *testing.T) {
	clearEvidenceTrustEnv(t)
	shipDir := writeShippedPack(t)
	t.Chdir(shipDir)

	cfg, err := LoadEvidencePackTrustConfigWithPath("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Fatalf("trust config was loaded from the working directory: %+v", cfg)
	}
}

func TestVerifyEvidencePackSealIgnoresTrustConfigBesidePack(t *testing.T) {
	clearEvidenceTrustEnv(t)
	shipDir := writeShippedPack(t)
	victimData := t.TempDir()
	t.Setenv("HELM_DATA_DIR", victimData)
	t.Chdir(shipDir)

	result := VerifyEvidencePackSeal("pack", VerifyEvidencePackSealOptions{})
	if result.State != "unverifiable" || result.SignatureValid {
		t.Fatalf("pack verified against trust shipped beside it: state=%s sig=%v errs=%v", result.State, result.SignatureValid, result.Errors)
	}
	if result.TrustLevel != EvidenceTrustProfileDevLocal {
		t.Fatalf("trust level taken from the shipped config: %s", result.TrustLevel)
	}

	// The operator's own trust config (VC [4]) does not name the attacker key,
	// so it cannot be overridden by the file beside the pack.
	own, err := NewEvidencePackTrustConfig(EvidenceTrustProfileDevLocal, "file-dev", "local-dev", "local-dev", false, victimData)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveEvidencePackTrustConfig(victimData, own); err != nil {
		t.Fatal(err)
	}
	result = VerifyEvidencePackSeal("pack", VerifyEvidencePackSealOptions{})
	if result.State != "unverifiable" || result.SignatureValid {
		t.Fatalf("operator trust config was overridden: state=%s errs=%v", result.State, result.Errors)
	}

	// An explicitly named config is the operator's choice and still works.
	shipped := filepath.Join(shipDir, "helm", "helm.yaml")
	result = VerifyEvidencePackSeal("pack", VerifyEvidencePackSealOptions{ConfigPath: shipped})
	if result.State != "valid" || result.TrustLevel != EvidenceTrustProfileTeam {
		t.Fatalf("explicit --config no longer verifies: state=%s trust=%s errs=%v", result.State, result.TrustLevel, result.Errors)
	}
	t.Setenv("HELM_EVIDENCE_TRUST_CONFIG", shipped)
	result = VerifyEvidencePackSeal("pack", VerifyEvidencePackSealOptions{})
	if result.State != "valid" || result.TrustLevel != EvidenceTrustProfileTeam {
		t.Fatalf("HELM_EVIDENCE_TRUST_CONFIG no longer verifies: state=%s trust=%s errs=%v", result.State, result.TrustLevel, result.Errors)
	}
}

func TestVerifyEvidencePackSealTamperedPackIsInvalidNotUnverifiable(t *testing.T) {
	clearEvidenceTrustEnv(t)
	t.Setenv("HELM_DATA_DIR", t.TempDir())
	shipDir := writeShippedPack(t)
	packDir := filepath.Join(shipDir, "pack")
	if err := os.WriteFile(filepath.Join(packDir, "01_SCORE.json"), []byte(`{"pass":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result := VerifyEvidencePackSeal(packDir, VerifyEvidencePackSealOptions{})
	if result.State != "invalid" {
		t.Fatalf("tampered pack state=%s, want invalid; errs=%v", result.State, result.Errors)
	}
}

func TestVerifyEvidenceAnchorReceiptsRejectsUnboundRFC3161Token(t *testing.T) {
	// VC 19-01 PoC B: a DER INTEGER stands in for the TSA token.
	root := strings.Repeat("a", 64)
	token, err := asn1.Marshal(42)
	if err != nil {
		t.Fatal(err)
	}
	seal := EvidencePackSeal{
		MerkleRoot: root,
		AnchorReceipts: []proofanchor.AnchorReceipt{{
			Backend:        "rfc3161",
			Request:        proofanchor.AnchorRequest{MerkleRoot: root},
			LogID:          "https://tsa.invalid/",
			IntegratedTime: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			Signature:      base64.StdEncoding.EncodeToString(token),
		}},
	}
	status, errs := verifyEvidenceAnchorReceipts(context.Background(), seal, nil, EvidenceTrustProfileCustomer)
	if status == "verified-externally" || len(errs) == 0 {
		t.Fatalf("forged rfc3161 anchor accepted: status=%s errs=%v", status, errs)
	}

	seal.AnchorReceipts[0].Signature = base64.StdEncoding.EncodeToString(rfc3161TokenForRoot(t, strings.Repeat("b", 64)))
	status, errs = verifyEvidenceAnchorReceipts(context.Background(), seal, nil, EvidenceTrustProfileCustomer)
	if status == "verified-externally" || len(errs) == 0 {
		t.Fatalf("rfc3161 token for another root accepted: status=%s errs=%v", status, errs)
	}
}

// rfc3161TokenForRoot builds an unsigned RFC 3161 TimeStampToken whose TSTInfo
// imprint is the SHA-256 of the root bytes, which is what the backend submits.
func rfc3161TokenForRoot(t *testing.T, root string) []byte {
	t.Helper()
	type algorithm struct{ Algorithm asn1.ObjectIdentifier }
	type imprint struct {
		HashAlgorithm algorithm
		HashedMessage []byte
	}
	rootBytes, err := hex.DecodeString(root)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(rootBytes)
	sha256OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	info, err := asn1.Marshal(struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint imprint
		SerialNumber   int
		GenTime        time.Time `asn1:"generalized"`
	}{1, asn1.ObjectIdentifier{1, 2, 3, 4}, imprint{algorithm{sha256OID}, digest[:]}, 1, fixedSealTime()})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := asn1.Marshal(struct {
		Version          int
		DigestAlgorithms []algorithm `asn1:"set"`
		EncapContentInfo struct {
			EContentType asn1.ObjectIdentifier
			EContent     []byte `asn1:"explicit,tag:0"`
		}
	}{Version: 3, DigestAlgorithms: []algorithm{{sha256OID}}, EncapContentInfo: struct {
		EContentType asn1.ObjectIdentifier
		EContent     []byte `asn1:"explicit,tag:0"`
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}, info}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signed}})
	if err != nil {
		t.Fatal(err)
	}
	return token
}
