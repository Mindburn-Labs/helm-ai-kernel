package main

// quantum_posture: these tests exercise classical Ed25519 receipt verification
// on the evidence route only; no post-quantum cryptographic control is added
// or claimed.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

// replayReceiptV5AsLegacy re-splits the bytes a receipt.v5 signature covers
// into the eight colon-joined fields of the legacy preimage and returns an
// unversioned receipt that carries the same signature and claims ALLOW.
func replayReceiptV5AsLegacy(t *testing.T, signed *contracts.Receipt) *contracts.Receipt {
	t.Helper()
	payload, err := helmcrypto.CanonicalizeReceiptV5(signed)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(payload), ":")
	for i := 6; i < len(parts)-1; i++ {
		clock, err := strconv.ParseUint(parts[i], 10, 64)
		if err != nil || strconv.FormatUint(clock, 10) != parts[i] {
			continue
		}
		forged := &contracts.Receipt{
			ReceiptID:    parts[0],
			DecisionID:   parts[1],
			EffectID:     parts[2],
			Status:       parts[3],
			OutputHash:   parts[4],
			PrevHash:     strings.Join(parts[5:i], ":"),
			LamportClock: clock,
			ArgsHash:     strings.Join(parts[i+1:], ":"),
			Verdict:      "ALLOW",
			ToolName:     "payments.transfer",
			Timestamp:    signed.Timestamp,
			Signature:    signed.Signature,
			PublicKeySet: signed.PublicKeySet,
		}
		if !bytes.Equal(helmcrypto.ReceiptPreimageV4(forged), payload) {
			t.Fatal("the planted receipt is not a legacy reading of the signed receipt.v5 bytes; the case proves nothing")
		}
		return forged
	}
	t.Fatal("the signed receipt.v5 bytes hold no colon-delimited integer to stand in for lamport_clock; the case proves nothing")
	return nil
}

// TestEvidenceVerifyDoesNotCheckAnUnversionedReceipt is helm-tracker#305
// defect B on POST /api/v1/evidence/verify. A receipt with no
// signature_version is checked against eight colon-joined fields, so the
// signature of a receipt.v5 DENY the runtime really issued verifies for an
// unversioned receipt that says ALLOW. The route does not opt in to the legacy
// preimage: the receipt signature check reports such a receipt as not checked
// (UNVERIFIABLE), never VERIFIED, whether it is the replay or a receipt the
// runtime signed before receipt.v5.
func TestEvidenceVerifyDoesNotCheckAnUnversionedReceipt(t *testing.T) {
	trusted, err := helmcrypto.NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize), "runtime-signer")
	if err != nil {
		t.Fatal(err)
	}
	svc := &Services{ReceiptSigner: trusted}
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	denial := newEvidenceVerifyTestReceipt("deny-1", "helm-gateway:8:tenant-a:4:ws-a", 1, "")
	denial.Status, denial.Verdict, denial.ReasonCode = "DENIED", "DENY", "MANDATE_LIMIT_EXCEEDED"
	if err := trusted.SignReceipt(denial); err != nil {
		t.Fatal(err)
	}
	if err := verifyTrustedEvidenceReceipt(svc, denial); err != nil {
		t.Fatalf("the genuine receipt.v5 DENY does not verify under the runtime key; the case proves nothing: %v", err)
	}
	replayed := replayReceiptV5AsLegacy(t, denial)

	legacy := newEvidenceVerifyTestReceipt("legacy-1", "legacy-session", 1, "")
	legacy.PublicKeySet = map[string]string{helmcrypto.SigPrefixEd25519: trusted.PublicKey()}
	if legacy.Signature, err = trusted.Sign(helmcrypto.ReceiptPreimageV4(legacy)); err != nil {
		t.Fatal(err)
	}
	if _, valid, err := helmcrypto.VerifyReceiptProfile(trusted.PublicKey(), "", legacy, helmcrypto.AllowLegacyReceiptPreimages); err != nil || !valid {
		t.Fatalf("the planted legacy receipt is not validly signed over the legacy preimage; the case proves nothing (valid=%v err=%v)", valid, err)
	}

	for name, tc := range map[string]struct {
		receipt *contracts.Receipt
		// wantOutcome is empty when another check also has something to say:
		// the replay's prev_hash is not a genesis value.
		wantOutcome string
	}{
		"a receipt.v5 signature replayed as an unversioned ALLOW": {replayed, ""},
		"a receipt the runtime signed before receipt.v5":          {legacy, "UNVERIFIABLE"},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.receipt.SignatureVersion != "" {
				t.Fatal("the planted receipt declares a signature_version; the case proves nothing")
			}
			if err := verifyTrustedEvidenceReceipt(svc, tc.receipt); !errors.Is(err, helmcrypto.ErrLegacyReceiptRefused) {
				t.Fatalf("verifyTrustedEvidenceReceipt = %v, want the legacy refusal", err)
			}
			if receiptVerifiesUnderCarriedKey(tc.receipt) {
				t.Fatal("an unversioned receipt verified under the key it carries; the carried-key path opted in to the legacy preimage")
			}

			// Sealed by the runtime key, so the seal verifies and only the
			// receipt signature check stands between this bundle and VERIFIED.
			bundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts(tc.receipt.SessionID, []*contracts.Receipt{tc.receipt}, nil, svc)
			if err != nil {
				t.Fatal(err)
			}
			result := postEvidenceVerification(t, mux, "/api/v1/evidence/verify", bundle)
			statuses := evidenceCheckStatuses(t, result)
			if statuses["bundle_seal"] != "VERIFIED" {
				t.Fatalf("runtime-sealed bundle seal = %s: %+v", statuses["bundle_seal"], result)
			}
			if statuses["receipt_signatures"] != "UNVERIFIABLE" {
				t.Fatalf("receipt_signatures = %s for an unversioned receipt, want UNVERIFIABLE (not checked): %+v", statuses["receipt_signatures"], result)
			}
			if result["outcome"] == "VERIFIED" || (tc.wantOutcome != "" && result["outcome"] != tc.wantOutcome) {
				t.Fatalf("outcome = %v, want %q and never VERIFIED: %+v", result["outcome"], tc.wantOutcome, result)
			}
			if !resultErrorsContain(result, tc.receipt.ReceiptID+" not checked") || !resultErrorsContain(result, "legacy") ||
				!resultErrorsContain(result, "signature_version") {
				t.Fatalf("the response must say the receipt was not checked and why: %+v", result)
			}
		})
	}
}

// TestEvidenceVerifyUnderAKeyRingReportsALegacyReceiptAsNotChecked: a runtime
// whose trust anchor is a KeyRing (rotated keys) answered an unversioned
// receipt with "no key verified the receipt", which this route reports as
// FAILED: "signature verification failed". No signature had been checked. The
// keyring now returns the legacy refusal, and the route reports the receipt
// as not checked, as it does under a single key.
func TestEvidenceVerifyUnderAKeyRingReportsALegacyReceiptAsNotChecked(t *testing.T) {
	trusted, err := helmcrypto.NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize), "runtime-signer")
	if err != nil {
		t.Fatal(err)
	}
	ring := helmcrypto.NewKeyRing()
	ring.AddKey(trusted)
	svc := &Services{ReceiptSigner: ring}

	legacy := newEvidenceVerifyTestReceipt("legacy-1", "legacy-session", 1, "")
	if legacy.Signature, err = trusted.Sign(helmcrypto.ReceiptPreimageV4(legacy)); err != nil {
		t.Fatal(err)
	}
	if _, valid, err := helmcrypto.VerifyReceiptProfile(trusted.PublicKey(), "", legacy, helmcrypto.AllowLegacyReceiptPreimages); err != nil || !valid {
		t.Fatalf("the planted legacy receipt is not validly signed; the case proves nothing (valid=%v err=%v)", valid, err)
	}
	if err := verifyTrustedEvidenceReceipt(svc, legacy); !errors.Is(err, helmcrypto.ErrLegacyReceiptRefused) {
		t.Fatalf("verifyTrustedEvidenceReceipt under a KeyRing = %v, want the legacy refusal", err)
	}
	result := evidenceVerification{}
	checkEvidenceReceiptSignatures(&result, []*contracts.Receipt{legacy}, svc)
	if len(result.ChecksRun) != 1 || result.ChecksRun[0].Status != "UNVERIFIABLE" {
		t.Fatalf("receipt_signatures under a KeyRing = %+v for an unversioned receipt, want UNVERIFIABLE (not checked)", result.ChecksRun)
	}
	if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "legacy-1 not checked") || strings.Contains(result.Errors[0], "verification failed") {
		t.Fatalf("the route must say the receipt was not checked, not that its signature failed: %v", result.Errors)
	}

	// A receipt.v5 receipt is still checked through the keyring, both ways.
	current := newEvidenceVerifyTestReceipt("v5-1", "session", 1, "")
	if err := trusted.SignReceipt(current); err != nil {
		t.Fatal(err)
	}
	result = evidenceVerification{}
	checkEvidenceReceiptSignatures(&result, []*contracts.Receipt{current}, svc)
	if len(result.ChecksRun) != 1 || result.ChecksRun[0].Status != "VERIFIED" {
		t.Fatalf("a receipt.v5 receipt under a KeyRing = %+v, want VERIFIED", result.ChecksRun)
	}
	current.Status = "TAMPERED"
	result = evidenceVerification{}
	checkEvidenceReceiptSignatures(&result, []*contracts.Receipt{current}, svc)
	if len(result.ChecksRun) != 1 || result.ChecksRun[0].Status != "FAILED" {
		t.Fatalf("a tampered receipt.v5 receipt under a KeyRing = %+v, want FAILED", result.ChecksRun)
	}
}

// sealedEvidenceBundleOfFiles builds a runtime-sealed evidence bundle whose
// receipt files hold exactly the bytes given, with a manifest that hashes
// them, so a test can plant a receipt file json.Marshal would never write.
func sealedEvidenceBundleOfFiles(t *testing.T, svc *Services, sessionID string, receiptFiles map[string][]byte, signedAt []*contracts.Receipt) []byte {
	t.Helper()
	files := map[string][]byte{}
	hashes := map[string]string{}
	for name, data := range receiptFiles {
		files[name] = data
		sum := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	manifest, err := json.Marshal(evidenceManifest{Version: "1.0", ExportedAt: "1970-01-01T00:00:00Z", SessionID: sessionID, FileHashes: hashes})
	if err != nil {
		t.Fatal(err)
	}
	files["manifest.json"] = manifest
	sealSigner, trustConfig, err := trustedEvidenceBundleSealSigner(svc)
	if err != nil {
		t.Fatal(err)
	}
	packDir := t.TempDir()
	if err := writeEvidenceBundlePackFiles(packDir, files); err != nil {
		t.Fatal(err)
	}
	if err := writeEvidenceBundleIndex(packDir, files); err != nil {
		t.Fatal(err)
	}
	if _, err := evidencepkg.SealEvidencePack(context.Background(), packDir, evidencepkg.SealEvidencePackOptions{
		PackID:      evidenceBundlePackID(sessionID, files),
		Profile:     evidencepkg.EvidenceTrustProfileDevLocal,
		Signer:      sealSigner,
		TrustConfig: trustConfig,
		SignedAt:    evidenceBundleSignedAt(signedAt),
	}); err != nil {
		t.Fatal(err)
	}
	for _, controlPath := range []string{evidenceBundleIndexPath, evidencepkg.EvidencePackSealPath} {
		data, err := os.ReadFile(filepath.Join(packDir, filepath.FromSlash(controlPath)))
		if err != nil {
			t.Fatal(err)
		}
		files[controlPath] = data
	}
	bundle, err := tarEvidenceBundleFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

// TestEvidenceVerifyReadsAReceiptFileAsItsReaderDoes: the route decoded each
// receipt file with encoding/json alone. A file that says verdict ALLOW by
// exact name and restores the signed DENY in "Verdict", or that writes
// "verdict" twice, then had its signature VERIFIED while every reader of the
// bundle that matches names exactly read ALLOW from it. The bundle seal does
// not help: whoever holds the bundle seals it. Every receipt file now goes
// through the parser receipt_verify uses.
func TestEvidenceVerifyReadsAReceiptFileAsItsReaderDoes(t *testing.T) {
	trusted, err := helmcrypto.NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize), "runtime-signer")
	if err != nil {
		t.Fatal(err)
	}
	svc := &Services{ReceiptSigner: trusted}
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	denial := newEvidenceVerifyTestReceipt("deny-1", "sess-a", 1, "")
	denial.Status, denial.Verdict, denial.ReasonCode = "DENIED", "DENY", "MANDATE_LIMIT_EXCEEDED"
	if err := trusted.SignReceipt(denial); err != nil {
		t.Fatal(err)
	}
	genuine, err := json.Marshal(denial)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(genuine, []byte(`"verdict":"DENY"`)) != 1 {
		t.Fatalf("the genuine receipt does not carry its verdict once: %s", genuine)
	}
	shadow := append([]byte(`{"verdict":"ALLOW",`), bytes.Replace(genuine, []byte(`"verdict":"DENY"`), []byte(`"Verdict":"DENY"`), 1)[1:]...)
	duplicate := append([]byte(`{"verdict":"ALLOW",`), genuine[1:]...)
	variantVersion := bytes.Replace(genuine, []byte(`"signature_version":`), []byte(`"Signature_Version":`), 1)
	for name, data := range map[string][]byte{"shadow": shadow} {
		var exact map[string]any
		if err := json.Unmarshal(data, &exact); err != nil {
			t.Fatal(err)
		}
		var folded contracts.Receipt
		if err := json.Unmarshal(data, &folded); err != nil {
			t.Fatal(err)
		}
		if exact["verdict"] != "ALLOW" || folded.Verdict != "DENY" {
			t.Fatalf("%s: the planted file does not read ALLOW by exact name over the signed DENY; the case proves nothing", name)
		}
	}

	verify := func(data []byte) map[string]any {
		bundle := sealedEvidenceBundleOfFiles(t, svc, "sess-a", map[string][]byte{"receipts/deny-1.json": data}, []*contracts.Receipt{denial})
		return postEvidenceVerification(t, mux, "/api/v1/evidence/verify", bundle)
	}
	// The harness builds a bundle the route verifies when nothing is planted.
	if result := verify(genuine); result["outcome"] != "VERIFIED" || evidenceCheckStatuses(t, result)["receipt_signatures"] != "VERIFIED" {
		t.Fatalf("the genuine receipt in a runtime-sealed bundle is not VERIFIED; the cases prove nothing: %+v", result)
	}

	for name, tc := range map[string]struct {
		data []byte
		want string
	}{
		"letter-case shadow":                       {shadow, "letter case"},
		"verdict written twice":                    {duplicate, `duplicate object member "verdict"`},
		"signature_version in another letter case": {variantVersion, "letter case"},
	} {
		t.Run(name, func(t *testing.T) {
			result := verify(tc.data)
			statuses := evidenceCheckStatuses(t, result)
			if statuses["receipt_signatures"] == "VERIFIED" || result["outcome"] == "VERIFIED" {
				t.Fatalf("a receipt file its reader reads differently was VERIFIED: %+v", result)
			}
			if result["outcome"] != "FAILED" || statuses["bundle_format"] != "FAILED" {
				t.Fatalf("outcome = %v, bundle_format = %s; want the bundle refused as unreadable: %+v", result["outcome"], statuses["bundle_format"], result)
			}
			if !resultErrorsContain(result, "receipts/deny-1.json") || !resultErrorsContain(result, tc.want) {
				t.Fatalf("the refusal must name the file and the reason (%s): %+v", tc.want, result["errors"])
			}
		})
	}
}
