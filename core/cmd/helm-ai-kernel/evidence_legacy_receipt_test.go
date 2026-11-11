package main

// quantum_posture: these tests exercise classical Ed25519 receipt verification
// on the evidence route only; no post-quantum cryptographic control is added
// or claimed.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
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
