package main

// quantum_posture: tests the published receipt keyring for classical Ed25519
// and hybrid Ed25519 + ML-DSA-65 signers; no new algorithm is exercised.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// receiptKeyringVectorSeed is the fixed test key: the Ed25519 seed 0x00..0x1f.
func receiptKeyringVectorSeed() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

// receiptKeyringVectorBody is the exact response for the fixed key under the
// Kernel's key id "root". The Control Plane's HELM_KERNEL_RECEIPT_KEYRING
// parser test uses the same bytes.
const receiptKeyringVectorBody = `{"keyring_version":"kernel-evaluate-receipt-keyring.v1","keys":[{"key_id":"root","profile":"classical","ed25519_public_key_hex":"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"}]}`

func getReceiptKeyring(t *testing.T, signer helmcrypto.Signer, method string) *httptest.ResponseRecorder {
	t.Helper()
	mux := newRuntimeRouteMux()
	var svc *Services
	if signer != nil {
		svc = &Services{ReceiptSigner: signer}
	}
	registerReceiptKeyringRoute(mux, svc)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, receiptKeyringPath, nil))
	return rec
}

func TestReceiptKeyringRouteServesTheExactVector(t *testing.T) {
	seed := receiptKeyringVectorSeed()
	signer := helmcrypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(seed), "root")

	rec := getReceiptKeyring(t, signer, http.MethodGet)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != receiptKeyringVectorBody {
		t.Fatalf("body drifted from the Control Plane vector:\n got %s\nwant %s", got, receiptKeyringVectorBody)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	private := ed25519.NewKeyFromSeed(seed)
	for name, secret := range map[string]string{"seed": hex.EncodeToString(seed), "private key": hex.EncodeToString(private)} {
		if strings.Contains(strings.ToLower(rec.Body.String()), secret) {
			t.Fatalf("keyring leaks the %s", name)
		}
	}
}

// TestReceiptKeyringMatchesTheIdentityStampedOnReceipts decodes the route the
// way the Control Plane does (one JSON value, unknown fields refused) and
// checks each profile against what SignReceipt writes on a real receipt.
func TestReceiptKeyringMatchesTheIdentityStampedOnReceipts(t *testing.T) {
	ed := helmcrypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(receiptKeyringVectorSeed()), "root")
	mldsa, err := helmcrypto.NewMLDSASigner("root")
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := helmcrypto.NewHybridSignerFromSigners(ed, mldsa, "root")
	if err != nil {
		t.Fatal(err)
	}
	for name, signer := range map[string]helmcrypto.Signer{"classical": ed, "hybrid": hybrid, "pqc": mldsa} {
		t.Run(name, func(t *testing.T) {
			rec := getReceiptKeyring(t, signer, http.MethodGet)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			decoder := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
			decoder.DisallowUnknownFields()
			var keyring receiptKeyring
			if err := decoder.Decode(&keyring); err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			if decoder.More() {
				t.Fatal("more than one JSON value")
			}
			if keyring.KeyringVersion != receiptKeyringVersion || len(keyring.Keys) != 1 {
				t.Fatalf("keyring = %+v", keyring)
			}

			receipt := &contracts.Receipt{ReceiptID: "keyring-probe", DecisionID: "d", EffectID: "e", Status: "ALLOW"}
			if err := signer.SignReceipt(receipt); err != nil {
				t.Fatal(err)
			}
			got := keyring.Keys[0]
			if got.KeyID != receipt.KeyID || got.Profile != receipt.SignatureProfile || got.Profile != name {
				t.Fatalf("identity %+v, receipt stamps key %q profile %q", got, receipt.KeyID, receipt.SignatureProfile)
			}
			published := map[string]string{}
			if got.Ed25519PublicKeyHex != "" {
				published[helmcrypto.SigPrefixEd25519] = got.Ed25519PublicKeyHex
			}
			if got.MLDSA65PublicKeyHex != "" {
				published[helmcrypto.SigPrefixMLDSA65] = got.MLDSA65PublicKeyHex
			}
			if len(published) != len(receipt.PublicKeySet) {
				t.Fatalf("published %v, receipt carries %v", published, receipt.PublicKeySet)
			}
			for algorithm, key := range receipt.PublicKeySet {
				if published[algorithm] != key || key != strings.ToLower(key) {
					t.Fatalf("%s: published %q, receipt carries %q", algorithm, published[algorithm], key)
				}
			}
			if _, valid, err := helmcrypto.VerifyReceiptRequiredProfile(got.Ed25519PublicKeyHex, got.MLDSA65PublicKeyHex, receipt, got.Profile); err != nil || !valid {
				t.Fatalf("the published keys do not verify a receipt this signer made: valid=%v err=%v", valid, err)
			}
		})
	}
}

func TestReceiptKeyringRouteRefusesWithoutASigner(t *testing.T) {
	rec := getReceiptKeyring(t, nil, http.MethodGet)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `"keys"`) {
		t.Fatalf("an unconfigured kernel served a keyring: %s", rec.Body.String())
	}
}

func TestReceiptKeyringRouteIsReadOnly(t *testing.T) {
	signer := helmcrypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(receiptKeyringVectorSeed()), "root")
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if rec := getReceiptKeyring(t, signer, method); rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s answered %d, want 405", method, rec.Code)
		}
	}
}
