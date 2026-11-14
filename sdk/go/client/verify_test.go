// quantum_posture: regression checks for classical Ed25519 receipt verification only.
package client

import (
	"encoding/json"
	"os"
	"testing"
)

// The vectors receipt_verify is held to by
// core/cmd/receipt_verify/sdk_vectors_test.go.
const vectorsPath = "../../../core/pkg/receiptverify/testdata/offline-verifier-vectors.json"

type sharedVector struct {
	ID          string   `json:"id"`
	Receipt     string   `json:"receipt"`
	TrustedKeys []string `json:"trusted_keys"`
	Valid       bool     `json:"valid"`
	Verdict     string   `json:"verdict"`
	ReceiptID   string   `json:"receipt_id"`
	Error       string   `json:"error"`
}

func loadVectors(t *testing.T) []sharedVector {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read shared vectors: %v", err)
	}
	var file struct {
		Vectors []sharedVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode shared vectors: %v", err)
	}
	if len(file.Vectors) < 20 {
		t.Fatalf("only %d shared vectors", len(file.Vectors))
	}
	return file.Vectors
}

func TestVerifyReceiptAgreesWithSharedVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.ID, func(t *testing.T) {
			got := VerifyReceipt([]byte(v.Receipt), v.TrustedKeys...)
			if got.Valid != v.Valid {
				t.Fatalf("valid = %v, want %v (%s: %s)", got.Valid, v.Valid, got.Error, got.Detail)
			}
			if v.Valid {
				if got.Verdict != v.Verdict || got.ReceiptID != v.ReceiptID || got.Error != "" {
					t.Fatalf("verified receipt reads %q/%q (%q), want %q/%q", got.ReceiptID, got.Verdict, got.Error, v.ReceiptID, v.Verdict)
				}
				return
			}
			if got.Error != v.Error || got.Signed != nil {
				t.Fatalf("error = %q (%s), want %q with no signed members", got.Error, got.Detail, v.Error)
			}
		})
	}
}

func TestVerifyReceiptRefusesBadKeys(t *testing.T) {
	v := loadVectors(t)[0]
	if got := VerifyReceipt([]byte(v.Receipt)); got.Error != "no_trusted_key" {
		t.Fatalf("no key: %q", got.Error)
	}
	if got := VerifyReceipt([]byte(v.Receipt), "not-hex"); got.Error != "bad_key" {
		t.Fatalf("bad key: %q", got.Error)
	}
	if got := VerifyReceipt([]byte(v.Receipt), "ed25519:"+v.TrustedKeys[0]); !got.Valid {
		t.Fatalf("prefixed key: %q %s", got.Error, got.Detail)
	}
}

func TestReceiptSigningPayloadMatchesReferencePack(t *testing.T) {
	for _, name := range []string{"decision_deny_genesis", "executor_success_empty_governance", "escaped_string_members"} {
		receipt, err := os.ReadFile("../../../reference_packs/receipt-v5/" + name + ".receipt.c14n.json")
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile("../../../reference_packs/receipt-v5/" + name + ".signing_payload.c14n.json")
		if err != nil {
			t.Fatal(err)
		}
		signed, _, _, err := parseReceiptV5(receipt)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := string(receiptSigningPayload(signed)); got+"\n" != string(want) && got != string(want) {
			t.Fatalf("%s payload\n got %s\nwant %s", name, got, want)
		}
	}
}
