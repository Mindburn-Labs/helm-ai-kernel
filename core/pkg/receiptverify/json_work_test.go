// quantum_posture: resource limits do not alter classical verifier semantics.
package receiptverify

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func workFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join("testdata", "frozen-chain-2026.json"))
	if err != nil {
		t.Fatal(err)
	}
	var frozen struct {
		KeyID        string `json:"key_id"`
		PublicKeyHex string `json:"public_key_hex"`
	}
	if err := json.Unmarshal(doc, &frozen); err != nil {
		t.Fatal(err)
	}
	root, err := json.Marshal(map[string]any{"keys": map[string]string{frozen.KeyID: frozen.PublicKeyHex}})
	if err != nil {
		t.Fatal(err)
	}
	return doc, root
}

func withPadding(doc []byte, value string) []byte {
	doc = bytes.TrimSpace(doc)
	return []byte(string(doc[:len(doc)-1]) + `,"padding":` + value + `}`)
}

func TestVerifyJSONWorkLimitsAndReuse(t *testing.T) {
	doc, root := workFixture(t)
	deep := strings.Repeat("[", 50000) + "0" + strings.Repeat("]", 50000)
	for _, c := range []struct {
		name      string
		doc, root []byte
		reason    string
	}{
		{"deep-document", withPadding(doc, deep), root, "nesting limit"},
		{"deep-trust", doc, withPadding(root, strings.Repeat("[", 1000)+"0"+strings.Repeat("]", 1000)), "nesting limit"},
		{"long-key", withPadding(doc, `{"`+strings.Repeat("k", MaxJSONKeyBytes+1)+`":0}`), root, "member name"},
		{"long-string", withPadding(doc, `"`+strings.Repeat("x", MaxJSONTokenBytes+1)+`"`), root, "token limit"},
		{"long-number", withPadding(doc, strings.Repeat("1", MaxJSONTokenBytes+1)), root, "token limit"},
		{"wide-document", withPadding(doc, `[`+strings.Repeat("0,", MaxJSONTokens)+`0]`), root, "work limit"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := VerifyJSON(c.doc, c.root)
			if got.Verdict != VerdictFailed || len(got.Verification.Errors) != 1 || !strings.Contains(got.Verification.Errors[0], c.reason) {
				t.Fatalf("resource input did not hit its bounded refusal: %+v", got)
			}
			if next := VerifyJSON(doc, root); next.Verdict != VerdictVerified {
				t.Fatalf("verifier not reusable after refusal: %+v", next)
			}
		})
	}
}

func TestAdapterLimitsDoNotChangeCLIParser(t *testing.T) {
	doc, root := workFixture(t)
	padded := withPadding(doc, strings.Repeat("[", 100)+"0"+strings.Repeat("]", 100))
	if got := VerifyJSON(padded, root); got.Verdict != VerdictFailed {
		t.Fatal("adapter should enforce its depth budget")
	}
	bundle, err := ParseBundle(padded)
	if err != nil {
		t.Fatal("legacy CLI parser changed:", err)
	}
	var trust struct {
		Keys map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(root, &trust); err != nil {
		t.Fatal(err)
	}
	if got := VerifyBundle(bundle, TrustRoot{Keys: trust.Keys}); !got.Valid {
		t.Fatalf("legacy receipt semantics changed: %+v", got)
	}
}
