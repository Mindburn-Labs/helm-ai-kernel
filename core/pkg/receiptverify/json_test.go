// quantum_posture: the shared corpus tests classical Ed25519 verification only.
package receiptverify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type jsonCorpus struct {
	Documents  map[string]string `json:"documents"`
	TrustRoots map[string]string `json:"trust_roots"`
	Cases      []struct {
		Name      string  `json:"name"`
		Document  string  `json:"document"`
		TrustRoot string  `json:"trust_root"`
		Expected  Verdict `json:"expected"`
	} `json:"cases"`
}

func TestVerifyJSONFrozenCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "wasm-json-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus jsonCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) < 30 {
		t.Fatal("required native/WASM security corpus is missing")
	}
	for _, c := range corpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			document, ok := corpus.Documents[c.Document]
			if !ok {
				t.Fatal("missing document", c.Document)
			}
			root, ok := corpus.TrustRoots[c.TrustRoot]
			if !ok {
				t.Fatal("missing explicit trust input", c.TrustRoot)
			}
			got := VerifyJSON([]byte(document), []byte(root))
			if got.SchemaVersion != DocumentSchemaVersion || got.Verdict != c.Expected {
				t.Fatalf("got %+v, want %s", got, c.Expected)
			}
			if got.Verification.Valid != (got.Verdict == VerdictVerified) {
				t.Fatalf("verdict and verifier disagree: %+v", got)
			}
		})
	}
}

func TestVerifyJSONInputBounds(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("testdata", "frozen-chain-2026.json"))
	if err != nil {
		t.Fatal(err)
	}
	var frozen struct {
		KeyID        string `json:"key_id"`
		PublicKeyHex string `json:"public_key_hex"`
	}
	if err := json.Unmarshal(document, &frozen); err != nil {
		t.Fatal(err)
	}
	trust, err := json.Marshal(map[string]any{"keys": map[string]string{frozen.KeyID: frozen.PublicKeyHex}})
	if err != nil {
		t.Fatal(err)
	}
	if got := VerifyJSON(document, trust); got.Verdict != VerdictVerified {
		t.Fatalf("size controls require a valid positive input: %+v", got)
	}
	oversizedDoc := append(append([]byte(nil), document...), bytes.Repeat([]byte(" "), MaxDocumentBytes-len(document)+1)...)
	oversizedTrust := append(append([]byte(nil), trust...), bytes.Repeat([]byte(" "), MaxTrustRootBytes-len(trust)+1)...)
	for _, c := range []struct {
		name            string
		document, trust []byte
	}{
		{"document-size", oversizedDoc, trust},
		{"document-encoding", []byte{0xff}, nil},
		{"trust-size", document, oversizedTrust},
		{"trust-encoding", document, []byte{0xff}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := VerifyJSON(c.document, c.trust)
			if got.Verdict != VerdictFailed || got.Verification.Valid || len(got.Verification.Errors) == 0 {
				t.Fatalf("invalid input did not fail closed: %+v", got)
			}
		})
	}
}

func TestVerifyJSONTrustedKeyLimit(t *testing.T) {
	keys := make(map[string]string)
	for i := 0; i < 129; i++ {
		keys[fmt.Sprint(i)] = strings.Repeat("00", 32)
	}
	root, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	got := VerifyJSON([]byte(`{"receipts":[]}`), root)
	if got.Verdict != VerdictFailed || len(got.Verification.Errors) != 1 ||
		!strings.Contains(got.Verification.Errors[0], "128-key limit") {
		t.Fatalf("oversized trust input was not refused: %+v", got)
	}
}
