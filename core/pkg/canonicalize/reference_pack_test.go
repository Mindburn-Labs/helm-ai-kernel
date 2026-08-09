package canonicalize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestCanonicalJSONReferencePackMatchesGoImplementation runs
// reference_packs/canonical-json-v1/vectors.json against this package. The same
// file is verified independently by reference_packs/canonical-json-v1/verify_vectors.py,
// which reimplements the rule in pure-stdlib Python without calling json.dumps.
// Both are wired into `make verify-canonical-json-vectors`, so the Go
// implementation and a from-the-spec implementation are held to identical
// bytes in CI.
func TestCanonicalJSONReferencePackMatchesGoImplementation(t *testing.T) {
	path := filepath.Join("..", "..", "..", "reference_packs", "canonical-json-v1", "vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read reference pack: %v", err)
	}

	var pack struct {
		SchemaVersion string `json:"schema_version"`
		Spec          string `json:"spec"`
		Vectors       []struct {
			ID            string `json:"id"`
			Description   string `json:"description"`
			Input         string `json:"input"`
			Canonical     string `json:"canonical"`
			SHA256        string `json:"sha256"`
			Interoperable bool   `json:"interoperable"`
			RFC8785       string `json:"rfc8785_canonical"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatalf("parse reference pack: %v", err)
	}
	if pack.SchemaVersion != "helm.canonical-json/v1" {
		t.Fatalf("unexpected schema version %q", pack.SchemaVersion)
	}
	if len(pack.Vectors) == 0 {
		t.Fatal("reference pack has no vectors")
	}

	for _, vector := range pack.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			var generic interface{}
			decoder := json.NewDecoder(bytes.NewReader([]byte(vector.Input)))
			decoder.UseNumber()
			if err := decoder.Decode(&generic); err != nil {
				t.Fatalf("decode input: %v", err)
			}

			got, err := JCS(generic)
			if err != nil {
				t.Fatalf("JCS: %v", err)
			}
			if string(got) != vector.Canonical {
				t.Fatalf("canonical bytes differ\n got: %q\nwant: %q", got, vector.Canonical)
			}

			sum := sha256.Sum256(got)
			if hex.EncodeToString(sum[:]) != vector.SHA256 {
				t.Fatalf("sha256 %s != %s", hex.EncodeToString(sum[:]), vector.SHA256)
			}

			err = CheckInteroperableNumbers(generic)
			if vector.Interoperable != (err == nil) {
				t.Fatalf("interoperable=%v, vector says %v (err=%v)", err == nil, vector.Interoperable, err)
			}
			if !vector.Interoperable {
				if vector.RFC8785 == "" {
					t.Fatal("a deviation vector must publish rfc8785_canonical so the deviation is never silent")
				}
				// InteroperableJCS is the gate P2-3 and P2-6 mint vectors
				// through: it must refuse to produce bytes a conformant
				// implementation would not reproduce.
				if _, err := InteroperableJCS(generic); err == nil {
					t.Fatal("InteroperableJCS must refuse a deviation vector")
				}
			} else if vector.RFC8785 != "" {
				t.Fatalf("vector claims interoperability but also publishes a differing RFC 8785 rendering %q", vector.RFC8785)
			}
		})
	}
}
