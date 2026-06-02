package canonicalize

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type extauthzVectorIndex struct {
	Vectors []struct {
		ID             string `json:"id"`
		Input          string `json:"input"`
		Canonical      string `json:"canonical"`
		SHA256         string `json:"sha256"`
		ExpectedStatus string `json:"expected_status"`
	} `json:"vectors"`
}

func TestExtauthzGoldenVectorsAreCanonical(t *testing.T) {
	root := filepath.Join("..", "..", "..", "reference_packs", "extauthz")
	indexBytes, err := os.ReadFile(filepath.Join(root, "vectors.json"))
	if err != nil {
		t.Fatalf("read vector index: %v", err)
	}
	var index extauthzVectorIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		t.Fatalf("parse vector index: %v", err)
	}
	for _, vector := range index.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			inputBytes, err := os.ReadFile(filepath.Join(root, vector.Input))
			if err != nil {
				t.Fatalf("read input: %v", err)
			}
			expectedCanonical, err := os.ReadFile(filepath.Join(root, vector.Canonical))
			if err != nil {
				t.Fatalf("read canonical: %v", err)
			}
			var value any
			decoder := json.NewDecoder(bytes.NewReader(inputBytes))
			decoder.UseNumber()
			if err := decoder.Decode(&value); err != nil {
				t.Fatalf("decode input: %v", err)
			}
			got, err := JCS(value)
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			expected := strings.TrimSuffix(string(expectedCanonical), "\n")
			if string(got) != expected {
				t.Fatalf("canonical mismatch:\n got: %s\nwant: %s", got, expected)
			}
			if hash := HashBytes(got); hash != vector.SHA256 {
				t.Fatalf("hash mismatch: got %s want %s", hash, vector.SHA256)
			}
		})
	}
}
