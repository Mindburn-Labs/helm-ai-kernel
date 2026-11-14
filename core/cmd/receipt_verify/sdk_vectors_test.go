package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// These are exact signed documents from the frozen chain/reference pack and
// adversarial mutations. The public SDK APIs consume the same bytes and keys.
func TestSDKOfflineVerifierVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(sdkVectorRoot(), "core/pkg/receiptverify/testdata/offline-verifier-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			ID          string   `json:"id"`
			Receipt     string   `json:"receipt"`
			TrustedKeys []string `json:"trusted_keys"`
			Valid       bool     `json:"valid"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Vectors) == 0 {
		t.Fatal("empty SDK corpus")
	}
	for _, vector := range corpus.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			dir := t.TempDir()
			document := filepath.Join(dir, "receipt.json")
			if err := os.WriteFile(document, []byte(vector.Receipt), 0600); err != nil {
				t.Fatal(err)
			}
			stdout, err := os.Create(filepath.Join(dir, "stdout"))
			if err != nil {
				t.Fatal(err)
			}
			defer stdout.Close()
			stderr, err := os.Create(filepath.Join(dir, "stderr"))
			if err != nil {
				t.Fatal(err)
			}
			defer stderr.Close()
			args := []string{"--receipt", document, "--json"}
			for _, key := range vector.TrustedKeys {
				args = append(args, "--key", key)
			}
			code := run(args, stdout, stderr)
			if (code == 0) != vector.Valid {
				diagnostic, _ := os.ReadFile(stderr.Name())
				output, _ := os.ReadFile(stdout.Name())
				t.Fatalf("exit=%d, want valid=%v; stderr=%s stdout=%s", code, vector.Valid, diagnostic, output)
			}
		})
	}
}

func sdkVectorRoot() string {
	if root := os.Getenv("HELM_SDK_VECTOR_ROOT"); root != "" {
		return root
	}
	return "../../.."
}
