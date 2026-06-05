package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorDoesNotLeakRootKeySeed(t *testing.T) {
	dir := t.TempDir()
	seed := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(filepath.Join(dir, "root.key"), []byte(seed), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root.pub"), []byte("public-key-fixture"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HELM_DATA_DIR", dir)

	for _, args := range [][]string{{"--json"}, {"--verbose"}} {
		var stdout, stderr bytes.Buffer
		_ = runDoctorCmd(args, &stdout, &stderr)
		out := stdout.String()
		if strings.Contains(out, seed) || strings.Contains(out, seed[:12]) {
			t.Fatalf("doctor output leaked root key seed for args %v: %s", args, out)
		}
		if !strings.Contains(out, "public_key_hash") {
			t.Fatalf("doctor output should use public key hash detail for args %v: %s", args, out)
		}
	}
}
