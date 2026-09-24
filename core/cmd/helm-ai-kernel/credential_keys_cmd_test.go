package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kms"
)

func runCredentialKeys(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(append([]string{"helm-ai-kernel", "credential-keys"}, args...), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// The operator path for §10.3 rotation: rotate, verify old, verify new, revoke.
func TestCredentialKeysRotateAndRevoke(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", "")

	if code, _, stderr := runCredentialKeys(t, "status", "--data-dir", dataDir); code != 1 || !strings.Contains(stderr, "no keystore") {
		t.Fatalf("status without a keystore: code=%d stderr=%q", code, stderr)
	}

	server, err := openCredentialKeystore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	binding := kms.Binding{Tenant: "operator", Connection: "openai/access_token"}
	ctOld, err := server.Encrypt("sk-old", binding)
	if err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runCredentialKeys(t, "rotate", "--data-dir", dataDir)
	if code != 0 || !strings.Contains(stdout, "rotated: v2 is active") || !strings.Contains(stdout, "usable: v1 v2") {
		t.Fatalf("rotate: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	// The next server start sees the rotation.
	server, err = openCredentialKeystore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := server.Decrypt(ctOld, binding); err != nil || got != "sk-old" {
		t.Fatalf("old ciphertext after rotate: %q, %v", got, err)
	}
	ctNew, err := server.Encrypt("sk-new", binding)
	if err != nil || !strings.HasPrefix(ctNew, "aad1:v2:") {
		t.Fatalf("new ciphertext %q, %v", ctNew, err)
	}

	if code, _, stderr := runCredentialKeys(t, "revoke", "2", "--data-dir", dataDir); code != 1 || !strings.Contains(stderr, "active") {
		t.Fatalf("revoking the active version: code=%d stderr=%q", code, stderr)
	}
	code, stdout, stderr = runCredentialKeys(t, "revoke", "--data-dir", dataDir, "1")
	if code != 0 || !strings.Contains(stdout, "revoked: v1") || !strings.Contains(stdout, "usable: v2\n") {
		t.Fatalf("revoke: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	server, err = openCredentialKeystore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Decrypt(ctOld, binding); err == nil {
		t.Fatal("a revoked version still decrypts")
	}
	if got, err := server.Decrypt(ctNew, binding); err != nil || got != "sk-new" {
		t.Fatalf("new ciphertext after revoke: %q, %v", got, err)
	}
}

func TestCredentialKeysRejectsBadArguments(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"unknown"},
		{"rotate", "extra"},
		{"revoke"},
		{"revoke", "one"},
	} {
		dataDir := t.TempDir()
		if _, err := kms.NewLocalKMS(kmsKeystorePath(dataDir)); err != nil {
			t.Fatal(err)
		}
		if code, _, _ := runCredentialKeys(t, append(args, "--data-dir", dataDir)...); code != 2 {
			t.Fatalf("args %v: code=%d, want 2", args, code)
		}
	}
}
