package runtime

// quantum_posture: writes fixed classical Ed25519 test seeds and checks the
// public half serve signs receipts under; no post-quantum claim.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testReceiptSeed is the seed receiptKeyEnv writes; its key id is
// testReceiptKeyID.
var testReceiptSeed = bytes.Repeat([]byte{0x7e}, ed25519.SeedSize)

const testReceiptKeyID = "helm-gateway:test"

func writeKeyFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// receiptKeyEnv is the receipt key configuration serve requires.
func receiptKeyEnv(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		envReceiptSigningKeyFile: writeKeyFile(t, hex.EncodeToString(testReceiptSeed)+"\n"),
		envReceiptKeyID:          testReceiptKeyID,
	}
}

// TestServeRefusesToStartWithoutAUsableReceiptKey: serve records every
// decision with a signed receipt, so it does not start without a key, and a
// passphrase or a key of the wrong size is not one (CTL-059).
func TestServeRefusesToStartWithoutAUsableReceiptKey(t *testing.T) {
	base := with(identityEnv, map[string]string{"HELM_GATEWAY_DATABASE_URL": "postgres://127.0.0.1:1/none?sslmode=disable"})
	args := []string{"serve", "--dev-insecure-listen", "127.0.0.1:0", "--health-listen", "127.0.0.1:0"}
	good := hex.EncodeToString(testReceiptSeed)
	for name, test := range map[string]struct {
		env  map[string]string
		want string
	}{
		"no key file":          {map[string]string{envReceiptKeyID: testReceiptKeyID}, envReceiptSigningKeyFile},
		"no key id":            {map[string]string{envReceiptSigningKeyFile: writeKeyFile(t, good)}, envReceiptKeyID},
		"a missing file":       {map[string]string{envReceiptSigningKeyFile: "/nonexistent/seed", envReceiptKeyID: testReceiptKeyID}, "no such file"},
		"a passphrase":         {map[string]string{envReceiptSigningKeyFile: writeKeyFile(t, "correct horse battery staple"), envReceiptKeyID: testReceiptKeyID}, "32-byte Ed25519 seed"},
		"a 31-byte seed":       {map[string]string{envReceiptSigningKeyFile: writeKeyFile(t, good[:62]), envReceiptKeyID: testReceiptKeyID}, "32-byte Ed25519 seed"},
		"a 64-byte key":        {map[string]string{envReceiptSigningKeyFile: writeKeyFile(t, good+good), envReceiptKeyID: testReceiptKeyID}, "32-byte Ed25519 seed"},
		"an empty file":        {map[string]string{envReceiptSigningKeyFile: writeKeyFile(t, ""), envReceiptKeyID: testReceiptKeyID}, "32-byte Ed25519 seed"},
		"a key id with =":      {map[string]string{envReceiptSigningKeyFile: writeKeyFile(t, good), envReceiptKeyID: "a=b"}, "key id"},
		"a key id with spaces": {map[string]string{envReceiptSigningKeyFile: writeKeyFile(t, good), envReceiptKeyID: "gateway key"}, "key id"},
		"an all-zero seed": {map[string]string{envReceiptSigningKeyFile: writeKeyFile(t, strings.Repeat("00", 32)), envReceiptKeyID: testReceiptKeyID},
			"all-zero seed"},
		"a key id and a prefix": {map[string]string{envReceiptSigningKeyFile: writeKeyFile(t, good), envReceiptKeyID: testReceiptKeyID,
			envReceiptKeyIDPrefix: "helm-gateway:ns:gw"}, envReceiptKeyIDPrefix},
		"a prefix with =": {map[string]string{envReceiptSigningKeyFile: writeKeyFile(t, good), envReceiptKeyIDPrefix: "a=b"}, "key id"},
	} {
		err := Run(context.Background(), args, env(with(base, test.env)), io.Discard)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: err = %v, want one naming %q", name, err, test.want)
		}
	}
	// Known good: the same configuration with a usable key loads it.
	signer, err := receiptSignerFromEnv(env(receiptKeyEnv(t)))
	if err != nil || signer.GetKeyID() != testReceiptKeyID {
		t.Fatalf("a hex seed: signer %v, err %v", signer, err)
	}
}

// TestReceiptKeyAcceptsHexAndBase64SeedsAndPrintsOnlyThePublicHalf: the chart
// writes a base64 seed and an operator may write hex; both name the same key,
// and `helm-gateway receipt-key` prints "<key_id>=<public hex>" and never the
// seed.
func TestReceiptKeyAcceptsHexAndBase64SeedsAndPrintsOnlyThePublicHalf(t *testing.T) {
	want := hex.EncodeToString(ed25519.NewKeyFromSeed(testReceiptSeed).Public().(ed25519.PublicKey))
	for name, body := range map[string]string{
		"hex":    hex.EncodeToString(testReceiptSeed) + "\n",
		"base64": base64.StdEncoding.EncodeToString(testReceiptSeed),
	} {
		var out bytes.Buffer
		values := map[string]string{envReceiptSigningKeyFile: writeKeyFile(t, body), envReceiptKeyID: testReceiptKeyID}
		if err := runReceiptKey(nil, env(values), &out); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if out.String() != testReceiptKeyID+"="+want+"\n" {
			t.Fatalf("%s: printed %q, want %s=%s", name, out.String(), testReceiptKeyID, want)
		}
		if strings.Contains(out.String(), hex.EncodeToString(testReceiptSeed)) || strings.Contains(out.String(), base64.StdEncoding.EncodeToString(testReceiptSeed)) {
			t.Fatalf("%s: receipt-key printed the seed", name)
		}
	}
	// The chart's default: the key id ends in the key's own fingerprint, so a
	// new seed is never published under the old key's id.
	fingerprint := sha256.Sum256(ed25519.NewKeyFromSeed(testReceiptSeed).Public().(ed25519.PublicKey))
	var derived bytes.Buffer
	prefixed := map[string]string{envReceiptSigningKeyFile: writeKeyFile(t, hex.EncodeToString(testReceiptSeed)), envReceiptKeyIDPrefix: "helm-gateway:ns:gw"}
	if err := runReceiptKey(nil, env(prefixed), &derived); err != nil {
		t.Fatal(err)
	}
	wantID := "helm-gateway:ns:gw:" + hex.EncodeToString(fingerprint[:8])
	if derived.String() != wantID+"="+want+"\n" {
		t.Fatalf("a derived key id printed %q, want %s=%s", derived.String(), wantID, want)
	}
	other := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	prefixed[envReceiptSigningKeyFile] = writeKeyFile(t, hex.EncodeToString(other))
	signer, err := receiptSignerFromEnv(env(prefixed))
	if err != nil || signer.GetKeyID() == wantID || !strings.HasPrefix(signer.GetKeyID(), "helm-gateway:ns:gw:") {
		t.Fatalf("another seed under the same prefix: %v, %v", signer, err)
	}
	if err := runReceiptKey([]string{"--seed"}, env(receiptKeyEnv(t)), io.Discard); err == nil {
		t.Fatal("receipt-key accepted an argument")
	}
	if err := runReceiptKey(nil, env(nil), io.Discard); err == nil || !strings.Contains(err.Error(), envReceiptSigningKeyFile) {
		t.Fatalf("receipt-key without a key: %v", err)
	}
}
