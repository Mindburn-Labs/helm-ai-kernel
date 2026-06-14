package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/decisionreceipt"
)

func TestImportReceiptCLIWritesPack(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signed, err := decisionreceipt.SignHelmExternal(contracts.ExternalDecisionReceipt{
		ReceiptID: "edr-cli-imp", Action: "github.create_issue", Verdict: "allow", SourceVendor: "v",
	}, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	in := writeReceiptFile(t, signed) // helper defined in verify_decision_receipt_cmd_test.go
	out := filepath.Join(t.TempDir(), "pack")

	var so, se bytes.Buffer
	code := runImportReceiptCmd([]string{in, "--out", out, "--public-key", hex.EncodeToString(pub)}, &so, &se)
	if code != 0 {
		t.Fatalf("exit=%d, want 0; stderr=%s", code, se.String())
	}
	for _, p := range []string{"manifest.json", "compatibility/import_manifest.json", "host_evidence/helm_external.v1/source.json"} {
		if _, err := os.Stat(filepath.Join(out, p)); err != nil {
			t.Fatalf("missing pack file %s: %v", p, err)
		}
	}
	if !bytes.Contains(so.Bytes(), []byte("manifest_hash")) {
		t.Fatalf("expected manifest_hash in output: %s", so.String())
	}
}

func TestImportReceiptCLIRequiresOut(t *testing.T) {
	var so, se bytes.Buffer
	code := runImportReceiptCmd([]string{"/tmp/whatever.json"}, &so, &se)
	if code != 2 {
		t.Fatalf("exit=%d, want 2 (missing --out)", code)
	}
}
