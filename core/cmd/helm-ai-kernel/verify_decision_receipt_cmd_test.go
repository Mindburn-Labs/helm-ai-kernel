package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/decisionreceipt"
)

func writeReceiptFile(t *testing.T, r contracts.ExternalDecisionReceipt) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "receipt.json")
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestVerifyDecisionReceiptCLITrustedKeyConformant(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signed, err := decisionreceipt.SignHelmExternal(contracts.ExternalDecisionReceipt{
		ReceiptID: "edr_cli_1", Action: "github.create_issue", Verdict: "allow",
	}, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := writeReceiptFile(t, signed)

	var out, errb bytes.Buffer
	code := runVerifyDecisionReceiptCmd([]string{path, "--public-key", hex.EncodeToString(pub)}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d, want 0; stdout=%s stderr=%s", code, out.String(), errb.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("crypto_conformant")) {
		t.Fatalf("expected crypto_conformant; got %s", out.String())
	}
}

func TestVerifyDecisionReceiptCLITamperedUnverified(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed, _ := decisionreceipt.SignHelmExternal(contracts.ExternalDecisionReceipt{ReceiptID: "edr_cli_2", Action: "x"}, priv)
	signed.Action = "tampered" // mutate after signing
	path := writeReceiptFile(t, signed)

	var out, errb bytes.Buffer
	code := runVerifyDecisionReceiptCmd([]string{path, "--public-key", hex.EncodeToString(pub)}, &out, &errb)
	if code != 1 {
		t.Fatalf("exit=%d, want 1 (unverified); stdout=%s", code, out.String())
	}
}

func TestVerifyDecisionReceiptCLIMissingFile(t *testing.T) {
	var out, errb bytes.Buffer
	code := runVerifyDecisionReceiptCmd([]string{"/nonexistent/receipt.json"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit=%d, want 2 (error); stderr=%s", code, errb.String())
	}
}
