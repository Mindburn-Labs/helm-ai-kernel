package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func persistEvaluateReceiptFile(t *testing.T) (receiptPath, keyPath string, receipt *contracts.Receipt) {
	t.Helper()
	isolateVerifyReceiptTest(t)
	signer, err := helmcrypto.NewEd25519Signer("verify-receipt-test")
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	store := &captureReceiptStore{}
	svc := &Services{DataDir: dataDir, ReceiptStore: store, ReceiptSigner: signer}
	decision := &contracts.DecisionRecord{
		ID:                 "dec-verify-receipt",
		Action:             "EXECUTE_TOOL",
		Verdict:            string(contracts.VerdictDeny),
		ReasonCode:         string(contracts.ReasonEmergencyStopFenced),
		PolicyContentHash:  "sha256:policy-content",
		PolicyDecisionHash: "sha256:pdp",
		InputContext:       map[string]any{"session_id": "session-verify-receipt"},
		Timestamp:          time.Unix(1700000000, 0).UTC(),
	}
	if err := persistDecisionReceipt(context.Background(), svc, decision, "agent.test", []byte("EXECUTE_TOOL:tool"), map[string]any{"source": "api.evaluate"}); err != nil {
		t.Fatalf("persist receipt: %v", err)
	}
	if store.stored == nil {
		t.Fatal("receipt was not stored")
	}
	src := portableEvaluateReceiptPath(dataDir, store.stored.ReceiptID)
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read persisted receipt: %v", err)
	}
	offBox := filepath.Join(t.TempDir(), "copied-evaluate-receipt.json")
	if err := os.WriteFile(offBox, raw, 0o600); err != nil {
		t.Fatalf("copy receipt off-box: %v", err)
	}
	keyPath = filepath.Join(t.TempDir(), "expected-ed25519.pub")
	if err := os.WriteFile(keyPath, []byte(signer.PublicKey()+"\n"), 0o644); err != nil {
		t.Fatalf("write trusted key: %v", err)
	}
	return offBox, keyPath, store.stored
}

func isolateVerifyReceiptTest(t *testing.T) {
	t.Helper()
	t.Setenv("HELM_ADMIN_API_KEY", "")
	t.Setenv("HELM_URL", "")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("https_proxy", "")
}

func TestVerifyReceiptCLITrustedCopiedFile(t *testing.T) {
	receiptPath, keyPath, _ := persistEvaluateReceiptFile(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "verify", "receipt",
		"--receipt", receiptPath,
		"--trusted-public-key-file", keyPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify receipt exit = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "integrity: true") || !strings.Contains(stdout.String(), "trusted:   true") {
		t.Fatalf("verify receipt output missing trusted integrity: %s", stdout.String())
	}
}

func TestVerifyReceiptCLITamperedVerdict(t *testing.T) {
	receiptPath, keyPath, _ := persistEvaluateReceiptFile(t)
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"verdict": "DENY"`, `"verdict": "ALLOW"`, 1)
	if tampered == string(raw) {
		t.Fatal("receipt fixture did not contain signed DENY verdict")
	}
	tamperedPath := filepath.Join(t.TempDir(), "tampered-verdict.json")
	if err := os.WriteFile(tamperedPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "verify", "receipt",
		"--receipt", tamperedPath,
		"--trusted-public-key-file", keyPath,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("tampered verdict exit = %d, want 1 stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "integrity: false") {
		t.Fatalf("tampered verdict output missing integrity=false: %s", stdout.String())
	}
}

func TestVerifyReceiptCLITamperedSignature(t *testing.T) {
	receiptPath, keyPath, _ := persistEvaluateReceiptFile(t)
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	sig, _ := doc["signature"].(string)
	if sig == "" {
		t.Fatal("receipt missing signature")
	}
	doc["signature"] = strings.Repeat("0", len(sig))
	tampered, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(t.TempDir(), "tampered-signature.json")
	if err := os.WriteFile(tamperedPath, append(tampered, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "verify", "receipt",
		"--receipt", tamperedPath,
		"--trusted-public-key-file", keyPath,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("tampered signature exit = %d, want 1 stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "integrity: false") {
		t.Fatalf("tampered signature output missing integrity=false: %s", stdout.String())
	}
}

func TestVerifyReceiptCLIMissingTrustedKey(t *testing.T) {
	receiptPath, _, _ := persistEvaluateReceiptFile(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "verify", "receipt",
		"--receipt", receiptPath,
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("missing trusted key must not verify: stdout=%s", stdout.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("usage error leaked data to stdout: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "trusted-public-key-file") {
		t.Fatalf("missing key stderr = %s", stderr.String())
	}
}

func TestVerifyReceiptCLIWrongTrustedKey(t *testing.T) {
	receiptPath, _, _ := persistEvaluateReceiptFile(t)
	wrong := filepath.Join(t.TempDir(), "wrong-trusted.pub")
	if err := os.WriteFile(wrong, []byte(strings.Repeat("f", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "verify", "receipt",
		"--receipt", receiptPath,
		"--trusted-public-key-file", wrong,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("wrong-anchor exit = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "integrity: true") || !strings.Contains(stdout.String(), "trusted:   false") {
		t.Fatalf("wrong-anchor output missing trust separation: %s", stdout.String())
	}
}

func TestVerifyReceiptCLIJSONReportsAdmissible(t *testing.T) {
	receiptPath, keyPath, stored := persistEvaluateReceiptFile(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "verify", "receipt",
		"--receipt", receiptPath,
		"--trusted-public-key-file", keyPath,
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("json verify exit = %d stderr=%s", code, stderr.String())
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("json report: %v\n%s", err, stdout.String())
	}
	if report["integrity_valid"] != true || report["signer_trusted"] != true {
		t.Fatalf("json report = %#v", report)
	}
	if report["receipt_id"] != stored.ReceiptID {
		t.Fatalf("json receipt_id = %v, want %s", report["receipt_id"], stored.ReceiptID)
	}
}
