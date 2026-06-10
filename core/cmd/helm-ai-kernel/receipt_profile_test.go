package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestReceiptProfileDefaultStaysClassical(t *testing.T) {
	t.Setenv("HELM_RECEIPT_PROFILE", "")

	signer, err := loadOrGenerateSignerWithDataDir(t.TempDir())
	if err != nil {
		t.Fatalf("signer init: %v", err)
	}
	r := contracts.Receipt{ReceiptID: "rcpt_1", DecisionID: "dec_1", Status: "SUCCESS"}
	if err := signer.SignReceipt(&r); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	if got := crypto.ReceiptSignatureProfile(r.Signature); got != crypto.ReceiptProfileClassical {
		t.Fatalf("default profile = %q, want classical", got)
	}
}

func TestReceiptProfileHybridIssuance(t *testing.T) {
	t.Setenv("HELM_RECEIPT_PROFILE", "hybrid")

	dataDir := t.TempDir()
	signer, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err != nil {
		t.Fatalf("hybrid signer init: %v", err)
	}

	r := contracts.Receipt{ReceiptID: "rcpt_1", DecisionID: "dec_1", Status: "SUCCESS"}
	if err := signer.SignReceipt(&r); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	if got := crypto.ReceiptSignatureProfile(r.Signature); got != crypto.ReceiptProfileHybrid {
		t.Fatalf("hybrid profile issuance produced %q envelope", got)
	}

	// PQ root key persists beside root.key and reloads to the same keypair.
	if _, err := os.Stat(filepath.Join(dataDir, "root.mldsa65.key")); err != nil {
		t.Fatalf("expected persisted ml-dsa-65 root key: %v", err)
	}
	reloaded, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err != nil {
		t.Fatalf("reload hybrid signer: %v", err)
	}
	if reloaded.PublicKey() != signer.PublicKey() {
		t.Fatal("reloaded hybrid signer does not match persisted keys")
	}
}

func TestReceiptProfileUnknownFailsClosed(t *testing.T) {
	t.Setenv("HELM_RECEIPT_PROFILE", "quantum-maybe")

	_, err := loadOrGenerateSignerWithDataDir(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "HELM_RECEIPT_PROFILE") {
		t.Fatalf("unknown profile must fail closed, got err=%v", err)
	}
}

func TestReceiptProfileHybridProductionRequiresPQKey(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "true")
	t.Setenv("HELM_RECEIPT_PROFILE", "hybrid")

	dataDir := t.TempDir()
	// Satisfy the classical root key requirement; leave the PQ key missing.
	seedHex := strings.Repeat("42", 32)
	if err := os.WriteFile(filepath.Join(dataDir, "root.key"), []byte(seedHex), 0o600); err != nil {
		t.Fatalf("write root.key: %v", err)
	}

	_, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err == nil || !strings.Contains(err.Error(), "root.mldsa65.key") {
		t.Fatalf("production hybrid mode must require the PQ root key, got err=%v", err)
	}
}
