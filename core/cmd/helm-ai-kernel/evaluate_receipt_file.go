// quantum_posture: portable evaluate receipt files carry classical Ed25519
// receipt.v5 signatures only; this write path adds no post-quantum control.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	portableEvaluateReceiptDirName = "evaluate"
	portableEvaluatePublicKeyName  = "expected-ed25519.pub"
)

func portableEvaluateReceiptDir(dataDir string) string {
	return filepath.Join(strings.TrimSpace(dataDir), "receipts", portableEvaluateReceiptDirName)
}

func portableEvaluateReceiptPath(dataDir, receiptID string) string {
	return filepath.Join(portableEvaluateReceiptDir(dataDir), sanitizeReceiptFileName(receiptID)+".json")
}

func portableEvaluatePublicKeyPath(dataDir string) string {
	return filepath.Join(portableEvaluateReceiptDir(dataDir), portableEvaluatePublicKeyName)
}

func sanitizeReceiptFileName(receiptID string) string {
	id := strings.TrimSpace(receiptID)
	if id == "" {
		return "receipt"
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, id)
}

// writePortableEvaluateReceipt writes the signed receipt.v5 object as a JSON
// file that can be copied off-box. It also writes the kernel Ed25519 public
// key beside it so a stranger can pass that file to `verify receipt`.
//
// Empty DataDir skips the write so existing in-memory persist tests stay
// unchanged. When DataDir is set, a write failure fails persist.
func writePortableEvaluateReceipt(svc *Services, receipt *contracts.Receipt) error {
	if svc == nil {
		return nil
	}
	dataDir := strings.TrimSpace(svc.DataDir)
	if dataDir == "" {
		return nil
	}
	if receipt == nil {
		return fmt.Errorf("portable evaluate receipt write requires a receipt")
	}
	dir := portableEvaluateReceiptDir(dataDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create portable evaluate receipt dir: %w", err)
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("encode portable evaluate receipt %s: %w", receipt.ReceiptID, err)
	}
	path := portableEvaluateReceiptPath(dataDir, receipt.ReceiptID)
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write portable evaluate receipt %s: %w", path, err)
	}
	if svc.ReceiptSigner == nil {
		return fmt.Errorf("receipt signer unavailable for portable public key")
	}
	pubBytes := svc.ReceiptSigner.PublicKeyBytes()
	if len(pubBytes) != ed25519PublicKeySize {
		return fmt.Errorf("portable evaluate public key must be %d Ed25519 bytes, got %d", ed25519PublicKeySize, len(pubBytes))
	}
	if err := os.WriteFile(portableEvaluatePublicKeyPath(dataDir), []byte(hex.EncodeToString(pubBytes)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write portable evaluate public key: %w", err)
	}
	return nil
}

const ed25519PublicKeySize = 32
