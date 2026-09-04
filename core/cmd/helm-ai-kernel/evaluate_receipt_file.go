// quantum_posture: portable evaluate EvidencePacks carry classical Ed25519
// receipt.v5 signatures and pack seals only; this write path adds no
// post-quantum control.
package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

const (
	portableEvaluateReceiptDirName = "evaluate"
	portableEvaluatePublicKeyName  = "expected-ed25519.pub"
	portableEvaluateEvidencePack   = "evidence-pack.tar"
	ed25519PublicKeySize           = 32
)

func portableEvaluateReceiptDir(dataDir string) string {
	return filepath.Join(strings.TrimSpace(dataDir), "receipts", portableEvaluateReceiptDirName)
}

func portableEvaluateEvidencePackDir(dataDir, receiptID string) string {
	return filepath.Join(portableEvaluateReceiptDir(dataDir), sanitizeReceiptFileName(receiptID))
}

func portableEvaluateEvidencePackPath(dataDir, receiptID string) string {
	return filepath.Join(portableEvaluateEvidencePackDir(dataDir, receiptID), portableEvaluateEvidencePack)
}

func portableEvaluatePublicKeyPath(dataDir, receiptID string) string {
	return filepath.Join(portableEvaluateEvidencePackDir(dataDir, receiptID), portableEvaluatePublicKeyName)
}

func portableEvaluateReceiptPath(dataDir, receiptID string) string {
	name := sanitizeReceiptFileName(receiptID)
	return filepath.Join(portableEvaluateEvidencePackDir(dataDir, receiptID), name+".json")
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

// writePortableEvaluateEvidencePack writes a copyable receipt.v5 JSON file
// and an EvidencePack that contains that same receipt. The command for the
// JSON file is:
//
//	helm-ai-kernel verify receipt --receipt <file> --trusted-public-key-file <key>
//
// Exit 0 requires integrity and the caller-supplied key. Empty DataDir
// skips the write so existing in-memory persist tests stay unchanged.
// When DataDir is set, a write failure fails persist.
func writePortableEvaluateEvidencePack(svc *Services, receipt *contracts.Receipt) error {
	if svc == nil {
		return nil
	}
	dataDir := strings.TrimSpace(svc.DataDir)
	if dataDir == "" {
		return nil
	}
	if receipt == nil {
		return fmt.Errorf("portable evaluate evidence pack write requires a receipt")
	}
	if receipt.OrganizationRuntimeDecisionAttestation != nil {
		if svc.ReceiptSigner == nil {
			return fmt.Errorf("organization runtime attestation verifier unavailable")
		}
		if err := contracts.VerifyOrganizationRuntimeReceiptAttestation(receipt, svc.ReceiptSigner.PublicKeyBytes()); err != nil {
			return fmt.Errorf("verify organization runtime attestation before evidence export: %w", err)
		}
	}
	packDir, err := os.MkdirTemp("", "helm-evaluate-evidence-*")
	if err != nil {
		return fmt.Errorf("create portable evaluate pack workspace: %w", err)
	}
	defer os.RemoveAll(packDir)
	if err := writeEvaluateEvidencePackTree(packDir, receipt); err != nil {
		return err
	}
	if err := sealEvaluateEvidencePack(svc, packDir, receipt); err != nil {
		return err
	}
	destDir := portableEvaluateEvidencePackDir(dataDir, receipt.ReceiptID)
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return fmt.Errorf("create portable evaluate pack dir: %w", err)
	}
	receiptJSON, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("encode portable evaluate receipt %s: %w", receipt.ReceiptID, err)
	}
	if err := os.WriteFile(portableEvaluateReceiptPath(dataDir, receipt.ReceiptID), append(receiptJSON, '\n'), 0o600); err != nil {
		return fmt.Errorf("write portable evaluate receipt: %w", err)
	}
	if err := writeDirectoryTar(packDir, portableEvaluateEvidencePackPath(dataDir, receipt.ReceiptID)); err != nil {
		return err
	}
	if svc.ReceiptSigner == nil {
		return fmt.Errorf("receipt signer unavailable for portable public key")
	}
	pubBytes := svc.ReceiptSigner.PublicKeyBytes()
	if len(pubBytes) != ed25519PublicKeySize {
		return fmt.Errorf("portable evaluate public key must be %d Ed25519 bytes, got %d", ed25519PublicKeySize, len(pubBytes))
	}
	if err := os.WriteFile(portableEvaluatePublicKeyPath(dataDir, receipt.ReceiptID), []byte(hex.EncodeToString(pubBytes)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write portable evaluate public key: %w", err)
	}
	return nil
}

func writeEvaluateEvidencePackTree(packDir string, receipt *contracts.Receipt) error {
	if err := conform.CreateEvidencePackDirs(packDir); err != nil {
		return err
	}
	receiptsDir := filepath.Join(packDir, "02_PROOFGRAPH", "receipts")
	if err := os.MkdirAll(receiptsDir, 0o750); err != nil {
		return fmt.Errorf("create evaluate pack receipts dir: %w", err)
	}
	receiptData, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("encode evaluate receipt %s: %w", receipt.ReceiptID, err)
	}
	receiptName := sanitizeReceiptFileName(receipt.ReceiptID) + ".json"
	if err := os.WriteFile(filepath.Join(receiptsDir, receiptName), append(receiptData, '\n'), 0o600); err != nil {
		return fmt.Errorf("write evaluate receipt into pack: %w", err)
	}
	if receipt.OrganizationRuntimeDecisionAttestation != nil {
		attestationsDir := filepath.Join(packDir, "02_PROOFGRAPH", "attestations")
		if err := os.MkdirAll(attestationsDir, 0o750); err != nil {
			return fmt.Errorf("create evaluate pack attestations dir: %w", err)
		}
		attestationData, err := json.MarshalIndent(receipt.OrganizationRuntimeDecisionAttestation, "", "  ")
		if err != nil {
			return fmt.Errorf("encode organization runtime attestation: %w", err)
		}
		attestationName := sanitizeReceiptFileName(receipt.ReceiptID) + ".organization-runtime.json"
		if err := os.WriteFile(filepath.Join(attestationsDir, attestationName), append(attestationData, '\n'), 0o600); err != nil {
			return fmt.Errorf("write organization runtime attestation into pack: %w", err)
		}
	}
	score, err := json.MarshalIndent(evaluateEvidencePackScore(receipt), "", "  ")
	if err != nil {
		return fmt.Errorf("encode evaluate pack score: %w", err)
	}
	score = append(score, '\n')
	if err := os.WriteFile(filepath.Join(packDir, "01_SCORE.json"), score, 0o600); err != nil {
		return fmt.Errorf("write evaluate pack score: %w", err)
	}
	sum := sha256.Sum256(score)
	if err := os.WriteFile(filepath.Join(packDir, "01_SCORE.json.sha256"), []byte(hex.EncodeToString(sum[:])+"\n"), 0o644); err != nil {
		return fmt.Errorf("write evaluate pack score digest: %w", err)
	}
	return writeDemoEvidenceIndex(packDir, "evaluate-"+sanitizeReceiptFileName(receipt.ReceiptID))
}

func evaluateEvidencePackScore(receipt *contracts.Receipt) map[string]any {
	verdict := strings.TrimSpace(receipt.Verdict)
	if verdict == "" {
		verdict = strings.TrimSpace(receipt.Status)
	}
	permit := strings.EqualFold(verdict, string(contracts.VerdictAllow))
	score := map[string]any{
		"verdict":    verdict,
		"permit":     permit,
		"receipt_id": receipt.ReceiptID,
		"reason":     receipt.ReasonCode,
	}
	if !permit {
		score["label"] = "DENY / no permit"
		score["pass"] = false
	}
	return score
}

func sealEvaluateEvidencePack(svc *Services, packDir string, receipt *contracts.Receipt) error {
	sealSigner, trustConfig, err := trustedEvidenceBundleSealSigner(svc)
	if err != nil {
		return err
	}
	if _, err := evidencepkg.SealEvidencePack(context.Background(), packDir, evidencepkg.SealEvidencePackOptions{
		PackID:      "evaluate-" + sanitizeReceiptFileName(receipt.ReceiptID),
		Profile:     evidencepkg.EvidenceTrustProfileDevLocal,
		Signer:      sealSigner,
		TrustConfig: trustConfig,
		SignedAt:    evidenceBundleSignedAt([]*contracts.Receipt{receipt}),
	}); err != nil {
		return fmt.Errorf("seal evaluate evidence pack: %w", err)
	}
	return nil
}

func writeDirectoryTar(srcDir, destPath string) error {
	file, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create evaluate evidence pack %s: %w", destPath, err)
	}
	defer file.Close()
	tw := tar.NewWriter(file)
	defer tw.Close()
	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("tar header %s: %w", rel, err)
		}
		hdr.Name = rel
		if info.IsDir() {
			hdr.Name = rel + "/"
			hdr.Size = 0
			return tw.WriteHeader(hdr)
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write tar header %s: %w", rel, err)
		}
		src, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open pack file %s: %w", rel, err)
		}
		_, copyErr := io.Copy(tw, src)
		_ = src.Close()
		if copyErr != nil {
			return fmt.Errorf("write pack file %s: %w", rel, copyErr)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("archive evaluate evidence pack: %w", err)
	}
	return nil
}
