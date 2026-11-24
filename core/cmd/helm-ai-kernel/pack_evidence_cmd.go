package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/translog"
)

func handlePackCreate(args []string) int {
	cmd := flag.NewFlagSet("pack create", flag.ContinueOnError)
	cmd.SetOutput(os.Stderr)

	var (
		sessionID   string
		receiptsDir string
		outPath     string
		dataDir     string
		jsonOutput  bool
	)

	cmd.StringVar(&sessionID, "session", "", "Session ID for the evidence pack (REQUIRED)")
	cmd.StringVar(&receiptsDir, "receipts", "", "Directory containing receipt files (REQUIRED)")
	cmd.StringVar(&outPath, "out", "", "Output path for the .tar pack (REQUIRED)")
	cmd.StringVar(&dataDir, "data-dir", "", "Kernel data directory for transparency checkpoint (default $HELM_DATA_DIR or ./data)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output result as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if sessionID == "" || receiptsDir == "" || outPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --session, --receipts, and --out are required")
		cmd.Usage()
		return 2
	}

	// Read all files from receipts directory
	files := make(map[string][]byte)
	err := filepath.Walk(receiptsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, _ := filepath.Rel(receiptsDir, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", relPath, err)
		}
		files[relPath] = data
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading receipts: %v\n", err)
		return 2
	}

	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no files found in receipts directory")
		return 2
	}

	// Auto-include proofgraph.json if it exists alongside receipts (Gap #22)
	pgPath := filepath.Join(receiptsDir, "proofgraph.json")
	if _, err := os.Stat(pgPath); err == nil {
		if _, exists := files["proofgraph.json"]; !exists {
			data, readErr := os.ReadFile(pgPath)
			if readErr == nil {
				files["proofgraph.json"] = data
			}
		}
	}

	// Auto-include trust_roots.json from artifacts if it exists (Gap #28)
	for _, trustPath := range []string{
		filepath.Join(receiptsDir, "..", "artifacts", "trust_roots.json"),
		filepath.Join(receiptsDir, "trust_roots.json"),
		"artifacts/trust_roots.json",
	} {
		if _, err := os.Stat(trustPath); err == nil {
			if _, exists := files["trust_roots.json"]; !exists {
				data, readErr := os.ReadFile(trustPath)
				if readErr == nil {
					files["trust_roots.json"] = data
				}
			}
			break
		}
	}

	opts := ExportPackOptions{}
	sth, transparencyFiles, err := transparencyArtifactsForPackCreate(translogDataDir(dataDir), files)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating transparency checkpoint: %v\n", err)
		return 2
	}
	if sth != nil {
		opts.TransparencySTH = sth
	}
	for name, data := range transparencyFiles {
		if _, exists := files[name]; exists {
			fmt.Fprintf(os.Stderr, "Error creating transparency proof: %s already exists\n", name)
			return 2
		}
		files[name] = data
	}

	// Create the pack
	if err := ExportPackWithOptions(sessionID, files, outPath, opts); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating pack: %v\n", err)
		return 2
	}

	if jsonOutput {
		result := map[string]any{
			"session_id": sessionID,
			"pack_path":  outPath,
			"file_count": len(files),
			"status":     "created",
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Evidence pack created: %s (%d files)\n", outPath, len(files))
	}

	return 0
}

func transparencyArtifactsForPackCreate(dataDir string, files map[string][]byte) (*translog.SignedTreeHead, map[string][]byte, error) {
	if dataDir == "" {
		dataDir = "data"
	}
	logDir := filepath.Join(dataDir, "translog")
	if _, err := os.Stat(logDir); err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	l, err := openTranslog(dataDir)
	if err != nil {
		return nil, nil, err
	}
	treeSize := l.Size()
	if treeSize == 0 {
		return nil, nil, nil
	}
	root, err := l.Root(treeSize)
	if err != nil {
		return nil, nil, err
	}
	signer, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err != nil {
		return nil, nil, err
	}
	logID := translog.LogIDFromPublicKey(signer.PublicKeyBytes())
	sth, err := translog.SignTreeHead(signer, logID, treeSize, root, time.Now())
	if err != nil {
		return nil, nil, err
	}

	proofs := make(map[string][]byte)
	for name, data := range files {
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		var receipt contracts.Receipt
		if err := json.Unmarshal(data, &receipt); err != nil {
			continue
		}
		if receipt.LogID == "" || receipt.Transparency == nil || receipt.Transparency.Deferred {
			continue
		}
		if receipt.LogID != logID || (receipt.Transparency.LogID != "" && receipt.Transparency.LogID != logID) {
			return nil, nil, fmt.Errorf("receipt %s is anchored to log %q, exporter log is %q", name, receipt.LogID, logID)
		}
		proof, err := l.InclusionProof(receipt.LeafIndex, treeSize)
		if err != nil {
			return nil, nil, fmt.Errorf("build inclusion proof for %s: %w", name, err)
		}
		expectedLeafHash, err := receiptTranslogLeafHash(&receipt)
		if err != nil {
			return nil, nil, fmt.Errorf("compute transparency leaf for %s: %w", name, err)
		}
		if !strings.EqualFold(proof.LeafHash, expectedLeafHash) {
			return nil, nil, fmt.Errorf("receipt %s transparency proof leaf hash mismatch: proof leaf %s, receipt leaf %s", name, proof.LeafHash, expectedLeafHash)
		}
		proofData, err := json.MarshalIndent(proof, "", "  ")
		if err != nil {
			return nil, nil, fmt.Errorf("marshal inclusion proof for %s: %w", name, err)
		}
		proofName := transparencyProofEntryName(name)
		if _, exists := proofs[proofName]; exists {
			return nil, nil, fmt.Errorf("duplicate transparency proof entry %s", proofName)
		}
		proofs[proofName] = proofData
	}

	return sth, proofs, nil
}

func receiptTranslogLeafHash(receipt *contracts.Receipt) (string, error) {
	receiptHashHex, err := contracts.ReceiptChainHash(receipt)
	if err != nil {
		return "", err
	}
	leafInput, err := hex.DecodeString(receiptHashHex)
	if err != nil {
		return "", fmt.Errorf("decode receipt chain hash: %w", err)
	}
	leafHash := translog.LeafHash(leafInput)
	return hex.EncodeToString(leafHash[:]), nil
}

func transparencyProofEntryName(receiptPath string) string {
	name := strings.TrimSpace(receiptPath)
	name = strings.Trim(name, "/")
	name = strings.TrimSuffix(name, filepath.Ext(name))
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "..", "_")
	if name == "" {
		name = "receipt"
	}
	return "transparency/inclusion/" + name + ".json"
}

func handlePackVerify(args []string) int {
	cmd := flag.NewFlagSet("pack verify", flag.ContinueOnError)
	cmd.SetOutput(os.Stderr)

	var (
		bundlePath string
		jsonOutput bool
	)

	cmd.StringVar(&bundlePath, "bundle", "", "Path to evidence pack .tar (REQUIRED)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output integrity/authenticity result as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if bundlePath == "" {
		fmt.Fprintln(os.Stderr, "Error: --bundle is required")
		cmd.Usage()
		return 2
	}

	manifest, err := VerifyPack(bundlePath)
	if err != nil {
		if jsonOutput {
			result := map[string]any{
				"bundle": bundlePath,
				"valid":  false,
				"error":  err.Error(),
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
		}
		return 1
	}

	if jsonOutput {
		result := map[string]any{
			"bundle":          bundlePath,
			"valid":           false,
			"integrity_valid": true,
			"authenticated":   false,
			"error":           "pack authenticity is unverified: trusted signature verification is required",
			"session_id":      manifest.SessionID,
			"version":         manifest.Version,
			"exported_at":     manifest.ExportedAt,
			"file_count":      len(manifest.FileHashes),
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Fprintf(os.Stderr, "Pack authenticity not verified: trusted signature verification is required\n")
		fmt.Printf("Integrity check passed: %s\n", bundlePath)
		fmt.Printf("   Session:  %s\n", manifest.SessionID)
		fmt.Printf("   Version:  %s\n", manifest.Version)
		fmt.Printf("   Exported: %s\n", manifest.ExportedAt)
		fmt.Printf("   Files:    %d\n", len(manifest.FileHashes))
	}

	return 1
}
