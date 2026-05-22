package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/correlation/hostaction"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence/externalhost"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/externalreceipt"
)

func runVerifyExternalReceiptCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("verify external-receipt", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var chainPath, publicKey string
	var jsonOutput bool
	cmd.StringVar(&chainPath, "chain", "", "Path to external host receipt chain JSON or JSONL")
	cmd.StringVar(&publicKey, "public-key", "", "Ed25519 public key hex or path to a file containing it")
	cmd.BoolVar(&jsonOutput, "json", false, "Output verification report as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if chainPath == "" {
		fmt.Fprintln(stderr, "Error: --chain is required")
		return 2
	}
	keyHex, err := readPublicKeyInput(publicKey)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	report, err := externalhost.VerifyFile(chainPath, externalhost.VerifyOptions{PublicKeyHex: keyHex, RequireKey: true})
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else if report.Verified {
		fmt.Fprintf(stdout, "VERIFIED external host receipt chain (%d receipts)\n", report.ReceiptCount)
		fmt.Fprintf(stdout, "Chain hash: %s\n", report.ChainHash)
	} else {
		fmt.Fprintf(stdout, "FAILED external host receipt chain (%d receipts)\n", report.ReceiptCount)
		for _, check := range report.Checks {
			if !check.Pass {
				fmt.Fprintf(stdout, "  - %s: %s\n", check.Name, check.Reason)
			}
		}
	}
	if !report.Verified {
		return 1
	}
	return 0
}

func runEvidenceAttachHostChain(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence attach-host-chain", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var bundle, chainPath, out, source string
	var jsonOutput bool
	cmd.StringVar(&bundle, "bundle", "", "EvidencePack directory or archive")
	cmd.StringVar(&chainPath, "chain", "", "External host receipt chain JSON or JSONL")
	cmd.StringVar(&out, "out", "", "Output EvidencePack directory or .tar archive")
	cmd.StringVar(&source, "source", "external", "Host evidence source name")
	cmd.BoolVar(&jsonOutput, "json", false, "Output attachment metadata as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if bundle == "" || chainPath == "" || out == "" {
		fmt.Fprintln(stderr, "Error: --bundle, --chain, and --out are required")
		return 2
	}
	chainData, err := os.ReadFile(chainPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error: read chain: %v\n", err)
		return 2
	}
	if _, err := externalhost.Parse(chainData); err != nil {
		fmt.Fprintf(stderr, "Error: parse chain: %v\n", err)
		return 2
	}

	var attachedPath string
	err = withEvidenceBundleDir(bundle, func(srcDir string) error {
		workDir := out
		var archiveOut string
		if isArchivePath(out) {
			tmp, err := os.MkdirTemp("", "helm-host-evidence-*")
			if err != nil {
				return err
			}
			defer os.RemoveAll(tmp)
			workDir = filepath.Join(tmp, "pack")
			archiveOut = out
		}
		if srcDir != workDir {
			if err := copyDir(srcDir, workDir); err != nil {
				return err
			}
		}
		layoutPath := hostEvidencePathForBundle(workDir, source, filepath.Base(chainPath))
		if err := os.MkdirAll(filepath.Dir(layoutPath), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(layoutPath, chainData, 0o600); err != nil {
			return err
		}
		relPath, err := filepath.Rel(workDir, layoutPath)
		if err != nil {
			return err
		}
		attachedPath = filepath.ToSlash(relPath)
		if err := updateEvidenceIndexes(workDir, attachedPath, chainData); err != nil {
			return err
		}
		if archiveOut != "" {
			return deterministicTarArchive(workDir, archiveOut)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: attach host chain: %v\n", err)
		return 2
	}

	payload := map[string]any{
		"bundle":        bundle,
		"out":           out,
		"attached_path": attachedPath,
		"sha256":        sha256Hex(chainData),
	}
	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(payload)
		return 0
	}
	fmt.Fprintf(stdout, "Attached host evidence: %s\n", attachedPath)
	fmt.Fprintf(stdout, "Output: %s\n", out)
	return 0
}

func runEvidenceCorrelateHost(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence correlate-host", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var bundle string
	var jsonOutput bool
	cmd.StringVar(&bundle, "bundle", "", "EvidencePack directory or archive")
	cmd.BoolVar(&jsonOutput, "json", false, "Output correlation results as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if bundle == "" && cmd.NArg() > 0 {
		bundle = cmd.Arg(0)
	}
	if bundle == "" {
		fmt.Fprintln(stderr, "Error: --bundle is required")
		return 2
	}

	var report hostCorrelationCLIReport
	err := withEvidenceBundleDir(bundle, func(dir string) error {
		helmReceipts, err := loadHELMReceipts(dir)
		if err != nil {
			return err
		}
		chain, err := loadCombinedHostChain(dir)
		if err != nil {
			return err
		}
		results := hostaction.Correlate(helmReceipts, chain, hostaction.Options{})
		report = hostCorrelationCLIReport{
			Bundle:       bundle,
			ResultCount:  len(results),
			Results:      results,
			DriftCount:   countBoundaryDrift(results),
			HELMReceipts: len(helmReceipts),
		}
		if chain != nil {
			report.HostReceipts = len(chain.Receipts)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: correlate host evidence: %v\n", err)
		return 2
	}
	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return 0
	}
	fmt.Fprintf(stdout, "Host correlation results: %d\n", report.ResultCount)
	fmt.Fprintf(stdout, "Boundary Drift findings: %d\n", report.DriftCount)
	for _, result := range report.Results {
		if result.BoundaryDrift != nil {
			fmt.Fprintf(stdout, "  - %s: %s\n", result.Status, result.ReasonCode)
		}
	}
	if report.DriftCount > 0 {
		return 1
	}
	return 0
}

type hostCorrelationCLIReport struct {
	Bundle       string                            `json:"bundle"`
	HELMReceipts int                               `json:"helm_receipts"`
	HostReceipts int                               `json:"host_receipts"`
	ResultCount  int                               `json:"result_count"`
	DriftCount   int                               `json:"boundary_drift_count"`
	Results      []contracts.HostCorrelationResult `json:"results"`
}

func readPublicKeyInput(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if data, err := os.ReadFile(value); err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	return value, nil
}

func hostEvidencePathForBundle(bundleRoot, source, base string) string {
	source = safeEvidenceName(source)
	base = safeEvidenceName(base)
	if _, err := os.Stat(filepath.Join(bundleRoot, "00_INDEX.json")); err == nil {
		return filepath.Join(bundleRoot, "11_HOST_EVIDENCE", source, base)
	}
	return filepath.Join(bundleRoot, "host_evidence", source, base)
}

func updateEvidenceIndexes(bundleRoot, relPath string, data []byte) error {
	hash := sha256Hex(data)
	if err := updateRootIndex(filepath.Join(bundleRoot, "00_INDEX.json"), relPath, hash); err != nil {
		return err
	}
	if err := updateRootManifest(filepath.Join(bundleRoot, "manifest.json"), relPath, hash, len(data)); err != nil {
		return err
	}
	launchpadManifest := filepath.Join(bundleRoot, "04_EXPORTS", "launchpad_manifest.json")
	if err := updateLaunchpadManifest(launchpadManifest, relPath, hash); err != nil {
		return err
	}
	if manifestData, err := os.ReadFile(launchpadManifest); err == nil {
		return updateRootIndex(filepath.Join(bundleRoot, "00_INDEX.json"), "04_EXPORTS/launchpad_manifest.json", sha256Hex(manifestData))
	}
	return nil
}

func updateRootIndex(path, relPath, hash string) error {
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	entries, _ := doc["entries"].([]any)
	updated := false
	for _, entry := range entries {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if m["path"] == relPath {
			m["sha256"] = hash
			updated = true
		}
	}
	if !updated {
		entries = append(entries, map[string]any{"path": relPath, "sha256": hash})
	}
	sort.Slice(entries, func(i, j int) bool {
		left, _ := entries[i].(map[string]any)
		right, _ := entries[j].(map[string]any)
		return fmt.Sprint(left["path"]) < fmt.Sprint(right["path"])
	})
	doc["entries"] = entries
	return writeIndentedJSON(path, doc)
}

func updateRootManifest(path, relPath, hash string, size int) error {
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	if raw, ok := doc["file_hashes"].(map[string]any); ok {
		raw[relPath] = hash
		return writeIndentedJSON(path, doc)
	}
	if _, ok := doc["entries"].([]any); !ok {
		return nil
	}
	var manifest evidencepack.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	upsertManifestEntry(&manifest, relPath, "sha256:"+hash, int64(size), "application/json")
	manifestHash, err := evidencepack.ComputeManifestHash(&manifest)
	if err != nil {
		return err
	}
	manifest.ManifestHash = manifestHash
	return writeIndentedJSON(path, manifest)
}

func updateLaunchpadManifest(path, relPath, hash string) error {
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	if _, ok := doc["file_hashes"].(map[string]any); !ok {
		doc["file_hashes"] = map[string]any{}
	}
	if _, ok := doc["artifacts"].(map[string]any); !ok {
		doc["artifacts"] = map[string]any{}
	}
	doc["file_hashes"].(map[string]any)[relPath] = hash
	doc["artifacts"].(map[string]any)[relPath] = "sha256:" + hash
	return writeIndentedJSON(path, doc)
}

func upsertManifestEntry(manifest *evidencepack.Manifest, path, contentHash string, size int64, contentType string) {
	for i := range manifest.Entries {
		if manifest.Entries[i].Path == path {
			manifest.Entries[i].ContentHash = contentHash
			manifest.Entries[i].Size = size
			manifest.Entries[i].ContentType = contentType
			return
		}
	}
	manifest.Entries = append(manifest.Entries, evidencepack.ManifestEntry{
		Path:        path,
		ContentHash: contentHash,
		Size:        size,
		ContentType: contentType,
	})
}

func writeIndentedJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func loadCombinedHostChain(bundleRoot string) (*contracts.ExternalReceiptChain, error) {
	files := externalreceipt.FindChainFiles(bundleRoot)
	if len(files) == 0 {
		return nil, nil
	}
	combined := &contracts.ExternalReceiptChain{SchemaVersion: contracts.ExternalReceiptChainVersion}
	for _, file := range files {
		chain, err := externalhost.ParseFile(file)
		if err != nil {
			return nil, err
		}
		combined.Receipts = append(combined.Receipts, chain.Receipts...)
	}
	return combined, nil
}

func loadHELMReceipts(bundleRoot string) ([]contracts.Receipt, error) {
	dir := filepath.Join(bundleRoot, "receipts")
	if _, err := os.Stat(dir); err != nil {
		dir = filepath.Join(bundleRoot, "02_PROOFGRAPH", "receipts")
	}
	var receipts []contracts.Receipt
	if _, err := os.Stat(dir); err != nil {
		return receipts, nil
	}
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || filepath.Ext(path) != ".json" {
			return walkErr
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var receipt contracts.Receipt
		if err := json.Unmarshal(data, &receipt); err == nil && receipt.ReceiptID != "" {
			receipts = append(receipts, receipt)
		}
		return nil
	})
	return receipts, err
}

func countBoundaryDrift(results []contracts.HostCorrelationResult) int {
	count := 0
	for _, result := range results {
		if result.BoundaryDrift != nil {
			count++
		}
	}
	return count
}
