package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

// runVerifyCmd implements `helm-ai-kernel verify` per §2.1.
//
// Validates a signed EvidencePack bundle: structure, hashes, and signature.
// Supports auditor mode via --json-out for structured verification reports.
//
// Exit codes:
//
//	0 = verification passed
//	1 = verification failed
//	2 = runtime error
func runVerifyCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "external-receipt" {
		return runVerifyExternalReceiptCmd(args[1:], stdout, stderr)
	}
	if len(args) > 0 && (args[0] == "pack" || args[0] == "proofgraph") {
		args = args[1:]
	}

	cmd := flag.NewFlagSet("verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		bundle           string
		jsonOutput       bool
		jsonOutFile      string
		online           bool
		ledgerURL        string
		profile          string
		configPath       string
		storageReceipt   string
		externalHostKey  string
		trustedPublicKey string
		managedAgentKey  string
		requireEIDAS     bool
		eidasMaxAgeHours int
		requireTEE       string
	)

	cmd.StringVar(&bundle, "bundle", "", "Path to EvidencePack directory or archive")
	cmd.BoolVar(&jsonOutput, "json", false, "Output results as JSON to stdout")
	cmd.StringVar(&jsonOutFile, "json-out", "", "Write structured audit report to file (auditor mode)")
	cmd.BoolVar(&online, "online", false, "Verify pack metadata against the public proof ledger after offline checks pass")
	cmd.StringVar(&ledgerURL, "ledger-url", "", "Public proof verification URL")
	cmd.StringVar(&profile, "profile", "", "Evidence trust profile: dev-local, team, customer, high-assurance (default: active config or dev-local)")
	cmd.StringVar(&configPath, "config", "", "Evidence trust config path (for example helm/helm.yaml)")
	cmd.StringVar(&storageReceipt, "storage-receipt", "", "Path to S3 Object Lock storage receipt for customer/high-assurance verification")
	cmd.StringVar(&externalHostKey, "external-host-public-key", strings.TrimSpace(os.Getenv("HELM_EXTERNAL_HOST_PUBLIC_KEY_HEX")), "Trusted Ed25519 public key hex for external host evidence chains")
	cmd.StringVar(&trustedPublicKey, "trusted-public-key", strings.TrimSpace(os.Getenv("HELM_VERIFY_PUBLIC_KEY_HEX")), "Trusted Ed25519 public key hex for conformance report signatures")
	cmd.StringVar(&managedAgentKey, "managed-agent-receipt-public-key", strings.TrimSpace(os.Getenv("HELM_MANAGED_AGENT_RECEIPT_PUBLIC_KEY_HEX")), "Trusted Ed25519 public key hex for embedded managed-agent receipt signatures")
	cmd.BoolVar(&requireEIDAS, "require-eidas", false, "Require every receipt to carry an eIDAS-qualified RFC 3161 anchor")
	cmd.IntVar(&eidasMaxAgeHours, "eidas-max-age-hours", 24, "Maximum age in hours of an anchor's integrated_time before --require-eidas treats it as stale")
	cmd.StringVar(&requireTEE, "require-tee", "", "Require every receipt to carry a TEE attestation; one of sevsnp|tdx|nitro|any (empty = no requirement)")

	normalizedArgs, normalizeErr := normalizeVerifyArgs(args)
	if normalizeErr != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", normalizeErr)
		return 2
	}
	if err := cmd.Parse(normalizedArgs); err != nil {
		return 2
	}

	if bundle == "" && cmd.NArg() > 0 {
		bundle = cmd.Arg(0)
	}
	if cmd.NArg() > 1 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected argument: %s\n", cmd.Arg(1))
		return 2
	}
	if bundle == "" {
		_, _ = fmt.Fprintln(stderr, "Error: evidence pack path is required")
		return 2
	}

	verifyTarget := bundle
	storageObjectPath := ""
	info, err := os.Stat(bundle)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: verification failed: %v\n", err)
		return 2
	}
	if !info.IsDir() {
		storageObjectPath = bundle
		tempDir, err := os.MkdirTemp("", "helm-verify-*")
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot create verification workspace: %v\n", err)
			return 2
		}
		defer os.RemoveAll(tempDir)

		if err := extractEvidenceArchive(bundle, tempDir); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: verification failed: %v\n", err)
			return 2
		}
		verifyTarget = tempDir
	}

	// Use the standalone verifier library (zero network deps)
	profileOpt := evidencepkg.EvidenceTrustProfile("")
	if strings.TrimSpace(profile) != "" {
		profileOpt = normalizeEvidenceTrustProfile(profile)
	}
	report, err := verifier.VerifyBundleWithOptions(verifyTarget, verifier.VerifyOptions{
		Profile:                         profileOpt,
		ConfigPath:                      configPath,
		StorageReceiptPath:              storageReceipt,
		StorageObjectPath:               storageObjectPath,
		ExternalHostKeyHex:              externalHostKey,
		ManagedAgentReceiptPublicKeyHex: managedAgentKey,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: verification failed: %v\n", err)
		return 2
	}

	// Also run legacy conform-based checks for backward compat
	if hasCanonicalEvidenceLayout(verifyTarget) {
		structIssues := conform.ValidateEvidencePackStructure(verifyTarget)
		if len(structIssues) > 0 {
			for _, issue := range structIssues {
				report.Checks = append(report.Checks, verifier.CheckResult{
					Name:   "conform:" + issue,
					Pass:   false,
					Reason: issue,
				})
			}
			report.Verified = false
		}
	}

	// Verify report signature when a conformance report signature is present.
	if hasConformanceSignature(verifyTarget) {
		sigErr := conform.VerifyReport(verifyTarget, func(data []byte, sig string) error {
			pubKeyHex := strings.TrimSpace(trustedPublicKey)
			if pubKeyHex == "" {
				return fmt.Errorf("signature present but no trusted verification key available (set --trusted-public-key or HELM_VERIFY_PUBLIC_KEY_HEX)")
			}

			pubKeyBytes, err := hex.DecodeString(pubKeyHex)
			if err != nil || len(pubKeyBytes) != 32 {
				return fmt.Errorf("invalid HELM_VERIFY_PUBLIC_KEY_HEX: must be 64 hex chars (32 bytes)")
			}

			sigBytes, err := hex.DecodeString(sig)
			if err != nil {
				return fmt.Errorf("invalid signature encoding: %w", err)
			}

			pubKey := ed25519.PublicKey(pubKeyBytes)
			if !ed25519.Verify(pubKey, data, sigBytes) {
				return fmt.Errorf("Ed25519 signature verification failed: signature does not match data")
			}
			return nil
		})
		if sigErr != nil {
			report.Checks = append(report.Checks, verifier.CheckResult{
				Name:   "signature_verification",
				Pass:   false,
				Reason: fmt.Sprintf("signature: %v", sigErr),
			})
			report.Verified = false
		}
	}

	if requireEIDAS {
		eidasResults := checkEIDASAnchors(verifyTarget, time.Duration(eidasMaxAgeHours)*time.Hour)
		report.Checks = append(report.Checks, eidasResults...)
		for _, r := range eidasResults {
			if !r.Pass {
				report.Verified = false
			}
		}
	}

	if requireTEE != "" {
		teeResults := checkTEEAttestations(verifyTarget, requireTEE)
		report.Checks = append(report.Checks, teeResults...)
		for _, r := range teeResults {
			if !r.Pass {
				report.Verified = false
			}
		}
	}

	if online && report.Verified {
		proof, proofErr := verifyOnlineProof(report, ledgerURL)
		if proofErr != nil {
			report.Checks = append(report.Checks, verifier.CheckResult{
				Name:   "online_proof",
				Pass:   false,
				Reason: proofErr.Error(),
			})
			report.Verified = false
		} else if !proof.Verified {
			reason := proof.Error
			if reason == "" {
				reason = "public proof API did not verify this pack"
			}
			report.Checks = append(report.Checks, verifier.CheckResult{
				Name:   "online_proof",
				Pass:   false,
				Reason: reason,
			})
			report.Verified = false
		} else {
			report.Checks = append(report.Checks, verifier.CheckResult{
				Name:   "online_proof",
				Pass:   true,
				Detail: "public proof API verified pack metadata",
			})
			mergeOnlineProof(report, proof)
		}
	}

	finalizeVerifyReport(report)

	// Write auditor JSON report to file if requested
	if jsonOutFile != "" {
		data, _ := json.MarshalIndent(report, "", "  ")
		if writeErr := os.WriteFile(jsonOutFile, data, 0644); writeErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot write audit report: %v\n", writeErr)
			return 2
		}
		_, _ = fmt.Fprintf(stdout, "Audit report written to %s\n", jsonOutFile)
	}

	// Output
	if jsonOutput {
		data, _ := json.MarshalIndent(report, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		if report.Verified {
			printCompactVerifyReport(stdout, report)
		} else {
			_, _ = fmt.Fprintf(stdout, "FAILED · envelope %s\n", displayEnvelopeID(report))
			_, _ = fmt.Fprintf(stdout, "Bundle: %s\n", bundle)
			for _, c := range report.Checks {
				if !c.Pass {
					_, _ = fmt.Fprintf(stdout, "  - %s: %s\n", c.Name, c.Reason)
				}
			}
		}
	}

	if !report.Verified {
		return 1
	}
	return 0
}

func extractEvidenceArchive(bundlePath, dstDir string) error {
	file, err := os.Open(bundlePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(bundlePath, ".gz") || strings.HasSuffix(bundlePath, ".tgz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("open gzip archive: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	tarReader := tar.NewReader(reader)
	var extractedBytes int64
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		targetPath, err := safeArchiveEntryPath(dstDir, header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0750); err != nil {
				return fmt.Errorf("create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if header.Size < 0 {
				return fmt.Errorf("archive entry %s has invalid size", header.Name)
			}
			if header.Size > maxEvidenceBundleBytes {
				return fmt.Errorf("archive entry %s exceeds %d bytes", header.Name, maxEvidenceBundleBytes)
			}
			if extractedBytes+header.Size > maxEvidenceBundleBytes {
				return fmt.Errorf("archive exceeds %d extracted bytes", maxEvidenceBundleBytes)
			}
			if err := os.MkdirAll(filepath.Dir(targetPath), 0750); err != nil {
				return fmt.Errorf("prepare file %s: %w", targetPath, err)
			}
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if err != nil {
				return fmt.Errorf("create file %s: %w", targetPath, err)
			}
			written, err := io.Copy(outFile, tarReader)
			if err != nil {
				outFile.Close()
				return fmt.Errorf("extract file %s: %w", targetPath, err)
			}
			if written != header.Size {
				outFile.Close()
				return fmt.Errorf("archive entry %s size mismatch", header.Name)
			}
			extractedBytes += written
			if err := outFile.Close(); err != nil {
				return fmt.Errorf("close file %s: %w", targetPath, err)
			}
		default:
			return fmt.Errorf("unsupported archive entry %s", header.Name)
		}
	}
}

func hasCanonicalEvidenceLayout(root string) bool {
	if _, err := os.Stat(filepath.Join(root, "00_INDEX.json")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(root, "02_PROOFGRAPH")); err == nil {
		return true
	}
	return false
}

func hasConformanceSignature(root string) bool {
	_, err := os.Stat(filepath.Join(root, "07_ATTESTATIONS", "conformance_report.sig"))
	return err == nil
}

func normalizeVerifyArgs(args []string) ([]string, error) {
	var flags []string
	var positional []string
	valueFlags := map[string]bool{
		"--bundle":                           true,
		"-bundle":                            true,
		"--json-out":                         true,
		"-json-out":                          true,
		"--ledger-url":                       true,
		"-ledger-url":                        true,
		"--profile":                          true,
		"-profile":                           true,
		"--config":                           true,
		"-config":                            true,
		"--storage-receipt":                  true,
		"-storage-receipt":                   true,
		"--external-host-public-key":         true,
		"-external-host-public-key":          true,
		"--trusted-public-key":               true,
		"-trusted-public-key":                true,
		"--managed-agent-receipt-public-key": true,
		"-managed-agent-receipt-public-key":  true,
		"--eidas-max-age-hours":              true,
		"-eidas-max-age-hours":               true,
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if strings.Contains(arg, "=") {
				continue
			}
			if valueFlags[arg] {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("%s requires a value", arg)
				}
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positional = append(positional, arg)
	}
	return append(flags, positional...), nil
}

type onlineProofResponse struct {
	Verified            bool    `json:"verified"`
	EnvelopeID          string  `json:"envelope_id,omitempty"`
	SealedAt            string  `json:"sealed_at,omitempty"`
	SignatureValidCount int     `json:"signature_valid_count,omitempty"`
	SignatureTotalCount int     `json:"signature_total_count,omitempty"`
	AnchorIndex         *uint64 `json:"anchor_index,omitempty"`
	MerkleRoot          string  `json:"merkle_root,omitempty"`
	Error               string  `json:"error,omitempty"`
}

func verifyOnlineProof(report *verifier.VerifyReport, ledgerURL string) (*onlineProofResponse, error) {
	if ledgerURL == "" {
		ledgerURL = os.Getenv("HELM_LEDGER_URL")
	}
	if ledgerURL == "" {
		ledgerURL = "https://mindburn.org/api/proof/verify"
	}

	body, err := json.Marshal(map[string]any{
		"envelope_id": report.EnvelopeID,
		"sealed_at":   report.SealedAt,
		"merkle_root": report.MerkleRoot,
		"anchor_index": func() any {
			if report.AnchorIndex == nil {
				return nil
			}
			return *report.AnchorIndex
		}(),
		"offline_verified": report.Verified,
	})
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(ledgerURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("public proof API unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("public proof API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var proof onlineProofResponse
	if err := json.NewDecoder(resp.Body).Decode(&proof); err != nil {
		return nil, fmt.Errorf("invalid public proof response: %w", err)
	}
	return &proof, nil
}

func mergeOnlineProof(report *verifier.VerifyReport, proof *onlineProofResponse) {
	if proof.EnvelopeID != "" {
		report.EnvelopeID = proof.EnvelopeID
	}
	if proof.SealedAt != "" {
		report.SealedAt = proof.SealedAt
	}
	if proof.MerkleRoot != "" {
		report.MerkleRoot = proof.MerkleRoot
	}
	if proof.SignatureTotalCount > 0 {
		report.SignatureTotalCount = proof.SignatureTotalCount
		report.SignatureValidCount = proof.SignatureValidCount
	}
	if proof.AnchorIndex != nil {
		report.AnchorIndex = proof.AnchorIndex
	}
}

func printCompactVerifyReport(stdout io.Writer, report *verifier.VerifyReport) {
	anchor := "offline"
	if report.AnchorIndex != nil {
		anchor = fmt.Sprintf("#%d", *report.AnchorIndex)
	}
	sealed := report.SealedAt
	if sealed == "" {
		sealed = "unknown"
	}
	sealState := report.SealState
	if sealState == "" {
		sealState = "unknown"
	}
	trust := report.TrustLevel
	if trust == "" {
		trust = string(evidencepkg.EvidenceTrustProfileDevLocal)
	}
	anchorStatus := report.AnchorStatus
	if anchorStatus == "" {
		anchorStatus = anchor
	} else if anchor != "offline" && anchorStatus != anchor {
		anchorStatus = anchor + " (" + anchorStatus + ")"
	}
	storageStatus := report.StorageStatus
	if storageStatus == "" {
		storageStatus = "unknown"
	}
	_, _ = fmt.Fprintf(stdout, "envelope %s · seal %s · sig %d/%d · trust %s\n", displayEnvelopeID(report), sealState, report.SignatureValidCount, report.SignatureTotalCount, trust)
	_, _ = fmt.Fprintf(stdout, "VERIFIED · sealed %s · anchor %s · storage %s\n", sealed, anchorStatus, storageStatus)
}

func displayEnvelopeID(report *verifier.VerifyReport) string {
	if report.EnvelopeID != "" {
		return report.EnvelopeID
	}
	return "unknown"
}

func finalizeVerifyReport(report *verifier.VerifyReport) {
	failed := 0
	for _, check := range report.Checks {
		if !check.Pass {
			failed++
		}
	}
	report.IssueCount = failed
	if failed > 0 {
		report.Verified = false
		report.Summary = fmt.Sprintf("FAIL: %d/%d checks failed", failed, len(report.Checks))
		return
	}
	report.Verified = true
	report.Summary = fmt.Sprintf("PASS: %d/%d checks passed", len(report.Checks), len(report.Checks))
}

// checkEIDASAnchors verifies that every receipt in the bundle carries an
// eIDAS-qualified RFC 3161 anchor (backend == "eidas-qtsp") and that the
// integrated_time of each anchor is fresher than maxAge.
//
// Anchor receipts are looked up under <bundle>/02_PROOFGRAPH/anchors/*.json
// and as embedded shapes inside <bundle>/00_INDEX.json (key "anchor"). The
// receipt JSON shape mirrors anchor.AnchorReceipt: {backend, log_id,
// log_index, integrated_time, signature, request:{...}}.
func checkEIDASAnchors(bundleRoot string, maxAge time.Duration) []verifier.CheckResult {
	const eidasBackend = "eidas-qtsp"

	results := make([]verifier.CheckResult, 0, 4)

	// Inventory candidate anchors from disk.
	anchorsDir := filepath.Join(bundleRoot, "02_PROOFGRAPH", "anchors")
	entries, _ := os.ReadDir(anchorsDir)

	type anchorMeta struct {
		Path           string
		Backend        string
		IntegratedTime time.Time
	}
	var anchors []anchorMeta

	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		path := filepath.Join(anchorsDir, ent.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			results = append(results, verifier.CheckResult{
				Name:   "eidas:read_anchor",
				Pass:   false,
				Reason: fmt.Sprintf("cannot read %s: %v", path, err),
			})
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			results = append(results, verifier.CheckResult{
				Name:   "eidas:parse_anchor",
				Pass:   false,
				Reason: fmt.Sprintf("cannot parse %s: %v", path, err),
			})
			continue
		}
		backend, _ := doc["backend"].(string)
		ts, _ := doc["integrated_time"].(string)
		parsed, _ := time.Parse(time.RFC3339, ts)
		anchors = append(anchors, anchorMeta{Path: path, Backend: backend, IntegratedTime: parsed})
	}

	// Also check 00_INDEX.json's embedded anchor field, when present.
	if data, err := os.ReadFile(filepath.Join(bundleRoot, "00_INDEX.json")); err == nil {
		var doc map[string]any
		if json.Unmarshal(data, &doc) == nil {
			if a, ok := doc["anchor"].(map[string]any); ok {
				backend, _ := a["backend"].(string)
				ts, _ := a["integrated_time"].(string)
				parsed, _ := time.Parse(time.RFC3339, ts)
				anchors = append(anchors, anchorMeta{Path: "00_INDEX.json#anchor", Backend: backend, IntegratedTime: parsed})
			}
		}
	}

	if len(anchors) == 0 {
		results = append(results, verifier.CheckResult{
			Name:   "eidas:require",
			Pass:   false,
			Reason: "no anchor receipts found under 02_PROOFGRAPH/anchors/ or 00_INDEX.json#anchor; --require-eidas needs at least one eIDAS-qualified anchor",
		})
		return results
	}

	now := time.Now().UTC()
	hasEIDAS := false
	for _, a := range anchors {
		if a.Backend != eidasBackend {
			results = append(results, verifier.CheckResult{
				Name:   "eidas:anchor_backend",
				Pass:   false,
				Reason: fmt.Sprintf("anchor %s has backend %q, not %q", a.Path, a.Backend, eidasBackend),
			})
			continue
		}
		hasEIDAS = true
		if maxAge > 0 && !a.IntegratedTime.IsZero() && now.Sub(a.IntegratedTime) > maxAge {
			results = append(results, verifier.CheckResult{
				Name: "eidas:anchor_freshness",
				Pass: false,
				Reason: fmt.Sprintf("anchor %s integrated_time %s is older than --eidas-max-age-hours window of %s",
					a.Path, a.IntegratedTime.Format(time.RFC3339), maxAge),
			})
			continue
		}
		results = append(results, verifier.CheckResult{
			Name:   "eidas:anchor_qualified",
			Pass:   true,
			Detail: fmt.Sprintf("%s carries eIDAS-qualified anchor at %s", a.Path, a.IntegratedTime.Format(time.RFC3339)),
		})
	}

	if !hasEIDAS {
		results = append(results, verifier.CheckResult{
			Name:   "eidas:require",
			Pass:   false,
			Reason: "no anchor with backend=eidas-qtsp found",
		})
	}

	return results
}

// checkTEEAttestations enforces --require-tee on a verified bundle. The
// `platform` argument selects the strictness:
//
//   - sevsnp | tdx | nitro: every receipt must carry a tee_attestation
//     whose platform field matches.
//   - any: every receipt must carry some tee_attestation regardless of
//     platform; useful for multi-platform fleets.
//
// helm-ai-kernel receipts grow a `tee_attestation` field as the kernel-side
// receipt extension lands (Workstream A3). Until each receipt actually
// carries one, this check fails closed - which is the right default for a
// flag named `--require-`.
func checkTEEAttestations(bundleRoot string, platform string) []verifier.CheckResult {
	platform = strings.ToLower(strings.TrimSpace(platform))
	switch platform {
	case "sevsnp", "tdx", "nitro", "any":
	default:
		return []verifier.CheckResult{{
			Name:   "tee:platform",
			Pass:   false,
			Reason: fmt.Sprintf("unknown --require-tee value %q (want sevsnp|tdx|nitro|any)", platform),
		}}
	}

	receiptsDir := filepath.Join(bundleRoot, "receipts")
	entries, _ := os.ReadDir(receiptsDir)

	var results []verifier.CheckResult
	receiptsSeen := 0
	receiptsWithTEE := 0
	receiptsWrongPlatform := 0

	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		path := filepath.Join(receiptsDir, ent.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			results = append(results, verifier.CheckResult{
				Name:   "tee:read_receipt",
				Pass:   false,
				Reason: fmt.Sprintf("cannot read %s: %v", path, err),
			})
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			continue
		}
		receiptsSeen++

		att, ok := doc["tee_attestation"].(map[string]any)
		if !ok {
			results = append(results, verifier.CheckResult{
				Name:   "tee:receipt_attested",
				Pass:   false,
				Reason: fmt.Sprintf("%s missing tee_attestation field; --require-tee=%s demands it on every receipt", ent.Name(), platform),
			})
			continue
		}
		receiptsWithTEE++

		gotPlatform, _ := att["platform"].(string)
		if platform != "any" && !strings.EqualFold(gotPlatform, platform) {
			receiptsWrongPlatform++
			results = append(results, verifier.CheckResult{
				Name:   "tee:platform_match",
				Pass:   false,
				Reason: fmt.Sprintf("%s has tee_attestation.platform=%q; --require-tee=%s requires %s", ent.Name(), gotPlatform, platform, platform),
			})
			continue
		}

		results = append(results, verifier.CheckResult{
			Name:   "tee:receipt_attested",
			Pass:   true,
			Detail: fmt.Sprintf("%s carries tee_attestation platform=%s", ent.Name(), gotPlatform),
		})
	}

	if receiptsSeen == 0 {
		results = append(results, verifier.CheckResult{
			Name:   "tee:require",
			Pass:   false,
			Reason: fmt.Sprintf("no receipts found under %s; --require-tee=%s needs at least one TEE-attested receipt", receiptsDir, platform),
		})
	}

	return results
}

func init() {
	Register(Subcommand{Name: "verify", Aliases: []string{}, Usage: "Verify EvidencePack bundle ([path] --bundle, --json, --online, --require-eidas, --require-tee)", RunFn: runVerifyCmd})
}
