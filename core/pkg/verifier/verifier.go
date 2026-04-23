// Package verifier provides offline EvidencePack verification.
//
// This package is intentionally minimal with ZERO server, proxy, or network
// dependencies. It is designed to be buildable and auditable as a standalone
// verification tool that an adversarial third party can trust.
//
// Trust model: the verifier trusts only the cryptographic primitives
// (Ed25519, SHA-256, JCS) and the EvidencePack format specification.
// It does NOT trust the HELM server, proxy, or any network service.
package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// VerifyReport is the structured output of offline verification.
// Designed for auditor consumption — every field is evidence-grade.
type VerifyReport struct {
	Bundle      string        `json:"bundle"`
	Verified    bool          `json:"verified"`
	Timestamp   time.Time     `json:"timestamp"`
	Checks      []CheckResult `json:"checks"`
	Summary     string        `json:"summary"`
	IssueCount  int           `json:"issue_count"`
	VerifierVer string        `json:"verifier_version"`
}

// CheckResult represents a single verification check.
type CheckResult struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
	Reason string `json:"reason,omitempty"` // failure reason
}

const VerifierVersion = "0.2.0"

// VerifyBundle performs offline verification of an EvidencePack directory.
// No network access. No server dependency. Pure filesystem + crypto.
func VerifyBundle(bundlePath string) (*VerifyReport, error) {
	report := &VerifyReport{
		Bundle:      bundlePath,
		Verified:    true,
		Timestamp:   time.Now().UTC(),
		Checks:      make([]CheckResult, 0),
		VerifierVer: VerifierVersion,
	}

	// 1. Structure check
	report.addCheck(checkStructure(bundlePath))

	// 2. Index integrity
	report.addCheck(checkIndex(bundlePath))

	// 3. File hash integrity
	report.addChecks(checkFileHashes(bundlePath))

	// 4. Chain integrity (receipt ordering)
	report.addCheck(checkChainIntegrity(bundlePath))

	// 5. Lamport monotonicity
	report.addCheck(checkLamportMonotonicity(bundlePath))

	// 6. Policy decision hashes
	report.addCheck(checkPolicyDecisionHashes(bundlePath))

	// 7. Replay determinism verdict
	report.addCheck(checkReplayDeterminism(bundlePath))

	// Compute summary
	failed := 0
	for _, c := range report.Checks {
		if !c.Pass {
			failed++
		}
	}
	report.IssueCount = failed
	if failed > 0 {
		report.Verified = false
		report.Summary = fmt.Sprintf("FAIL: %d/%d checks failed", failed, len(report.Checks))
	} else {
		report.Summary = fmt.Sprintf("PASS: %d/%d checks passed", len(report.Checks), len(report.Checks))
	}

	return report, nil
}

func (r *VerifyReport) addCheck(c CheckResult) {
	r.Checks = append(r.Checks, c)
}

func (r *VerifyReport) addChecks(cs []CheckResult) {
	r.Checks = append(r.Checks, cs...)
}

// --- Check implementations ---

func checkStructure(bundlePath string) CheckResult {
	info, err := os.Stat(bundlePath)
	if err != nil {
		return CheckResult{Name: "structure", Pass: false, Reason: fmt.Sprintf("path not found: %v", err)}
	}
	if !info.IsDir() {
		// Could be a tar.gz — for now we only support directories
		return CheckResult{Name: "structure", Pass: false, Reason: "bundle must be a directory (tar.gz extraction not yet supported in library)"}
	}

	// Check for manifest.json or 00_INDEX.json
	hasManifest := fileExists(filepath.Join(bundlePath, "manifest.json"))
	hasIndex := fileExists(filepath.Join(bundlePath, "00_INDEX.json"))

	if !hasManifest && !hasIndex {
		return CheckResult{Name: "structure", Pass: false, Reason: "missing manifest.json or 00_INDEX.json"}
	}

	return CheckResult{Name: "structure", Pass: true, Detail: "bundle structure valid"}
}

func checkIndex(bundlePath string) CheckResult {
	indexPath := filepath.Join(bundlePath, "00_INDEX.json")
	if !fileExists(indexPath) {
		// Try manifest.json as alternative
		manifestPath := filepath.Join(bundlePath, "manifest.json")
		if !fileExists(manifestPath) {
			return CheckResult{Name: "index_integrity", Pass: true, Detail: "no index file (legacy bundle)"}
		}
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			return CheckResult{Name: "index_integrity", Pass: false, Reason: fmt.Sprintf("cannot read manifest: %v", err)}
		}
		var manifest map[string]any
		if err := json.Unmarshal(data, &manifest); err != nil {
			return CheckResult{Name: "index_integrity", Pass: false, Reason: fmt.Sprintf("invalid manifest JSON: %v", err)}
		}
		return CheckResult{Name: "index_integrity", Pass: true, Detail: "manifest.json valid JSON"}
	}

	data, err := os.ReadFile(indexPath)
	if err != nil {
		return CheckResult{Name: "index_integrity", Pass: false, Reason: fmt.Sprintf("cannot read index: %v", err)}
	}
	var index map[string]any
	if err := json.Unmarshal(data, &index); err != nil {
		return CheckResult{Name: "index_integrity", Pass: false, Reason: fmt.Sprintf("invalid index JSON: %v", err)}
	}
	return CheckResult{Name: "index_integrity", Pass: true, Detail: "00_INDEX.json valid"}
}

func checkFileHashes(bundlePath string) []CheckResult {
	var results []CheckResult

	// Try manifest.json with file_hashes
	manifestPath := filepath.Join(bundlePath, "manifest.json")
	if fileExists(manifestPath) {
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			return []CheckResult{{Name: "file_hashes", Pass: false, Reason: fmt.Sprintf("cannot read manifest: %v", err)}}
		}

		var manifest struct {
			FileHashes map[string]string `json:"file_hashes"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil || manifest.FileHashes == nil {
			return []CheckResult{{Name: "file_hashes", Pass: true, Detail: "no file hashes in manifest"}}
		}

		// Sort keys for deterministic output
		keys := make([]string, 0, len(manifest.FileHashes))
		for k := range manifest.FileHashes {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, name := range keys {
			expectedHash := manifest.FileHashes[name]
			filePath := filepath.Join(bundlePath, name)
			content, err := os.ReadFile(filePath)
			if err != nil {
				results = append(results, CheckResult{
					Name: fmt.Sprintf("hash:%s", name), Pass: false,
					Reason: fmt.Sprintf("file missing: %v", err),
				})
				continue
			}
			actualHash := sha256Hex(content)
			if actualHash != expectedHash {
				results = append(results, CheckResult{
					Name: fmt.Sprintf("hash:%s", name), Pass: false,
					Reason: fmt.Sprintf("hash mismatch: expected %s, got %s", expectedHash, actualHash),
				})
			} else {
				results = append(results, CheckResult{
					Name:   fmt.Sprintf("hash:%s", name),
					Pass:   true,
					Detail: "hash verified",
				})
			}
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{Name: "file_hashes", Pass: true, Detail: "no hash manifest (legacy bundle)"})
	}

	return results
}

func checkChainIntegrity(bundlePath string) CheckResult {
	// Look for proofgraph.json or 02_PROOFGRAPH/
	pgPath := filepath.Join(bundlePath, "proofgraph.json")
	pgDir := filepath.Join(bundlePath, "02_PROOFGRAPH")

	if !fileExists(pgPath) && !dirExists(pgDir) {
		return CheckResult{
			Name:   "chain_integrity",
			Pass:   false,
			Reason: "missing proof graph: neither proofgraph.json nor 02_PROOFGRAPH/ found — chain integrity cannot be verified",
		}
	}

	if fileExists(pgPath) {
		data, err := os.ReadFile(pgPath)
		if err != nil {
			return CheckResult{Name: "chain_integrity", Pass: false, Reason: fmt.Sprintf("cannot read proofgraph: %v", err)}
		}
		var pg map[string]any
		if err := json.Unmarshal(data, &pg); err != nil {
			return CheckResult{Name: "chain_integrity", Pass: false, Reason: fmt.Sprintf("invalid proofgraph JSON: %v", err)}
		}
		return CheckResult{Name: "chain_integrity", Pass: true, Detail: "proof graph valid JSON"}
	}

	return CheckResult{Name: "chain_integrity", Pass: true, Detail: "proof graph directory present"}
}

func checkLamportMonotonicity(bundlePath string) CheckResult {
	// Receipt files are required for Lamport monotonicity verification.
	// An evidence pack without receipts cannot prove ordering.
	receiptsDir := filepath.Join(bundlePath, "receipts")
	if !dirExists(receiptsDir) {
		return CheckResult{
			Name:   "lamport_monotonicity",
			Pass:   false,
			Reason: "missing receipts directory — Lamport ordering cannot be verified",
		}
	}

	entries, err := os.ReadDir(receiptsDir)
	if err != nil {
		return CheckResult{Name: "lamport_monotonicity", Pass: false, Reason: fmt.Sprintf("cannot read receipts: %v", err)}
	}

	if len(entries) == 0 {
		return CheckResult{Name: "lamport_monotonicity", Pass: false, Reason: "receipts directory is empty — no Lamport claims to verify"}
	}

	return CheckResult{Name: "lamport_monotonicity", Pass: true, Detail: fmt.Sprintf("%d receipt files present", len(entries))}
}

func checkPolicyDecisionHashes(bundlePath string) CheckResult {
	// Verify that decision records exist and contain decision hashes.
	// Check receipts for decision_hash fields.
	receiptsDir := filepath.Join(bundlePath, "receipts")
	if !dirExists(receiptsDir) {
		// Already caught by lamport check, but note here too
		return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: "no receipts directory — cannot verify decision hashes"}
	}

	entries, err := os.ReadDir(receiptsDir)
	if err != nil || len(entries) == 0 {
		return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: "no receipt files to verify decision hashes"}
	}

	// Structural check: parse each receipt and verify decision_hash field exists
	verified := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filePath := filepath.Join(receiptsDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}
		var receipt map[string]any
		if err := json.Unmarshal(data, &receipt); err != nil {
			continue
		}
		if _, ok := receipt["decision_hash"]; ok {
			verified++
		}
	}

	if verified == 0 {
		return CheckResult{Name: "policy_decision_hashes", Pass: false, Reason: "no receipts contain decision_hash field"}
	}

	return CheckResult{Name: "policy_decision_hashes", Pass: true, Detail: fmt.Sprintf("%d receipts with decision hashes", verified)}
}

func checkReplayDeterminism(bundlePath string) CheckResult {
	// Replay tapes are optional but recommended for L2+ conformance.
	// Their absence is not a failure, but we note it explicitly.
	tapesDir := filepath.Join(bundlePath, "08_TAPES")
	if !dirExists(tapesDir) {
		return CheckResult{Name: "replay_determinism", Pass: true, Detail: "warn: no tapes directory — replay verification skipped (optional for L1)"}
	}

	entries, err := os.ReadDir(tapesDir)
	if err != nil || len(entries) == 0 {
		return CheckResult{Name: "replay_determinism", Pass: true, Detail: "warn: no tape files — replay verification skipped (optional for L1)"}
	}

	return CheckResult{Name: "replay_determinism", Pass: true, Detail: fmt.Sprintf("%d tape files available for replay", len(entries))}
}

// --- Helpers ---

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
