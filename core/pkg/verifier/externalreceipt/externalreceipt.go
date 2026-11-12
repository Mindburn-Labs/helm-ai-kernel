package externalreceipt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence/externalhost"
)

type BundleReport struct {
	// Found is true when the pack holds a receipt chain file, or a file under
	// the host evidence directories that could not be told from a damaged one.
	Found      bool     `json:"found"`
	ChainFiles []string `json:"chain_files,omitempty"`
	// ReportFiles are files named like a correlation or verification report
	// that parse as one. They are not receipt chains and are not verified;
	// they are listed so a caller can say which files it left out. Paths are
	// relative to the pack, slash-separated.
	ReportFiles  []string                           `json:"report_files,omitempty"`
	ChainReports []*externalhost.VerificationReport `json:"chain_reports,omitempty"`
	Checks       []externalhost.CheckResult         `json:"checks,omitempty"`
}

type VerifyOptions struct {
	PublicKeyHex string
}

var (
	receiptStat       = os.Stat
	receiptWalkDir    = filepath.WalkDir
	receiptRel        = filepath.Rel
	receiptVerifyFile = externalhost.VerifyFile
)

func VerifyBundle(bundleRoot string) BundleReport {
	return VerifyBundleWithOptions(bundleRoot, VerifyOptions{})
}

func VerifyBundleWithOptions(bundleRoot string, opts VerifyOptions) BundleReport {
	found := scanHostEvidence(bundleRoot)
	report := BundleReport{ChainFiles: found.chains}
	for _, file := range found.reports {
		report.ReportFiles = append(report.ReportFiles, rel(bundleRoot, file))
	}
	// A file that is there and cannot be read as a report or as a chain is a
	// failure. Skipping it by name reported the pack as having no host
	// evidence at all.
	for _, file := range found.damaged {
		report.Checks = append(report.Checks, externalhost.CheckResult{
			Name:   "external_host:report_file",
			Pass:   false,
			Status: externalhost.StatusFailed,
			Reason: fmt.Sprintf("%s is named like a correlation or verification report but does not hold one JSON object or array, so it cannot be told from a damaged receipt chain", rel(bundleRoot, file)),
		})
	}
	for _, file := range found.chains {
		chainReport, err := receiptVerifyFile(file, externalhost.VerifyOptions{RequireKey: true, PublicKeyHex: opts.PublicKeyHex})
		if err != nil {
			report.Checks = append(report.Checks, externalhost.CheckResult{
				Name:   "external_host:chain_file",
				Pass:   false,
				Status: externalhost.StatusFailed,
				Reason: fmt.Sprintf("%s: %v", rel(bundleRoot, file), err),
			})
			continue
		}
		report.ChainReports = append(report.ChainReports, chainReport)
		for _, check := range chainReport.Checks {
			check.Name = rel(bundleRoot, file) + ":" + check.Name
			report.Checks = append(report.Checks, check)
		}
	}
	report.Found = len(found.chains) > 0 || len(report.Checks) > 0
	return report
}

// FindChainFiles lists the receipt chain files under the pack's host evidence
// directories, sorted.
func FindChainFiles(bundleRoot string) []string {
	return scanHostEvidence(bundleRoot).chains
}

// hostEvidenceFiles sorts the JSON files under the host evidence directories
// into receipt chains, report sidecars and files that are neither.
type hostEvidenceFiles struct {
	chains  []string
	reports []string
	damaged []string
}

type reportFileKind int

const (
	reportFileDamaged reportFileKind = iota
	reportFileIsReport
	reportFileIsChain
)

func scanHostEvidence(bundleRoot string) hostEvidenceFiles {
	var out hostEvidenceFiles
	for _, dir := range []string{
		filepath.Join(bundleRoot, "host_evidence"),
		filepath.Join(bundleRoot, "11_HOST_EVIDENCE"),
	} {
		info, err := receiptStat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		_ = receiptWalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			name := strings.ToLower(entry.Name())
			if ext == ".json" && (strings.Contains(name, "correlation") || strings.Contains(name, "verification")) {
				// The name says report, not chain. The content decides: the
				// name alone would let any file opt out of verification.
				switch classifyReportFile(path) {
				case reportFileIsChain:
					out.chains = append(out.chains, path)
				case reportFileIsReport:
					out.reports = append(out.reports, path)
				default:
					out.damaged = append(out.damaged, path)
				}
				return nil
			}
			if ext == ".json" || ext == ".jsonl" || ext == ".ndjson" {
				out.chains = append(out.chains, path)
			}
			return nil
		})
	}
	sort.Strings(out.chains)
	sort.Strings(out.reports)
	sort.Strings(out.damaged)
	return out
}

// classifyReportFile reads a file named like a report. A file that holds host
// receipts is a chain whatever it is called; one JSON object or array without
// them is a report; anything else is damaged.
func classifyReportFile(path string) reportFileKind {
	data, err := os.ReadFile(path) // #nosec G304 -- the path comes from walking the pack's host evidence directories
	if err != nil {
		return reportFileDamaged
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var document any
	if err := decoder.Decode(&document); err != nil {
		return reportFileDamaged
	}
	// Exactly one document: trailing data makes it something else.
	if _, err := decoder.Token(); err != io.EOF {
		return reportFileDamaged
	}
	switch typed := document.(type) {
	case map[string]any:
		_, hasReceipts := typed["receipts"]
		_, isReceipt := typed["receipt_id"]
		if hasReceipts || isReceipt {
			return reportFileIsChain
		}
		return reportFileIsReport
	case []any:
		for _, item := range typed {
			if object, ok := item.(map[string]any); ok {
				if _, isReceipt := object["receipt_id"]; isReceipt {
					return reportFileIsChain
				}
			}
		}
		return reportFileIsReport
	default:
		return reportFileDamaged
	}
}

func rel(root, path string) string {
	r, err := receiptRel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(r)
}
