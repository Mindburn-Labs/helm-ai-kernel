package externalreceipt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence/externalhost"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/packfs"
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
	receiptStat    = func(pack *packfs.FS, name string) (fs.FileInfo, error) { return pack.Stat(name) }
	receiptWalkDir = func(pack *packfs.FS, dir string, fn fs.WalkDirFunc) error { return pack.Walk(dir, fn) }
	// receiptVerifyChain verifies the chain file name, whose bytes are data.
	receiptVerifyChain = func(_ string, data []byte, opts externalhost.VerifyOptions) (*externalhost.VerificationReport, error) {
		chain, err := externalhost.Parse(data)
		if err != nil {
			return nil, err
		}
		return externalhost.VerifyChain(chain, opts)
	}
)

func VerifyBundle(bundleRoot string) BundleReport {
	return VerifyBundleWithOptions(bundleRoot, VerifyOptions{})
}

// VerifyBundleWithOptions verifies the receipt chains under the pack's host
// evidence directories. Every file is read through one os.Root on the pack
// (package packfs): a symbolic link that leaves the pack, a file that is not
// a regular file and a file over packfs.MaxFileBytes are failed by name, never
// read.
func VerifyBundleWithOptions(bundleRoot string, opts VerifyOptions) BundleReport {
	var report BundleReport
	pack, err := packfs.Open(bundleRoot)
	if err != nil {
		return report
	}
	defer func() { _ = pack.Close() }()

	found := scanHostEvidence(pack)
	report.ChainFiles = osPaths(bundleRoot, found.chains)
	report.ReportFiles = found.reports
	// A file that is there and cannot be read as a report or as a chain is a
	// failure. Skipping it by name reported the pack as having no host
	// evidence at all.
	for _, file := range found.damaged {
		name := "external_host:report_file"
		if file.dir {
			name = "external_host:evidence_dir"
		}
		report.Checks = append(report.Checks, externalhost.CheckResult{
			Name:   name,
			Pass:   false,
			Status: externalhost.StatusFailed,
			Reason: file.reason,
		})
	}
	for _, name := range found.chains {
		data, err := pack.ReadFile(name)
		var chainReport *externalhost.VerificationReport
		if err == nil {
			chainReport, err = receiptVerifyChain(name, data, externalhost.VerifyOptions{RequireKey: true, PublicKeyHex: opts.PublicKeyHex})
		}
		if err != nil {
			report.Checks = append(report.Checks, externalhost.CheckResult{
				Name:   "external_host:chain_file",
				Pass:   false,
				Status: externalhost.StatusFailed,
				Reason: fmt.Sprintf("%s: %v", name, err),
			})
			continue
		}
		report.ChainReports = append(report.ChainReports, chainReport)
		for _, check := range chainReport.Checks {
			check.Name = name + ":" + check.Name
			report.Checks = append(report.Checks, check)
		}
	}
	report.Found = len(found.chains) > 0 || len(report.Checks) > 0
	return report
}

// FindChainFiles lists the receipt chain files under the pack's host evidence
// directories, sorted, as paths under bundleRoot.
func FindChainFiles(bundleRoot string) []string {
	pack, err := packfs.Open(bundleRoot)
	if err != nil {
		return nil
	}
	defer func() { _ = pack.Close() }()
	return osPaths(bundleRoot, scanHostEvidence(pack).chains)
}

func osPaths(root string, names []string) []string {
	if len(names) == 0 {
		return nil
	}
	paths := make([]string, len(names))
	for i, name := range names {
		paths[i] = filepath.Join(root, filepath.FromSlash(name))
	}
	return paths
}

// hostEvidenceFiles sorts the JSON files under the host evidence directories
// into receipt chains, report sidecars and files that are neither. Names are
// relative to the pack, slash-separated.
type hostEvidenceFiles struct {
	chains  []string
	reports []string
	damaged []damagedFile
}

type damagedFile struct {
	name   string
	reason string
	// dir is set for a host evidence directory the pack root refused.
	dir bool
}

type reportFileKind int

const (
	reportFileDamaged reportFileKind = iota
	reportFileIsReport
	reportFileIsChain
)

// hostEvidenceDirs are the directories a pack keeps host evidence in, in the
// order chain files are listed.
var hostEvidenceDirs = []string{"11_HOST_EVIDENCE", "host_evidence"}

func scanHostEvidence(pack *packfs.FS) hostEvidenceFiles {
	var out hostEvidenceFiles
	for _, dir := range hostEvidenceDirs {
		info, err := receiptStat(pack, dir)
		if err != nil {
			// A host evidence directory the pack root refuses (a link out of
			// the pack) is named, not taken for a missing one.
			if !errors.Is(err, fs.ErrNotExist) {
				out.damaged = append(out.damaged, damagedFile{name: dir, reason: fmt.Sprintf("%s is not read: %v", dir, err), dir: true})
			}
			continue
		}
		if !info.IsDir() {
			continue
		}
		_ = receiptWalkDir(pack, dir, func(name string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return nil
			}
			ext := strings.ToLower(path.Ext(name))
			base := strings.ToLower(entry.Name())
			if ext == ".json" && (strings.Contains(base, "correlation") || strings.Contains(base, "verification")) {
				// The name says report, not chain. The content decides: the
				// name alone would let any file opt out of verification.
				switch kind, reason := classifyReportFile(pack, name); kind {
				case reportFileIsChain:
					out.chains = append(out.chains, name)
				case reportFileIsReport:
					out.reports = append(out.reports, name)
				default:
					out.damaged = append(out.damaged, damagedFile{name: name, reason: reason})
				}
				return nil
			}
			if ext == ".json" || ext == ".jsonl" || ext == ".ndjson" {
				out.chains = append(out.chains, name)
			}
			return nil
		})
	}
	sort.Strings(out.chains)
	sort.Strings(out.reports)
	sort.Slice(out.damaged, func(i, j int) bool { return out.damaged[i].name < out.damaged[j].name })
	return out
}

// classifyReportFile reads a file named like a report, through the pack root
// and up to packfs.MaxFileBytes. A file that holds host receipts is a chain
// whatever it is called; one JSON object or array without them is a report;
// anything else is damaged, and the reason says why.
func classifyReportFile(pack *packfs.FS, name string) (reportFileKind, string) {
	data, err := pack.ReadFile(name)
	if err != nil {
		return reportFileDamaged, fmt.Sprintf("%s is named like a correlation or verification report and was not read: %v", name, err)
	}
	damaged := fmt.Sprintf("%s is named like a correlation or verification report but does not hold one JSON object or array, so it cannot be told from a damaged receipt chain", name)
	decoder := json.NewDecoder(bytes.NewReader(data))
	var document any
	if err := decoder.Decode(&document); err != nil {
		return reportFileDamaged, damaged
	}
	// Exactly one document: trailing data makes it something else.
	if _, err := decoder.Token(); err != io.EOF {
		return reportFileDamaged, damaged
	}
	switch typed := document.(type) {
	case map[string]any:
		_, hasReceipts := typed["receipts"]
		_, isReceipt := typed["receipt_id"]
		if hasReceipts || isReceipt {
			return reportFileIsChain, ""
		}
		return reportFileIsReport, ""
	case []any:
		for _, item := range typed {
			if object, ok := item.(map[string]any); ok {
				if _, isReceipt := object["receipt_id"]; isReceipt {
					return reportFileIsChain, ""
				}
			}
		}
		return reportFileIsReport, ""
	default:
		return reportFileDamaged, damaged
	}
}
