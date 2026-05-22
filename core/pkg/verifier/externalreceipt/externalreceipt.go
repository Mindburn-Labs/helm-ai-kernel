package externalreceipt

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence/externalhost"
)

type BundleReport struct {
	Found        bool                               `json:"found"`
	ChainFiles   []string                           `json:"chain_files,omitempty"`
	ChainReports []*externalhost.VerificationReport `json:"chain_reports,omitempty"`
	Checks       []externalhost.CheckResult         `json:"checks,omitempty"`
}

func VerifyBundle(bundleRoot string) BundleReport {
	files := FindChainFiles(bundleRoot)
	report := BundleReport{Found: len(files) > 0, ChainFiles: files}
	if len(files) == 0 {
		return report
	}
	for _, file := range files {
		chainReport, err := externalhost.VerifyFile(file, externalhost.VerifyOptions{RequireKey: true})
		if err != nil {
			report.Checks = append(report.Checks, externalhost.CheckResult{
				Name:   "external_host:chain_file",
				Pass:   false,
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
	return report
}

func FindChainFiles(bundleRoot string) []string {
	var out []string
	for _, dir := range []string{
		filepath.Join(bundleRoot, "host_evidence"),
		filepath.Join(bundleRoot, "11_HOST_EVIDENCE"),
	} {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			name := strings.ToLower(entry.Name())
			if ext == ".json" && (strings.Contains(name, "correlation") || strings.Contains(name, "verification")) {
				return nil
			}
			if ext == ".json" || ext == ".jsonl" || ext == ".ndjson" {
				out = append(out, path)
			}
			return nil
		})
	}
	sort.Strings(out)
	return out
}

func rel(root, path string) string {
	r, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(r)
}
