// Command helm-risk-scan is the local-first AI agent risk scan. It reads local
// Claude, Codex, MCP and source evidence, or workstation receipts, and emits an
// anonymized RiskEnvelope with optional local previews and a scan EvidencePack.
//
// It moved out of helm-ai-kernel in HELM-756: the scan observes configuration
// and enforces nothing, so it sits outside the kernel's trusted computing base.
// Nothing leaves the machine; the former --upload path was dropped.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/tools/riskscan/internal/riskenvelope"
	"github.com/Mindburn-Labs/helm-ai-kernel/tools/riskscan/internal/riskscan"
)

const (
	exitOK       = 0
	exitFailed   = 1
	exitUsage    = 2
	binaryName   = "helm-risk-scan"
	usageSummary = "Usage: helm-risk-scan <scan|verify> [options]"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "Error: unknown command %q\n", args[0])
		printUsage(stderr)
		return exitUsage
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, usageSummary)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  scan    Build an anonymized local RiskEnvelope for a repo or a receipts directory")
	fmt.Fprintln(w, "  verify  Check a scan EvidencePack's artifact integrity offline")
}

type previewFlags []string

func (f *previewFlags) String() string { return strings.Join(*f, ",") }

func (f *previewFlags) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("preview path is required")
	}
	*f = append(*f, value)
	return nil
}

func usageError(stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, "Error: "+format+"\n", args...)
	return exitUsage
}

func runScan(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet(binaryName+" scan", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		rootPath     string
		receiptsPath string
		cohort       string
		saltFile     string
		envelopePath string
		evidencePack string
		noUserConfig bool
		previews     previewFlags
	)
	cmd.StringVar(&rootPath, "path", ".", "Directory to scan")
	cmd.StringVar(&receiptsPath, "from-receipts", "", "Project workstation observe/decision receipts from this directory")
	cmd.StringVar(&cohort, "cohort", string(riskenvelope.CohortUnknown), "Cohort bucket: unknown|1-10repos|11-50repos|51-200repos|201plusrepos")
	cmd.StringVar(&saltFile, "salt-file", "", "Local-only pseudonym salt file (default: user config dir)")
	cmd.StringVar(&envelopePath, "risk-envelope", "", "Write anonymized RiskEnvelope JSON")
	cmd.Var(&previews, "preview", "Write local preview (.md or .html); may be repeated")
	cmd.StringVar(&evidencePack, "evidence-pack", "", "Write anonymized scan EvidencePack tar")
	cmd.BoolVar(&noUserConfig, "no-user-config", false, "Do not inspect user-level Claude, Codex, or desktop MCP config")
	if err := cmd.Parse(args); err != nil {
		return exitUsage
	}
	if cmd.NArg() != 0 {
		return usageError(stderr, "unexpected arguments: %s", strings.Join(cmd.Args(), " "))
	}
	if saltFile == "" {
		var err error
		if saltFile, err = defaultSaltFile(); err != nil {
			return usageError(stderr, "resolving default salt file: %v", err)
		}
	}
	salt, err := riskenvelope.LoadOrCreateSaltFile(saltFile)
	if err != nil {
		return usageError(stderr, "loading scan salt: %v", err)
	}
	opts := riskscan.BuildOptions{
		Salt:              salt,
		Cohort:            riskenvelope.CohortBucket(cohort),
		Now:               time.Now().UTC(),
		IncludeUserConfig: !noUserConfig,
	}
	var envelope riskenvelope.RiskEnvelope
	if strings.TrimSpace(receiptsPath) != "" {
		envelope, err = riskscan.ScanReceipts(receiptsPath, opts)
	} else {
		envelope, err = riskscan.Scan(rootPath, opts)
	}
	if err != nil {
		if errors.Is(err, riskscan.ErrScanCoverageIncomplete) {
			return usageError(stderr, "scanning declared input: coverage could not be completed; no artifacts were written")
		}
		return usageError(stderr, "scanning declared input: %v", err)
	}
	body, err := riskscan.EnvelopeJSON(envelope)
	if err != nil {
		return usageError(stderr, "building risk envelope: %v", err)
	}
	if envelopePath != "" {
		if err := writeFile(envelopePath, body); err != nil {
			return usageError(stderr, "writing risk envelope: %v", err)
		}
	}
	previewPayloads := map[string][]byte{}
	for _, previewPath := range previews {
		payload, packName, err := renderPreview(previewPath, envelope)
		if err != nil {
			return usageError(stderr, "rendering preview: %v", err)
		}
		if err := writeFile(previewPath, payload); err != nil {
			return usageError(stderr, "writing preview: %v", err)
		}
		previewPayloads[packName] = payload
	}
	if evidencePack != "" {
		if err := riskscan.WriteEvidencePack(evidencePack, envelope, previewPayloads); err != nil {
			return usageError(stderr, "writing evidence pack: %v", err)
		}
	}
	if envelope.BoundaryGrade != nil {
		fmt.Fprintf(stdout, "Boundary grade: %s — %s\n", envelope.BoundaryGrade.Letter, envelope.BoundaryGrade.Reason)
	}
	fmt.Fprintf(stdout, "RiskEnvelope: %s\n", envelope.EnvelopeID)
	fmt.Fprintf(stdout, "Content hash: %s\n", envelope.EnvelopeContentHash)
	fmt.Fprintf(stdout, "Findings: %d\n", len(envelope.Findings))
	fmt.Fprintf(stdout, "MCP servers detected: %d\n", envelope.Posture.MCPServerCount)
	fmt.Fprintf(stdout, "Static config files read: %d\n", envelope.Posture.StaticConfigFilesRead)
	return exitOK
}

func renderPreview(path string, envelope riskenvelope.RiskEnvelope) ([]byte, string, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md", ".markdown":
		payload, err := riskscan.RenderMarkdown(envelope)
		return payload, "preview/report.md", err
	case ".html", ".htm":
		payload, err := riskscan.RenderHTML(envelope)
		return payload, "preview/report.html", err
	default:
		return nil, "", fmt.Errorf("preview path must end in .md or .html: %s", path)
	}
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// defaultSaltFile keeps the path helm-ai-kernel scan used, so pseudonyms stay
// stable for anyone who scanned before the move.
func defaultSaltFile() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "helm-ai-kernel", "scan_salt.hex"), nil
}
