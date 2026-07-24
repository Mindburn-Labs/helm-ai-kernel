package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	cliui "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/riskenvelope"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/riskscan"
)

type scanPreviewFlags []string

func (f *scanPreviewFlags) String() string {
	return strings.Join(*f, ",")
}

func (f *scanPreviewFlags) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("preview path is required")
	}
	*f = append(*f, value)
	return nil
}

func runScanCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("scan", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		rootPath     string
		receiptsPath string
		cohort       string
		saltFile     string
		envelopePath string
		evidencePack string
		upload       bool
		uploadURL    string
		yes          bool
		previews     scanPreviewFlags
	)
	cmd.StringVar(&rootPath, "path", ".", "Directory to scan")
	cmd.StringVar(&receiptsPath, "from-receipts", "", "Project workstation observe/decision receipts from this directory")
	cmd.StringVar(&cohort, "cohort", string(riskenvelope.CohortUnknown), "Cohort bucket: unknown|1-10repos|11-50repos|51-200repos|201plusrepos")
	cmd.StringVar(&saltFile, "salt-file", "", "Local-only pseudonym salt file (default: user config dir)")
	cmd.StringVar(&envelopePath, "risk-envelope", "", "Write anonymized RiskEnvelope JSON")
	cmd.Var(&previews, "preview", "Write local preview (.md or .html); may be repeated")
	cmd.StringVar(&evidencePack, "evidence-pack", "", "Write anonymized scan EvidencePack tar")
	cmd.BoolVar(&upload, "upload", false, "Upload anonymized RiskEnvelope JSON")
	cmd.StringVar(&uploadURL, "upload-url", "", "Explicit upload endpoint for --upload")
	cmd.BoolVar(&yes, "yes", false, "Confirm upload after local preview is printed")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if cmd.NArg() != 0 {
		return cliui.WriteError(stderr, cliui.UsageErrorf("scan", "unexpected arguments: %s", strings.Join(cmd.Args(), " ")))
	}
	if saltFile == "" {
		var err error
		saltFile, err = defaultScanSaltFile()
		if err != nil {
			return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "scan", "resolving default salt file"))
		}
	}
	salt, err := riskenvelope.LoadOrCreateSaltFile(saltFile)
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "scan", "loading scan salt"))
	}
	opts := riskscan.BuildOptions{
		Salt:   salt,
		Cohort: riskenvelope.CohortBucket(cohort),
		Now:    time.Now().UTC(),
	}
	var envelope riskenvelope.RiskEnvelope
	if strings.TrimSpace(receiptsPath) != "" {
		envelope, err = riskscan.ScanReceipts(receiptsPath, opts)
	} else {
		envelope, err = riskscan.Scan(rootPath, opts)
	}
	if err != nil {
		if errors.Is(err, riskscan.ErrScanCoverageIncomplete) {
			return cliui.WriteError(stderr, cliui.UsageErrorf("scan", "scanning declared input: coverage could not be completed; no artifacts were written"))
		}
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "scan", "scanning declared input"))
	}
	body, err := riskscan.EnvelopeJSON(envelope)
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "scan", "building risk envelope"))
	}
	if envelopePath != "" {
		if err := writeScanFile(envelopePath, body); err != nil {
			return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "scan", "writing risk envelope"))
		}
	}

	previewPayloads := map[string][]byte{}
	for _, previewPath := range previews {
		payload, packName, err := renderPreview(previewPath, envelope)
		if err != nil {
			return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "scan", "rendering preview"))
		}
		if err := writeScanFile(previewPath, payload); err != nil {
			return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "scan", "writing preview"))
		}
		previewPayloads[packName] = payload
	}
	if evidencePack != "" {
		if err := riskscan.WriteEvidencePack(evidencePack, envelope, previewPayloads); err != nil {
			return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "scan", "writing evidence pack"))
		}
	}

	fmt.Fprintf(stdout, "RiskEnvelope: %s\n", envelope.EnvelopeID)
	fmt.Fprintf(stdout, "Content hash: %s\n", envelope.EnvelopeContentHash)
	fmt.Fprintf(stdout, "Findings: %d\n", len(envelope.Findings))
	fmt.Fprintf(stdout, "Static config files read: %d\n", envelope.Posture.StaticConfigFilesRead)

	if upload {
		if strings.TrimSpace(uploadURL) == "" {
			return cliui.WriteError(stderr, cliui.UsageErrorf("scan", "--upload-url is required with --upload"))
		}
		fmt.Fprintf(stdout, "Upload destination: %s\n", uploadURL)
		fmt.Fprintf(stdout, "Upload body hash: %s\n", riskenvelope.SHA256Ref(body))
		fmt.Fprintf(stdout, "Upload body bytes: %d\n", len(body))
		fmt.Fprintln(stdout, "Upload privacy: raw_prompts=false source_code=false secret_values=false command_bodies=false")
		if !yes {
			return cliui.WriteError(stderr, cliui.UsageErrorf("scan", "Upload not sent; rerun with --yes after reviewing the local preview."))
		}
		if err := riskscan.UploadEnvelope(context.Background(), uploadURL, body); err != nil {
			return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "scan", "uploading risk envelope"))
		}
		fmt.Fprintln(stdout, "Upload sent.")
	}
	return 0
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

func writeScanFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func defaultScanSaltFile() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "helm-ai-kernel", "scan_salt.hex"), nil
}

func init() {
	Register(Subcommand{
		Name:  "scan",
		Usage: "Local anonymized AI agent risk scan",
		RunFn: runScanCmd,
	})
}
