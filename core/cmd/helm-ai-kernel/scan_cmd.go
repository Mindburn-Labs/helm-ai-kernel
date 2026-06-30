package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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
		fmt.Fprintf(stderr, "Unexpected scan arguments: %s\n", strings.Join(cmd.Args(), " "))
		return 2
	}
	if saltFile == "" {
		var err error
		saltFile, err = defaultScanSaltFile()
		if err != nil {
			fmt.Fprintf(stderr, "Error resolving default salt file: %v\n", err)
			return 2
		}
	}
	salt, err := riskenvelope.LoadOrCreateSaltFile(saltFile)
	if err != nil {
		fmt.Fprintf(stderr, "Error loading scan salt: %v\n", err)
		return 2
	}
	envelope, err := riskscan.Scan(rootPath, riskscan.BuildOptions{
		Salt:   salt,
		Cohort: riskenvelope.CohortBucket(cohort),
		Now:    time.Now().UTC(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error scanning %q: %v\n", rootPath, err)
		return 2
	}
	body, err := riskscan.EnvelopeJSON(envelope)
	if err != nil {
		fmt.Fprintf(stderr, "Error building risk envelope: %v\n", err)
		return 2
	}
	if envelopePath != "" {
		if err := writeScanFile(envelopePath, body); err != nil {
			fmt.Fprintf(stderr, "Error writing risk envelope: %v\n", err)
			return 2
		}
	}

	previewPayloads := map[string][]byte{}
	for _, previewPath := range previews {
		payload, packName, err := renderPreview(previewPath, envelope)
		if err != nil {
			fmt.Fprintf(stderr, "Error rendering preview: %v\n", err)
			return 2
		}
		if err := writeScanFile(previewPath, payload); err != nil {
			fmt.Fprintf(stderr, "Error writing preview: %v\n", err)
			return 2
		}
		previewPayloads[packName] = payload
	}
	if evidencePack != "" {
		if err := riskscan.WriteEvidencePack(evidencePack, envelope, previewPayloads); err != nil {
			fmt.Fprintf(stderr, "Error writing evidence pack: %v\n", err)
			return 2
		}
	}

	fmt.Fprintf(stdout, "RiskEnvelope: %s\n", envelope.EnvelopeID)
	fmt.Fprintf(stdout, "Content hash: %s\n", envelope.EnvelopeContentHash)
	fmt.Fprintf(stdout, "Findings: %d\n", len(envelope.Findings))
	fmt.Fprintf(stdout, "Static config files read: %d\n", envelope.Posture.StaticConfigFilesRead)

	if upload {
		if strings.TrimSpace(uploadURL) == "" {
			fmt.Fprintln(stderr, "Error: --upload-url is required with --upload")
			return 2
		}
		fmt.Fprintf(stdout, "Upload destination: %s\n", uploadURL)
		fmt.Fprintf(stdout, "Upload body hash: %s\n", riskenvelope.SHA256Ref(body))
		fmt.Fprintf(stdout, "Upload body bytes: %d\n", len(body))
		fmt.Fprintln(stdout, "Upload privacy: raw_prompts=false source_code=false secret_values=false command_bodies=false")
		if !yes {
			fmt.Fprintln(stderr, "Upload not sent; rerun with --yes after reviewing the local preview.")
			return 2
		}
		if err := riskscan.UploadEnvelope(context.Background(), uploadURL, body); err != nil {
			fmt.Fprintf(stderr, "Error uploading risk envelope: %v\n", err)
			return 2
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
