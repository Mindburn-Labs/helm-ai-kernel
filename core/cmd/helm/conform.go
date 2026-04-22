package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform/gates"
)

// runConform implements `helm conform` per §2.1.
//
// Exit codes:
//
//	0 = all gates pass
//	1 = any gate failed
//	2 = runtime error
func runConform(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("conform", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		profile      string
		jurisdiction string
		outputDir    string
		jsonOutput   bool
		signed       bool
		gateFilter   multiFlag
		level        string
	)

	cmd.StringVar(&profile, "profile", "", "Conformance profile (REQUIRED unless --level): SMB, CORE, ENTERPRISE, REGULATED_FINANCE, REGULATED_HEALTH, AGENTIC_WEB_ROUTER")
	cmd.StringVar(&jurisdiction, "jurisdiction", "", "Jurisdiction code (e.g. US, EU, APAC)")
	cmd.StringVar(&outputDir, "output", "", "Output directory for EvidencePack (default: artifacts/conformance)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output report as JSON to stdout")
	cmd.BoolVar(&signed, "signed", false, "Emit signed report artifacts (conform_report.json + .sha256 + .sig)")
	cmd.Var(&gateFilter, "gate", "Run only specific gate(s) (repeatable)")
	cmd.StringVar(&level, "level", "", "Conformance level shortcut: L1 (deterministic bytes, ProofGraph, EvidencePack) or L2 (L1 + budget, HITL, replay, tenant, envelope)")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	// Map --level to profile + gate filter
	if level != "" && profile == "" {
		switch level {
		case "L1":
			profile = "SMB"
			gateFilter = []string{"G0", "G1", "G2A"}
		case "L2":
			profile = "CORE"
			gateFilter = []string{"G0", "G1", "G2", "G2A", "G3A", "G5", "G8", "GX_ENVELOPE", "GX_TENANT"}
		default:
			_, _ = fmt.Fprintf(stderr, "Error: unknown level %q (valid: L1, L2)\n", level)
			return 2
		}
	}

	if profile == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --profile or --level is required")
		_, _ = fmt.Fprintln(stderr, "Valid profiles: SMB, CORE, ENTERPRISE, REGULATED_FINANCE, REGULATED_HEALTH, AGENTIC_WEB_ROUTER")
		_, _ = fmt.Fprintln(stderr, "Valid levels:   L1, L2")
		return 2
	}

	// Validate profile
	profileID := conform.ProfileID(profile)
	if conform.GatesForProfile(profileID) == nil && len(gateFilter) == 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unknown profile %q\n", profile)
		return 2
	}

	// Resolve project root
	projectRoot, err := os.Getwd()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot determine working directory: %v\n", err)
		return 2
	}

	// Build engine with all gates
	engine := gates.DefaultEngine()

	// Run conformance
	opts := &conform.RunOptions{
		Profile:      profileID,
		Jurisdiction: jurisdiction,
		GateFilter:   []string(gateFilter),
		ProjectRoot:  projectRoot,
		OutputDir:    outputDir,
	}

	report, err := engine.Run(opts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: conformance run failed: %v\n", err)
		return 2
	}

	// Emit signed report artifacts if requested
	if signed {
		artDir := outputDir
		if artDir == "" {
			artDir = filepath.Join(projectRoot, "artifacts", "conformance")
		}
		if err := os.MkdirAll(artDir, 0750); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot create output dir: %v\n", err)
			return 2
		}

		// Write conform_report.json
		reportData, _ := json.MarshalIndent(report, "", "  ")
		reportPath := filepath.Join(artDir, "conform_report.json")
		if err := os.WriteFile(reportPath, reportData, 0644); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot write report: %v\n", err)
			return 2
		}

		// Write conform_report.sha256
		hash := sha256.Sum256(reportData)
		hashHex := hex.EncodeToString(hash[:])
		hashPath := filepath.Join(artDir, "conform_report.sha256")
		_ = os.WriteFile(hashPath, []byte(hashHex+"  conform_report.json\n"), 0644)

		// Sign with Ed25519 if key is available, otherwise hash-based fallback
		sigPath := filepath.Join(artDir, "conform_report.sig")
		keyHex := os.Getenv("HELM_SIGNING_KEY_HEX")
		if keyHex != "" && len(keyHex) == 128 {
			// Ed25519 private key as hex (64 bytes = 128 hex chars)
			keyBytes, err := hex.DecodeString(keyHex)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "Error: invalid HELM_SIGNING_KEY_HEX: %v\n", err)
				return 2
			}
			privKey := ed25519.NewKeyFromSeed(keyBytes[:32])
			sig := ed25519.Sign(privKey, hash[:])
			sigPayload := map[string]string{
				"algorithm":   "ed25519",
				"report_hash": hashHex,
				"signature":   hex.EncodeToString(sig),
				"profile":     string(report.Profile),
				"run_id":      report.RunID,
				"verdict":     fmt.Sprintf("%v", report.Pass),
			}
			sigData, _ := json.MarshalIndent(sigPayload, "", "  ")
			_ = os.WriteFile(sigPath, sigData, 0644)
			_, _ = fmt.Fprintf(stdout, "Ed25519 signed artifacts written to %s/\n", artDir)
		} else {
			// Unsigned fallback — clearly labeled as digest-only (NOT an HMAC)
			sigPayload := map[string]string{
				"algorithm":   "sha256-digest-only",
				"report_hash": hashHex,
				"profile":     string(report.Profile),
				"run_id":      report.RunID,
				"verdict":     fmt.Sprintf("%v", report.Pass),
				"warning":     "UNSIGNED: set HELM_SIGNING_KEY_HEX for cryptographic Ed25519 signatures",
			}
			sigData, _ := json.MarshalIndent(sigPayload, "", "  ")
			_ = os.WriteFile(sigPath, sigData, 0644)
			_, _ = fmt.Fprintf(stdout, "⚠️  Unsigned digest-only artifacts written to %s/ (set HELM_SIGNING_KEY_HEX for Ed25519)\n", artDir)
		}
		_, _ = fmt.Fprintf(stdout, "  conform_report.json\n")
		_, _ = fmt.Fprintf(stdout, "  conform_report.sha256\n")
		_, _ = fmt.Fprintf(stdout, "  conform_report.sig\n")
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(report, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else if !signed {
		printConformanceReport(stdout, report)
	}

	if !report.Pass {
		return 1
	}
	return 0
}

func printConformanceReport(w io.Writer, report *conform.ConformanceReport) {
	_, _ = fmt.Fprintf(w, "HELM Conformance Report\n")
	_, _ = fmt.Fprintf(w, "───────────────────────\n")
	_, _ = fmt.Fprintf(w, "Run ID:    %s\n", report.RunID)
	_, _ = fmt.Fprintf(w, "Profile:   %s\n", report.Profile)
	_, _ = fmt.Fprintf(w, "Timestamp: %s\n", report.Timestamp.Format("2006-01-02T15:04:05Z"))
	_, _ = fmt.Fprintf(w, "Duration:  %s\n\n", report.Duration)

	for _, gr := range report.GateResults {
		status := "✅ PASS"
		if !gr.Pass {
			status = "❌ FAIL"
		}
		_, _ = fmt.Fprintf(w, "  %s  %s", status, gr.GateID)
		if len(gr.Reasons) > 0 {
			_, _ = fmt.Fprintf(w, "  [%s]", gr.Reasons[0])
			if len(gr.Reasons) > 1 {
				_, _ = fmt.Fprintf(w, " (+%d more)", len(gr.Reasons)-1)
			}
		}
		_, _ = fmt.Fprintln(w)
	}

	_, _ = fmt.Fprintln(w)
	if report.Pass {
		_, _ = fmt.Fprintf(w, "Result: ✅ PASS (%d gates)\n", len(report.GateResults))
	} else {
		failed := 0
		for _, gr := range report.GateResults {
			if !gr.Pass {
				failed++
			}
		}
		_, _ = fmt.Fprintf(w, "Result: ❌ FAIL (%d/%d gates failed)\n", failed, len(report.GateResults))
	}
}

// multiFlag allows repeatable flag values (e.g. --gate G0 --gate G1).
type multiFlag []string

func (f *multiFlag) String() string { return fmt.Sprintf("%v", *f) }
func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func init() {
	Register(Subcommand{Name: "conform", Aliases: []string{"conformance"}, Usage: "Run conformance gates (--level L1|L2 or --profile, --json)", RunFn: runConform})
}
