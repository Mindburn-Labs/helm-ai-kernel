// quantum_posture: doctor reports classical cryptographic setup and computes
// diagnostic SHA-256 checksums; it does not implement hybrid or post-quantum
// cryptographic controls.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
)

func init() {
	Register(Subcommand{
		Name:    "doctor",
		Aliases: []string{"diag"},
		Usage:   "Diagnose HELM setup (crypto, policies, connectors, config)",
		RunFn:   runDoctorCmd,
	})
}

// checkStatus represents the outcome of a single diagnostic check.
type checkStatus string

const (
	statusPass checkStatus = "pass"
	statusWarn checkStatus = "warn"
	statusFail checkStatus = "fail"
	statusInfo checkStatus = "info"
)

// CheckResult holds the outcome of a single diagnostic check.
type CheckResult struct {
	Name       string      `json:"name"`
	Status     checkStatus `json:"status"`
	Message    string      `json:"message"`
	Detail     string      `json:"detail,omitempty"`
	Suggestion string      `json:"suggestion,omitempty"`
}

const doctorOnboardingSuggestion = "Run: helm-ai-kernel setup status"

const doctorMCPScanSuggestion = "Run: helm-ai-kernel mcp scan"

// doctorSummary is the JSON-serializable summary.
type doctorSummary struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

// doctorReport is the top-level JSON output.
type doctorReport struct {
	Checks  []CheckResult `json:"checks"`
	Summary doctorSummary `json:"summary"`
	Healthy bool          `json:"healthy"`
}

// checkFunc is the signature for individual diagnostic checks.
type checkFunc func(verbose bool) CheckResult

// runDoctorCmd implements `helm-ai-kernel doctor` -- comprehensive diagnostic report.
//
// Exit codes:
//
//	0 = all healthy (no warnings, no failures)
//	1 = some warnings but no critical failures
//	2 = one or more critical failures
func runDoctorCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		jsonOutput bool
		verbose    bool
	)
	fs.BoolVar(&jsonOutput, "json", false, "Output as JSON (alias for --format=json)")
	formatFlag := ui.RegisterFormat(fs, ui.FormatText)
	fs.BoolVar(&verbose, "verbose", false, "Show detailed check info")

	if code, ok := ui.ParseFlags(fs, args, stderr, "doctor", ui.FormatText); !ok {
		return code
	}
	jsonOutput = jsonOutput || formatFlag.IsJSON()

	results := collectDoctorResults(verbose)

	// Tally summary.
	var summary doctorSummary
	for _, r := range results {
		switch r.Status {
		case statusPass:
			summary.Pass++
		case statusWarn:
			summary.Warn++
		case statusFail:
			summary.Fail++
		case statusInfo:
			summary.Pass++ // informational counts as pass
		}
	}

	healthy := summary.Fail == 0

	if jsonOutput {
		return renderJSON(stdout, results, summary, healthy)
	}
	return renderText(stdout, results, summary, verbose)
}

func renderJSON(out io.Writer, results []CheckResult, summary doctorSummary, healthy bool) int {
	report := doctorReport{
		Checks:  results,
		Summary: summary,
		Healthy: healthy,
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		_, _ = fmt.Fprintf(out, `{"error": %q}`+"\n", err.Error())
		return 2
	}
	if !healthy {
		return 2
	}
	if summary.Warn > 0 {
		return 1
	}
	return 0
}

func collectDoctorResults(verbose bool) []CheckResult {
	checks := []checkFunc{
		checkCryptoKeys,
		checkDataDirectory,
		checkConfig,
		checkDatabase,
		checkPolicyBundles,
		checkEvidenceStore,
		checkPortAvailability,
		checkGoVersion,
		checkHELMVersion,
		checkDiskSpace,
		checkSetupLifecycle,
		checkMCPConfigs,
	}
	results := make([]CheckResult, 0, len(checks))
	for _, check := range checks {
		results = append(results, check(verbose))
	}
	return results
}

func renderText(out io.Writer, results []CheckResult, summary doctorSummary, verbose bool) int {
	return renderTextWithCaps(out, results, summary, verbose, doctorCapabilities(out))
}

func renderTextWithCaps(out io.Writer, results []CheckResult, summary doctorSummary, verbose bool, caps ui.Capabilities) int {
	p := ui.NewPrinterWithCaps(out, caps)
	p.Brand(ui.BrandHeader{
		Name:    "HELM Doctor",
		Tagline: "Diagnose keys, policy, store, and ports.",
		Hint:    "Words stay intact without color. JSON twin: helm-ai-kernel doctor --json",
	})
	p.Blank()

	groups := []struct {
		title string
		names []string
	}{
		{title: "Environment", names: []string{"go_version", "helm_version", "disk_space", "port_availability"}},
		{title: "Store", names: []string{"crypto_keys", "data_directory", "database", "evidence_store"}},
		{title: "Policy", names: []string{"config", "policy_bundles"}},
	}
	seen := map[string]struct{}{}
	for _, group := range groups {
		p.Title(group.title)
		for _, name := range group.names {
			for _, r := range results {
				if r.Name != name {
					continue
				}
				seen[name] = struct{}{}
				writeDoctorRow(p, r, verbose)
			}
		}
		p.Blank()
	}
	var leftover []CheckResult
	for _, r := range results {
		if _, ok := seen[r.Name]; ok {
			continue
		}
		leftover = append(leftover, r)
	}
	if len(leftover) > 0 {
		p.Title("Findings")
		for _, r := range leftover {
			writeDoctorRow(p, r, verbose)
		}
		p.Blank()
	}

	_, _ = fmt.Fprintf(out, "Summary: %s %d, %s %d, %s %d\n",
		p.R.Status(ui.StatusPass), summary.Pass,
		p.R.Status(ui.StatusWarn), summary.Warn,
		p.R.Status(ui.StatusFail), summary.Fail,
	)

	if summary.Fail > 0 {
		return 2
	}
	if summary.Warn > 0 {
		return 1
	}

	_, _ = fmt.Fprintf(out, "\n%s All checks passed. HELM is ready.\n", p.R.Status(ui.StatusPass))
	return 0
}

func writeDoctorRow(p ui.Printer, r CheckResult, verbose bool) {
	p.Line("  %s %s", doctorStatusMarker(p.R, r.Status), r.Name)
	p.Muted("     " + r.Message)
	if verbose && r.Detail != "" {
		p.Muted("     Detail: " + r.Detail)
	}
	if (r.Status == statusFail || r.Status == statusWarn) && r.Suggestion != "" {
		p.Muted("     Next action: " + r.Suggestion)
	}
}

func doctorCapabilities(out io.Writer) ui.Capabilities {
	file, ok := out.(*os.File)
	if !ok {
		return ui.Capabilities{Width: ui.DefaultTerminalWidth}
	}
	return ui.DetectCapabilities(os.Stdin, file, ui.TerminalOptions{
		Format: ui.FormatText,
		Color:  ui.ColorAuto,
	})
}

func doctorStatusMarker(renderer ui.Renderer, status checkStatus) string {
	switch status {
	case statusPass:
		return renderer.Status(ui.StatusPass)
	case statusWarn:
		return renderer.Status(ui.StatusWarn)
	case statusFail:
		return renderer.Status(ui.StatusFail)
	case statusInfo:
		// Info is a value report, not a check outcome. The shared renderer has
		// no info state, so keep it visible without reintroducing styling.
		return "[INFO]"
	default:
		return renderer.Status(ui.StatusWarn)
	}
}
