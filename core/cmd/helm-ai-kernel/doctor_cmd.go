// quantum_posture: doctor reports classical cryptographic setup and computes
// diagnostic SHA-256 checksums; it does not implement hybrid or post-quantum
// cryptographic controls.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

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

const doctorOnboardingSuggestion = "Run: helm-ai-kernel setup --quickstart --profile mcp --yes"

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
	fs.BoolVar(&jsonOutput, "json", false, "Output as JSON")
	fs.BoolVar(&verbose, "verbose", false, "Show detailed check info")

	if err := fs.Parse(args); err != nil {
		return 2
	}

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
	}

	results := make([]CheckResult, 0, len(checks))
	for _, check := range checks {
		results = append(results, check(verbose))
	}

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

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

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

func renderText(out io.Writer, results []CheckResult, summary doctorSummary, verbose bool) int {
	return renderTextWithCaps(out, results, summary, verbose, doctorCapabilities(out))
}

func renderTextWithCaps(out io.Writer, results []CheckResult, summary doctorSummary, verbose bool, caps ui.Capabilities) int {
	renderer := ui.NewRenderer(out, caps)
	_, _ = fmt.Fprint(out, "\nHELM Doctor -- Diagnostic Report\n\n")

	for _, r := range results {
		_, _ = fmt.Fprintf(out, "  %s %s\n", doctorStatusMarker(renderer, r.Status), r.Name)
		_, _ = fmt.Fprintf(out, "     %s\n", r.Message)

		if verbose && r.Detail != "" {
			_, _ = fmt.Fprintf(out, "     Detail: %s\n", r.Detail)
		}
		if (r.Status == statusFail || r.Status == statusWarn) && r.Suggestion != "" {
			_, _ = fmt.Fprintf(out, "     Next action: %s\n", r.Suggestion)
		}
	}

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "Summary: %s %d, %s %d, %s %d\n",
		renderer.Status(ui.StatusPass), summary.Pass,
		renderer.Status(ui.StatusWarn), summary.Warn,
		renderer.Status(ui.StatusFail), summary.Fail,
	)

	if summary.Fail > 0 {
		return 2
	}
	if summary.Warn > 0 {
		return 1
	}

	_, _ = fmt.Fprintf(out, "\n%s All checks passed. HELM is ready.\n", renderer.Status(ui.StatusPass))
	return 0
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

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

// resolveDataDir returns the canonical setup data directory, honoring HELM_DATA_DIR.
func resolveDataDir() string {
	if d := os.Getenv("HELM_DATA_DIR"); d != "" {
		return d
	}
	if d := defaultSetupDataDir(); d != "" {
		return d
	}
	return "data"
}

// resolveKeysDir returns candidate directories for Ed25519 keypairs.
func resolveKeysDir() []string {
	dirs := []string{filepath.Join(resolveDataDir(), "keys")}

	home, err := os.UserHomeDir()
	if err == nil {
		dirs = append(dirs, filepath.Join(home, ".helm", "keys"))
	}

	// Also check the root data dir for root.key (the actual convention used by lite mode).
	dirs = append(dirs, resolveDataDir())

	return dirs
}

func checkCryptoKeys(verbose bool) CheckResult {
	r := CheckResult{Name: "crypto_keys"}

	// Check for root.key / root.pub in known locations.
	for _, dir := range resolveKeysDir() {
		keyPath := filepath.Join(dir, "root.key")
		if info, err := os.Stat(keyPath); err == nil && !info.IsDir() {
			detail := fmt.Sprintf("key at %s", keyPath)
			if pubDetail := rootPublicKeyDetail(dir); pubDetail != "" {
				detail = fmt.Sprintf("key at %s (%s)", keyPath, pubDetail)
			}
			r.Status = statusPass
			r.Message = "Ed25519 keypair loaded"
			r.Detail = detail
			return r
		}

		// Also check for any .key files in a keys/ subdirectory.
		if entries, err := os.ReadDir(dir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".key") {
					r.Status = statusPass
					r.Message = "Ed25519 keypair loaded"
					r.Detail = fmt.Sprintf("key at %s", filepath.Join(dir, entry.Name()))
					return r
				}
			}
		}
	}

	r.Status = statusFail
	r.Message = "No keypair found"
	r.Suggestion = doctorOnboardingSuggestion
	return r
}

func rootPublicKeyDetail(dir string) string {
	pubPath := filepath.Join(dir, "root.pub")
	data, err := os.ReadFile(pubPath)
	if err != nil {
		return ""
	}
	pub := strings.TrimSpace(string(data))
	if pub == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(pub))
	return fmt.Sprintf("public_key_hash: sha256:%x", sum[:6])
}

func checkDataDirectory(verbose bool) CheckResult {
	r := CheckResult{Name: "data_directory"}
	dataDir := resolveDataDir()

	info, err := os.Stat(dataDir)
	if err != nil {
		r.Status = statusFail
		r.Message = "Data directory missing"
		r.Detail = dataDir
		r.Suggestion = doctorOnboardingSuggestion
		return r
	}
	if !info.IsDir() {
		r.Status = statusFail
		r.Message = "Data path exists but is not a directory"
		r.Detail = dataDir
		return r
	}

	// Check writability by attempting to create and remove a temp file.
	testPath := filepath.Join(dataDir, ".helm_doctor_probe")
	if err := os.WriteFile(testPath, []byte("probe"), 0600); err != nil {
		r.Status = statusFail
		r.Message = "Data directory not writable"
		r.Detail = fmt.Sprintf("%s: %v", dataDir, err)
		return r
	}
	_ = os.Remove(testPath)

	r.Status = statusPass
	r.Message = fmt.Sprintf("Writable at %s", dataDir)
	r.Detail = dataDir
	return r
}

func checkConfig(verbose bool) CheckResult {
	r := CheckResult{Name: "configuration"}

	// Check HELM_CONFIG_PATH first, then local helm.yaml.
	configPath := os.Getenv("HELM_CONFIG_PATH")
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			r.Status = statusPass
			r.Message = fmt.Sprintf("Loaded from %s (HELM_CONFIG_PATH)", configPath)
			r.Detail = configPath
			return r
		}
		r.Status = statusWarn
		r.Message = fmt.Sprintf("HELM_CONFIG_PATH set but file not found: %s", configPath)
		r.Suggestion = "Create the config file or unset HELM_CONFIG_PATH to use defaults"
		return r
	}

	for _, candidate := range []string{
		filepath.Join(resolveDataDir(), "quickstart", "oss_local_first_run.toml"),
		"helm.yaml", "helm.yml", ".helm.yaml",
	} {
		if _, err := os.Stat(candidate); err == nil {
			r.Status = statusPass
			r.Message = fmt.Sprintf("Loaded from %s", candidate)
			r.Detail = candidate
			return r
		}
	}

	r.Status = statusWarn
	r.Message = "No config file found, using defaults"
	r.Suggestion = doctorOnboardingSuggestion
	return r
}

func checkDatabase(verbose bool) CheckResult {
	r := CheckResult{Name: "database"}
	dataDir := resolveDataDir()

	// Check for SQLite database (lite mode).
	dbPath := filepath.Join(dataDir, "helm.db")
	if info, err := os.Stat(dbPath); err == nil && !info.IsDir() {
		size := formatBytes(info.Size())
		r.Status = statusPass
		r.Message = fmt.Sprintf("SQLite accessible at %s (%s)", dbPath, size)
		r.Detail = dbPath
		return r
	}

	// Check if DATABASE_URL is set (Postgres mode).
	if os.Getenv("DATABASE_URL") != "" {
		r.Status = statusPass
		r.Message = "DATABASE_URL configured (PostgreSQL mode)"
		r.Detail = "Connection string set via environment"
		return r
	}

	r.Status = statusFail
	r.Message = "Database not found"
	r.Suggestion = doctorOnboardingSuggestion
	return r
}

func checkPolicyBundles(verbose bool) CheckResult {
	r := CheckResult{Name: "policy_bundles"}

	policiesDirs := []string{
		filepath.Join(resolveDataDir(), "policies"),
		filepath.Join(resolveDataDir(), "quickstart"),
		filepath.Join(resolveDataDir(), "quickstart", "reference_packs"),
		"packs",
		"policies",
	}

	var total int
	var foundDir string
	for _, dir := range policiesDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if strings.HasSuffix(name, ".yaml") ||
				strings.HasSuffix(name, ".yml") ||
				strings.HasSuffix(name, ".toml") ||
				strings.HasSuffix(name, ".json") ||
				strings.HasSuffix(name, ".wasm") ||
				strings.HasSuffix(name, ".cel") ||
				strings.HasSuffix(name, ".rego") {
				total++
				if foundDir == "" {
					foundDir = dir
				}
			}
		}
	}

	if total > 0 {
		r.Status = statusPass
		r.Message = fmt.Sprintf("%d policy bundle(s) loaded", total)
		r.Detail = fmt.Sprintf("from %s", foundDir)
		return r
	}

	r.Status = statusWarn
	r.Message = "No policy bundles found -- all actions will use default policy"
	r.Suggestion = doctorOnboardingSuggestion
	return r
}

func checkEvidenceStore(verbose bool) CheckResult {
	r := CheckResult{Name: "evidence_store"}
	dataDir := resolveDataDir()

	evidenceDirs := []string{
		filepath.Join(dataDir, "evidence"),
		filepath.Join(dataDir, "artifacts"),
		"evidence",
	}

	for _, dir := range evidenceDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			r.Status = statusPass
			r.Message = fmt.Sprintf("Initialized at %s", dir)
			r.Detail = dir
			return r
		}
	}

	r.Status = statusWarn
	r.Message = "Evidence directory missing"
	r.Detail = filepath.Join(dataDir, "evidence")
	r.Suggestion = doctorOnboardingSuggestion
	return r
}

func checkPortAvailability(verbose bool) CheckResult {
	r := CheckResult{Name: "port_8080"}

	port := 8080
	if envPort := os.Getenv("HELM_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			port = p
			r.Name = fmt.Sprintf("port_%d", port)
		}
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		r.Status = statusWarn
		r.Message = fmt.Sprintf("Port %d in use (another HELM instance?)", port)
		r.Detail = err.Error()
		return r
	}
	_ = ln.Close()

	r.Status = statusPass
	r.Message = fmt.Sprintf("Port %d available", port)
	return r
}

func checkGoVersion(verbose bool) CheckResult {
	return CheckResult{
		Name:    "go_version",
		Status:  statusInfo,
		Message: runtime.Version(),
		Detail:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

func checkHELMVersion(verbose bool) CheckResult {
	return CheckResult{
		Name:    "helm_version",
		Status:  statusInfo,
		Message: displayVersion(),
		Detail:  fmt.Sprintf("commit %s, built %s", displayCommit(), displayBuildTime()),
	}
}

func checkDiskSpace(verbose bool) CheckResult {
	r := CheckResult{Name: "disk_space"}
	dataDir := resolveDataDir()

	// Resolve to an absolute path for the statfs call. If data dir does not
	// exist yet, fall back to the current working directory.
	target := dataDir
	if _, err := os.Stat(target); err != nil {
		target = "."
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		absTarget = target
	}

	available, err := availableDiskBytes(absTarget)
	if err != nil {
		r.Status = statusWarn
		r.Message = "Unable to determine disk space"
		r.Detail = err.Error()
		return r
	}

	const oneGB = uint64(1 << 30)

	availableStr := formatBytesUint64(available)
	if available < oneGB {
		r.Status = statusWarn
		r.Message = fmt.Sprintf("Low disk space: %s available", availableStr)
		r.Suggestion = "Free disk space in the data directory partition"
		return r
	}

	r.Status = statusPass
	r.Message = fmt.Sprintf("%s available", availableStr)
	r.Detail = absTarget
	return r
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func formatBytes(b int64) string {
	return formatBytesUint64(uint64(b))
}

func formatBytesUint64(b uint64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
		tb = gb * 1024
	)
	switch {
	case b >= tb:
		return fmt.Sprintf("%.1f TB", float64(b)/float64(tb))
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
