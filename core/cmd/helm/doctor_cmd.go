package main

import (
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
	"syscall"
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

// runDoctorCmd implements `helm doctor` -- comprehensive diagnostic report.
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
	_, _ = fmt.Fprintf(out, "\n%sHELM Doctor%s -- Diagnostic Report\n\n", ColorBold+ColorPurple, ColorReset)

	for _, r := range results {
		icon := statusIcon(r.Status)
		label := padRight(r.Name, 22)

		_, _ = fmt.Fprintf(out, "  %s %s%s%s\n", icon, ColorBold, label, ColorReset)
		_, _ = fmt.Fprintf(out, "     %s\n", r.Message)

		if verbose && r.Detail != "" {
			_, _ = fmt.Fprintf(out, "     %s%s%s\n", ColorGray, r.Detail, ColorReset)
		}
		if r.Status == statusFail && r.Suggestion != "" {
			_, _ = fmt.Fprintf(out, "     %sSuggestion: %s%s\n", ColorYellow, r.Suggestion, ColorReset)
		}
		if r.Status == statusWarn && r.Suggestion != "" {
			_, _ = fmt.Fprintf(out, "     %sSuggestion: %s%s\n", ColorYellow, r.Suggestion, ColorReset)
		}
	}

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "Summary: %s%d passed%s, %s%d warning%s, %s%d failed%s\n",
		ColorGreen, summary.Pass, ColorReset,
		warnColor(summary.Warn), summary.Warn, ColorReset,
		failColor(summary.Fail), summary.Fail, ColorReset,
	)

	if summary.Fail > 0 {
		return 2
	}
	if summary.Warn > 0 {
		return 1
	}

	_, _ = fmt.Fprintf(out, "\n%sAll checks passed. HELM is ready.%s\n", ColorGreen+ColorBold, ColorReset)
	return 0
}

func statusIcon(s checkStatus) string {
	switch s {
	case statusPass:
		return "\u2705" // check mark
	case statusWarn:
		return "\u26a0\ufe0f " // warning
	case statusFail:
		return "\u274c" // cross
	case statusInfo:
		return "\u2139\ufe0f " // info
	default:
		return "  "
	}
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func warnColor(n int) string {
	if n > 0 {
		return ColorYellow
	}
	return ColorGreen
}

func failColor(n int) string {
	if n > 0 {
		return ColorRed
	}
	return ColorGreen
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

// resolveDataDir returns the data directory, honoring HELM_DATA_DIR.
func resolveDataDir() string {
	if d := os.Getenv("HELM_DATA_DIR"); d != "" {
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
			// Found a key file. Try to read enough to extract a key ID snippet.
			detail := fmt.Sprintf("key at %s", keyPath)
			data, readErr := os.ReadFile(keyPath)
			if readErr == nil && len(data) >= 12 {
				keyID := strings.TrimSpace(string(data))
				if len(keyID) > 12 {
					keyID = keyID[:12]
				}
				detail = fmt.Sprintf("key at %s (key_id: %s...)", keyPath, keyID)
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
	r.Suggestion = "Run: helm init"
	return r
}

func checkDataDirectory(verbose bool) CheckResult {
	r := CheckResult{Name: "data_directory"}
	dataDir := resolveDataDir()

	info, err := os.Stat(dataDir)
	if err != nil {
		r.Status = statusFail
		r.Message = "Data directory missing"
		r.Detail = dataDir
		r.Suggestion = "Run: helm init"
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

	for _, candidate := range []string{"helm.yaml", "helm.yml", ".helm.yaml"} {
		if _, err := os.Stat(candidate); err == nil {
			r.Status = statusPass
			r.Message = fmt.Sprintf("Loaded from %s", candidate)
			r.Detail = candidate
			return r
		}
	}

	r.Status = statusWarn
	r.Message = "No config file found, using defaults"
	r.Suggestion = "Run: helm init"
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
	r.Suggestion = "Run: helm init"
	return r
}

func checkPolicyBundles(verbose bool) CheckResult {
	r := CheckResult{Name: "policy_bundles"}

	policiesDirs := []string{
		filepath.Join(resolveDataDir(), "policies"),
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
	r.Suggestion = "Add policy files to data/policies/ or packs/"
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
	r.Suggestion = "Run: helm init"
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

	var stat syscall.Statfs_t
	if err := syscall.Statfs(absTarget, &stat); err != nil {
		r.Status = statusWarn
		r.Message = "Unable to determine disk space"
		r.Detail = err.Error()
		return r
	}

	// Available bytes for unprivileged users.
	available := stat.Bavail * uint64(stat.Bsize)
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
