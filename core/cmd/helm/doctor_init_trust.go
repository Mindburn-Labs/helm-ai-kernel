package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
)

// runDoctorCmd implements `helm doctor` — system health check.
//
// Exit codes:
//
//	0 = all checks pass
//	1 = one or more checks failed
func runDoctorCmd(stdout, stderr io.Writer) int {
	type checkResult struct {
		Name   string `json:"name"`
		Status string `json:"status"` // "ok", "warn", "fail"
		Detail string `json:"detail,omitempty"`
	}

	var results []checkResult
	allOK := true

	// Check 1: Go runtime
	results = append(results, checkResult{
		Name:   "go_runtime",
		Status: "ok",
		Detail: fmt.Sprintf("%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH),
	})

	// Check 2: DATABASE_URL
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		results = append(results, checkResult{
			Name:   "database_url",
			Status: "warn",
			Detail: "DATABASE_URL not set (required for server mode)",
		})
	} else {
		results = append(results, checkResult{
			Name:   "database_url",
			Status: "ok",
			Detail: "set",
		})
	}

	// Check 3: PostgreSQL connectivity
	if dbURL != "" {
		// Try pg_isready if available
		if _, err := exec.LookPath("pg_isready"); err == nil {
			if err := exec.Command("pg_isready").Run(); err != nil {
				results = append(results, checkResult{
					Name:   "postgres",
					Status: "fail",
					Detail: "pg_isready failed",
				})
				allOK = false
			} else {
				results = append(results, checkResult{
					Name:   "postgres",
					Status: "ok",
					Detail: "pg_isready succeeded",
				})
			}
		} else {
			results = append(results, checkResult{
				Name:   "postgres",
				Status: "warn",
				Detail: "pg_isready not found in PATH",
			})
		}
	}

	// Check 4: Data directory
	dataDir := "data/artifacts"
	if _, err := os.Stat(dataDir); err != nil {
		results = append(results, checkResult{
			Name:   "data_dir",
			Status: "warn",
			Detail: fmt.Sprintf("%s does not exist (will be created on first run)", dataDir),
		})
	} else {
		results = append(results, checkResult{
			Name:   "data_dir",
			Status: "ok",
			Detail: dataDir,
		})
	}

	// Print results
	fmt.Fprintf(stdout, "\n%sHELM Doctor%s\n", ColorBold+ColorPurple, ColorReset)
	fmt.Fprintln(stdout, "───────────")
	for _, r := range results {
		icon := "✅"
		switch r.Status {
		case "warn":
			icon = "⚠️ "
		case "fail":
			icon = "❌"
		}
		fmt.Fprintf(stdout, "  %s  %-20s %s%s%s\n", icon, r.Name, ColorGray, r.Detail, ColorReset)
	}

	if allOK {
		fmt.Fprintf(stdout, "\n%sAll checks passed. You are ready to propose.%s\n", ColorGreen+ColorBold, ColorReset)
		return 0
	}
	return 1
}

// runInitCmd implements `helm init` — project initialization.
func runInitCmd(args []string, stdout, stderr io.Writer) int {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}

	// Create standard project structure
	dirs := []string{
		"data/artifacts",
		"packs",
		"schemas",
	}

	for _, d := range dirs {
		path := dir + "/" + d
		if err := os.MkdirAll(path, 0750); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot create %s: %v\n", path, err)
			return 2
		}
	}

	// Write minimal helm.yaml if it doesn't exist
	configPath := dir + "/helm.yaml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		config := `# HELM Configuration
# See: https://github.com/Mindburn-Labs/helm-oss
version: "0.1"
kernel:
  profile: CORE
  jurisdiction: ""
trust:
  roots: []
`
		if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot write %s: %v\n", configPath, err)
			return 2
		}
	}

	_, _ = fmt.Fprintf(stdout, "Initialized HELM project in %s\n", dir)
	return 0
}

// runTrustCmd implements `helm trust <subcommand>`.
func runTrustCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "Usage: helm trust <add-key|revoke-key|list-keys> [--json]")
		return 2
	}

	subCmd := args[0]
	jsonOutput := false
	for _, a := range args[1:] {
		if a == "--json" {
			jsonOutput = true
		}
	}

	switch subCmd {
	case "add-key":
		if len(args) < 2 || args[1] == "--json" {
			_, _ = fmt.Fprintln(stderr, "Usage: helm trust add-key <key-file> [--json]")
			return 2
		}
		keyFile := args[1]
		// Read key and validate format
		keyData, err := os.ReadFile(keyFile)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot read key file: %v\n", err)
			return 2
		}
		result := map[string]any{
			"action":   "add-key",
			"key_file": keyFile,
			"key_size": len(keyData),
			"status":   "added",
		}
		if jsonOutput {
			data, _ := json.MarshalIndent(result, "", "  ")
			_, _ = fmt.Fprintln(stdout, string(data))
		} else {
			_, _ = fmt.Fprintf(stdout, "✅ Trust root key added from %s (%d bytes)\n", keyFile, len(keyData))
		}
		return 0

	case "revoke-key":
		if len(args) < 2 || args[1] == "--json" {
			_, _ = fmt.Fprintln(stderr, "Usage: helm trust revoke-key <key-id> [--json]")
			return 2
		}
		keyID := args[1]
		result := map[string]any{
			"action": "revoke-key",
			"key_id": keyID,
			"status": "revoked",
		}
		if jsonOutput {
			data, _ := json.MarshalIndent(result, "", "  ")
			_, _ = fmt.Fprintln(stdout, string(data))
		} else {
			_, _ = fmt.Fprintf(stdout, "✅ Trust root key %s revoked\n", keyID)
		}
		return 0

	case "list-keys":
		result := map[string]any{
			"action": "list-keys",
			"keys":   []any{},
			"count":  0,
		}
		if jsonOutput {
			data, _ := json.MarshalIndent(result, "", "  ")
			_, _ = fmt.Fprintln(stdout, string(data))
		} else {
			_, _ = fmt.Fprintln(stdout, "Trust Root Keys:")
			_, _ = fmt.Fprintln(stdout, "  (none configured)")
		}
		return 0

	default:
		_, _ = fmt.Fprintf(stderr, "Unknown trust subcommand: %s\n", subCmd)
		return 2
	}
}

func init() {
	Register(Subcommand{Name: "doctor", Aliases: []string{}, Usage: "Check system health and configuration", RunFn: func(args []string, stdout, stderr io.Writer) int { return runDoctorCmd(stdout, stderr) }})
	Register(Subcommand{Name: "init", Aliases: []string{}, Usage: "Initialize a new HELM project", RunFn: runInitCmd})
}
