// watch_cmd.go — `helm-ai-kernel watch`: terminal-native live approval
// watcher with approve/deny hotkeys.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

const (
	defaultWatchURL      = "http://127.0.0.1:8080"
	watchURLEnv          = "HELM_KERNEL_URL"
	watchAdminAPIKeyEnv  = "HELM_ADMIN_API_KEY"
	defaultWatchInterval = 2 * time.Second
)

func init() {
	Register(Subcommand{
		Name:  "watch",
		Usage: "Watch live approval state with approve/deny hotkeys (TUI; --once for a snapshot)",
		RunFn: runWatchCmd,
	})
}

func runWatchCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("watch", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var rawURL, apiKeyFile, actor string
	var interval time.Duration
	var once, jsonOut bool
	cmd.StringVar(&rawURL, "url", "", "Kernel server URL (default $HELM_KERNEL_URL or "+defaultWatchURL+")")
	cmd.StringVar(&apiKeyFile, "api-key-file", "", "Path to a 0600 file containing the admin API key (default $HELM_ADMIN_API_KEY)")
	cmd.StringVar(&actor, "actor", "operator.cli", "Actor recorded on approve/deny transitions")
	cmd.DurationVar(&interval, "interval", defaultWatchInterval, "Polling interval for server state")
	cmd.BoolVar(&once, "once", false, "Print a single snapshot and exit (no TUI)")
	cmd.BoolVar(&jsonOut, "json", false, "Print the snapshot as JSON (implies --once)")
	if err := cmd.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if rawURL == "" {
		rawURL = strings.TrimSpace(os.Getenv(watchURLEnv))
	}
	if rawURL == "" {
		rawURL = defaultWatchURL
	}
	if interval <= 0 {
		_, _ = fmt.Fprintln(stderr, "Error: --interval must be positive")
		return 2
	}

	apiKey, err := resolveWatchAPIKey(apiKeyFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	client, err := newApprovalHTTPClient(rawURL, apiKey)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	// Snapshot mode: explicit --once/--json, or non-TTY stdout (fail closed to
	// a plain snapshot rather than a broken TUI).
	if jsonOut || once || !writerIsTerminal(stdout) {
		return runWatchSnapshot(client, jsonOut, stdout, stderr)
	}

	program := tea.NewProgram(newWatchModel(client, actor, interval))
	if _, err := program.Run(); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: watch TUI failed: %v\n", err)
		return 1
	}
	return 0
}

func runWatchSnapshot(client approvalClient, jsonOut bool, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	items, err := client.ListApprovals(ctx)
	if err != nil {
		// Fail closed: a failed fetch is an error exit, never an empty list.
		_, _ = fmt.Fprintf(stderr, "Error: cannot load approval state: %v\n", err)
		return 1
	}
	if jsonOut {
		data, err := json.MarshalIndent(map[string]any{
			"refreshed_at": time.Now().UTC(),
			"pending":      filterPendingApprovals(items),
		}, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: encode snapshot: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}
	renderApprovalSnapshot(stdout, items, time.Now())
	return 0
}

// resolveWatchAPIKey reads the admin API key from --api-key-file (0600) or the
// HELM_ADMIN_API_KEY environment variable. Missing key fails closed.
func resolveWatchAPIKey(apiKeyFile string) (string, error) {
	if strings.TrimSpace(apiKeyFile) != "" {
		info, err := os.Stat(apiKeyFile)
		if err != nil {
			return "", fmt.Errorf("read API key file: %w", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("API key file %s must not be readable by group/others (chmod 0600)", apiKeyFile)
		}
		data, err := os.ReadFile(apiKeyFile)
		if err != nil {
			return "", fmt.Errorf("read API key file: %w", err)
		}
		key := strings.TrimSpace(string(data))
		if key == "" {
			return "", fmt.Errorf("API key file %s is empty", apiKeyFile)
		}
		return key, nil
	}
	key := strings.TrimSpace(os.Getenv(watchAdminAPIKeyEnv))
	if key == "" {
		return "", fmt.Errorf("admin API key is required (set %s or --api-key-file)", watchAdminAPIKeyEnv)
	}
	return key, nil
}

// writerIsTerminal reports whether w looks like an interactive terminal.
func writerIsTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
