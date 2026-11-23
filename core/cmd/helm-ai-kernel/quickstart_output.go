package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

func writeQuickstartError(logger *slog.Logger, logFormat string, stderr io.Writer, err error, route string) {
	if logFormat == "json" {
		attrs := []any{"error", err}
		if route != "" {
			attrs = append(attrs, "next_step", route)
		}
		logger.Error("quickstart failed", attrs...)
		return
	}
	_, _ = fmt.Fprintf(stderr, "quickstart: %v\n", err)
	if route != "" {
		_, _ = fmt.Fprintf(stderr, "  %s\n", route)
	}
}

// quickstartErrorRoute turns the most common start failures into a concrete
// next command instead of a bare Go error the user has to interpret. An error
// that says what is wrong but not what to do is a dead end.
func quickstartErrorRoute(err error, opts quickstartOptions) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "address already in use"), strings.Contains(msg, "eaddrinuse"):
		return fmt.Sprintf("That port is already in use. Choose another: helm-ai-kernel quickstart --port <n> (current: %d).", opts.Port)
	case strings.Contains(msg, "permission denied"):
		return "The data or bind path is not writable by this user. Point --data-dir at a directory you own, or fix its permissions."
	case strings.Contains(msg, "bind"), strings.Contains(msg, "listen"):
		return "The Kernel could not bind its loopback address. Pass --addr 127.0.0.1 --port <n> to choose an open one."
	}
	return ""
}

func (p quickstartPrepared) summary(operation string) map[string]any {
	summary := map[string]any{
		"operation":          operation,
		"data_dir":           p.DataDir,
		"kernel_url":         p.KernelURL,
		"policy_path":        p.PolicyPath,
		"profile":            p.Profile,
		"entitlements":       []string{"OSS_CORE"},
		"planned_actions":    p.PlannedActions,
		"start_onboarding":   true,
		"requires_cloud":     false,
		"requires_docker":    false,
		"requires_model_key": false,
	}
	if p.Console {
		summary["console"] = true
	}
	if operation == "start" && p.Runtime != nil && !p.Console {
		summary["tenant_id"] = p.Runtime.TenantID
		summary["principal_id"] = p.Runtime.PrincipalID
		summary["local_session_ttl"] = time.Until(p.Runtime.ExpiresAt).String()
		summary["local_session_exchange_url"] = p.KernelURL + "/api/v1/local-session/exchange"
		if p.LocalSessionCredentialPath != "" {
			summary["local_session_credential_path"] = p.LocalSessionCredentialPath
		}
		// The bootstrap token exchanges for a local session and must never be
		// emitted in machine-readable command output, where it is commonly
		// redirected to logs or a pipe. The private local credential document
		// gives interactive clients a usable delivery path without doing so.
	}
	return summary
}

func printQuickstartUsage(stdout io.Writer) {
	fmt.Fprintln(stdout, "Usage: helm-ai-kernel quickstart [--addr ADDR] [--port PORT] [--data-dir DIR] [--profile PROFILE] [--console --console-port PORT --no-open] [--offline] [--json] [--dry-run]")
	fmt.Fprintln(stdout)
	printLocalConsoleJourney(stdout)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Quickstart logs default to text; set HELM_LOG_FORMAT=json for structured logs.")
	fmt.Fprintln(stdout, "Pass --reset --yes only to replace HELM-owned quickstart state.")
}

func printLocalConsoleJourney(w io.Writer) {
	fmt.Fprintln(w, "Local browser Console:")
	fmt.Fprintln(w, "  helm-ai-kernel quickstart --console")
	fmt.Fprintln(w, "  helm-ai-kernel quickstart --console --no-open")
	fmt.Fprintln(w, "Starts a loopback-only Kernel and verified packaged browser Console for local policy and receipt proof.")
	fmt.Fprintln(w, "Requires a Console-including packaged layout (helm-ai-kernel-<os>-<arch>-console.tar.gz or equivalent); Homebrew and raw release binaries are headless.")
	fmt.Fprintln(w, "Primary flags: --console, --console-port (0 chooses an ephemeral port), --no-open, --data-dir, --profile, --dry-run, --json.")
}

func writeQuickstartReady(stdout io.Writer, prepared quickstartPrepared, bindAddr string, port int, consoleURL string, jsonOutput bool) {
	if jsonOutput {
		summary := prepared.summary("start")
		if prepared.Console {
			summary["console_url"] = consoleURL
		}
		_ = json.NewEncoder(stdout).Encode(summary)
		return
	}
	fmt.Fprintf(stdout, "HELM quickstart ready\n\n")
	fmt.Fprintf(stdout, "Kernel:  %s\n", localKernelOrigin(bindAddr, port))
	if prepared.Console {
		fmt.Fprintf(stdout, "Console: %s\n", consoleURL)
	}
	fmt.Fprintf(stdout, "Policy:  %s\n\n", prepared.PolicyPath)
}
