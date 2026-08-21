// watch_cmd.go provides a terminal-native approval snapshot and review loop.
// Typed APPROVE/DENY confirmation is required; the operator TUI never reduces
// a ceremony to a hotkey.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	defaultWatchURL     = "http://127.0.0.1:8080"
	watchURLEnv         = "HELM_KERNEL_URL"
	watchAdminAPIKeyEnv = "HELM_ADMIN_API_KEY"
)

const (
	watchRequestTimeout = 10 * time.Second
	maxWatchKeyFileSize = 16 << 10
)

func init() {
	Register(Subcommand{
		Name:   "watch",
		Usage:  "Review live approval state with typed APPROVE/DENY confirmation",
		RunFn:  runWatchCmd,
		HelpFn: printWatchUsage,
	})
}

func printWatchUsage(stdout io.Writer) {
	fmt.Fprintln(stdout, "Usage: helm-ai-kernel watch [--url URL] [--api-key-file FILE] [--once|--json]")
	fmt.Fprintln(stdout, "Review live approval state from the Kernel and confirm APPROVE or DENY with a second exact word.")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Notes:")
	fmt.Fprintln(stdout, "  --once and --json are snapshot-only and never prompt or change state.")
	fmt.Fprintln(stdout, "  Set HELM_ADMIN_API_KEY or use --api-key-file; there is deliberately no --api-key flag.")
}

type watchClientFactory func(rawURL, apiKey string) (approvalClient, error)

type watchRuntime struct {
	input     io.Reader
	caps      ui.Capabilities
	outputTTY bool
	newClient watchClientFactory
}

// redactingApprovalClient keeps a resolved bearer credential out of every
// server or transport error before the watch UI can render it. The wrapped
// error remains available through Unwrap so callers retain errors.Is/As
// behavior and any structured error metadata.
type redactingApprovalClient struct {
	delegate approvalClient
	secret   string
}

func (c redactingApprovalClient) ListApprovals(ctx context.Context) ([]contracts.ApprovalCeremony, error) {
	items, err := c.delegate.ListApprovals(ctx)
	return items, redactWatchError(err, c.secret)
}

func (c redactingApprovalClient) TransitionApproval(ctx context.Context, approvalID, action, expectedCeremonyHash, reason string) (contracts.ApprovalCeremony, error) {
	item, err := c.delegate.TransitionApproval(ctx, approvalID, action, expectedCeremonyHash, reason)
	return item, redactWatchError(err, c.secret)
}

type redactedWatchError struct {
	cause   error
	message string
}

func (e redactedWatchError) Error() string { return e.message }
func (e redactedWatchError) Unwrap() error { return e.cause }

func redactWatchError(err error, secret string) error {
	if err == nil || secret == "" {
		return err
	}
	message := err.Error()
	if !strings.Contains(message, secret) {
		return err
	}
	return redactedWatchError{
		cause:   err,
		message: strings.ReplaceAll(message, secret, "[REDACTED]"),
	}
}

func runWatchCmd(args []string, stdout, stderr io.Writer) int {
	caps := ui.DetectCapabilities(os.Stdin, os.Stderr, ui.TerminalOptions{
		Format: ui.FormatText,
		Color:  ui.ColorAuto,
	})
	return runWatchCmdWithRuntime(args, stdout, stderr, watchRuntime{
		input:     os.Stdin,
		caps:      caps,
		outputTTY: writerIsTerminal(stdout),
		newClient: func(rawURL, apiKey string) (approvalClient, error) {
			return newApprovalHTTPClient(rawURL, apiKey)
		},
	})
}

func runWatchCmdWithRuntime(args []string, stdout, stderr io.Writer, runtime watchRuntime) int {
	cmd := flag.NewFlagSet("watch", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var rawURL, apiKeyFile string
	var once, jsonOut bool
	cmd.StringVar(&rawURL, "url", "", "Kernel server URL (default $HELM_KERNEL_URL or "+defaultWatchURL+")")
	cmd.StringVar(&apiKeyFile, "api-key-file", "", "Path to a private file containing the admin API key")
	cmd.BoolVar(&once, "once", false, "Print one stable snapshot and exit")
	cmd.BoolVar(&jsonOut, "json", false, "Print the stable snapshot as JSON and exit")
	if err := cmd.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
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
	apiKey, err := resolveWatchAPIKey(apiKeyFile)
	if err != nil {
		writeWatchError(stderr, err)
		return 2
	}
	if runtime.newClient == nil {
		runtime.newClient = func(url, key string) (approvalClient, error) { return newApprovalHTTPClient(url, key) }
	}
	client, err := runtime.newClient(rawURL, apiKey)
	if err != nil {
		writeWatchError(stderr, redactWatchError(err, apiKey))
		return 2
	}
	client = redactingApprovalClient{delegate: client, secret: apiKey}

	// JSON and every non-terminal combination are snapshot-only. There is no
	// prompt, ANSI chrome, or state-changing path outside a real terminal.
	if jsonOut || once || !runtime.outputTTY || !runtime.caps.Interactive {
		return runWatchSnapshot(client, jsonOut, stdout, stderr)
	}
	return runWatchInteractive(client, runtime.input, stderr, runtime.caps)
}

// runWatchSnapshot always writes data to stdout and diagnostics to stderr.
// It has no human chrome, so a pipe receives a stable, parseable snapshot.
func runWatchSnapshot(client approvalClient, jsonOut bool, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), watchRequestTimeout)
	defer cancel()
	items, err := client.ListApprovals(ctx)
	if err != nil {
		writeWatchError(stderr, fmt.Errorf("cannot load approval state: %w", err))
		return 1
	}
	pending := filterPendingApprovals(items)
	if jsonOut {
		data, err := json.MarshalIndent(struct {
			Pending any `json:"pending"`
		}{Pending: pending}, "", "  ")
		if err != nil {
			writeWatchError(stderr, fmt.Errorf("encode snapshot: %w", err))
			return 1
		}
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}
	renderApprovalSnapshot(stdout, pending)
	return 0
}

// runWatchInteractive is an explicit line-oriented review session. A user
// chooses an ID and decision word, then ui.ConfirmDecision renders the full
// context and requires a second exact APPROVE or DENY word before its callback
// may call TransitionApproval.
func runWatchInteractive(client approvalClient, input io.Reader, chrome io.Writer, caps ui.Capabilities) int {
	if !caps.Interactive || input == nil {
		writeWatchError(chrome, ui.ErrNonInteractive)
		return 2
	}
	renderer := ui.NewRenderer(chrome, caps)
	reader := bufio.NewReader(input)
	model := newWatchModel(client)

	for {
		ctx, cancel := context.WithTimeout(context.Background(), watchRequestTimeout)
		err := model.refresh(ctx, time.Now())
		cancel()
		if err != nil {
			renderer.WriteTimeline("HELM watch", []ui.Step{{
				Status: ui.StatusFail,
				Title:  "Approval state could not be refreshed",
				Detail: "Actions are disabled until a fresh server snapshot succeeds.",
			}})
			writeWatchError(chrome, fmt.Errorf("cannot load approval state: %w", err))
			return 1
		}

		renderer.WriteTimeline("HELM watch", []ui.Step{
			{Status: ui.StatusPass, Title: "Fresh server-derived approval snapshot loaded"},
			{Status: ui.StatusWait, Title: "Enter an approval ID to begin a reviewed decision"},
		})
		renderApprovalSnapshot(chrome, model.pending)
		_, _ = fmt.Fprint(chrome, "Approval ID to review (blank exits): ")
		approvalID, ok, err := readWatchLine(reader)
		if err != nil {
			writeWatchError(chrome, fmt.Errorf("read approval ID: %w", err))
			return 1
		}
		if !ok || approvalID == "" {
			return 0
		}
		item, err := model.pendingApproval(approvalID)
		if err != nil {
			writeWatchError(chrome, err)
			continue
		}

		// Show the full ceremony context before asking which way to decide, so
		// the reviewer reads the requester, reason, quorum and expiry before
		// picking a side — not after.
		renderer.WriteCompletion(watchReviewCard(item))
		_, _ = fmt.Fprintf(chrome, "Decision for %s (APPROVE or DENY; blank cancels): ", terminalSafe(item.ApprovalID))
		choice, ok, err := readWatchLine(reader)
		if err != nil {
			writeWatchError(chrome, fmt.Errorf("read decision: %w", err))
			return 1
		}
		if !ok || choice == "" {
			_, _ = fmt.Fprintln(chrome, "No state change recorded.")
			continue
		}
		action, err := watchDecisionAction(choice)
		if err != nil {
			writeWatchError(chrome, err)
			continue
		}
		if block := watchActionBlockReason(item, action); block != "" {
			writeWatchError(chrome, errors.New(block))
			continue
		}

		var transitionedState string
		var transitionedReason string
		err = renderer.ConfirmDecision(reader, watchDecisionContext(item, action), func() error {
			if block := watchActionBlockReason(item, action); block != "" {
				return errors.New(block)
			}
			// Recheck under the callback: no transition is possible if the
			// snapshot became unavailable or another action is in flight.
			if _, err := model.pendingApproval(item.ApprovalID); err != nil {
				return err
			}
			model.busy = true
			defer func() { model.busy = false }()
			transitionCtx, cancel := context.WithTimeout(context.Background(), watchRequestTimeout)
			defer cancel()
			transitioned, err := client.TransitionApproval(
				transitionCtx,
				item.ApprovalID,
				strings.ToLower(string(action)),
				item.CeremonyHash,
				"operator decision via helm-ai-kernel watch",
			)
			transitionedState = string(transitioned.State)
			transitionedReason = terminalSafe(transitioned.Reason)
			return err
		})
		if err != nil {
			if errors.Is(err, ui.ErrConfirmationRequired) {
				_, _ = fmt.Fprintln(chrome, "No state change recorded: explicit confirmation did not match.")
				continue
			}
			if errors.Is(err, errWatchApprovalChanged) {
				renderer.WriteTimeline("HELM watch", []ui.Step{{
					Status: ui.StatusWait,
					Title:  "Approval changed; refresh and review again",
					Detail: "The ceremony changed after the displayed snapshot. Loading a fresh server snapshot before another action.",
				}})
				continue
			}
			writeWatchError(chrome, fmt.Errorf("approval transition was not recorded: %w", err))
			continue
		}
		expectedState := watchDecisionState(action)
		if transitionedState != expectedState {
			detail := fmt.Sprintf("Server state: %s. Refreshing state before another action.", terminalSafe(transitionedState))
			if transitionedReason != "" {
				detail = fmt.Sprintf("Server state: %s. %s Refreshing state before another action.", terminalSafe(transitionedState), transitionedReason)
			}
			renderer.WriteTimeline("HELM watch", []ui.Step{{
				Status: ui.StatusWait,
				Title:  fmt.Sprintf("%s did not reach %s state for %s", action, expectedState, terminalSafe(item.ApprovalID)),
				Detail: detail,
			}})
			continue
		}
		renderer.WriteTimeline("HELM watch", []ui.Step{{
			Status: ui.StatusPass,
			Title:  fmt.Sprintf("%s recorded for %s", action, terminalSafe(item.ApprovalID)),
			Detail: "Refreshing server state before another action.",
		}})
	}
}

func readWatchLine(reader *bufio.Reader) (string, bool, error) {
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false, err
	}
	if err != nil && line == "" {
		return "", false, nil
	}
	return strings.TrimSpace(line), true, nil
}

func watchDecisionAction(value string) (ui.DecisionAction, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case string(ui.DecisionApprove):
		return ui.DecisionApprove, nil
	case string(ui.DecisionDeny):
		return ui.DecisionDeny, nil
	default:
		return "", errors.New("decision must be APPROVE or DENY; no state change was recorded")
	}
}

func watchDecisionState(action ui.DecisionAction) string {
	if action == ui.DecisionDeny {
		return "denied"
	}
	return "approved"
}

// resolveWatchAPIKey accepts an environment key or a regular, private key
// file. There is deliberately no --api-key flag: command-line arguments are
// observable and must never carry the credential.
func resolveWatchAPIKey(apiKeyFile string) (string, error) {
	if strings.TrimSpace(apiKeyFile) == "" {
		key := strings.TrimSpace(os.Getenv(watchAdminAPIKeyEnv))
		if err := validateApprovalAPIKey(key); err != nil {
			return "", err
		}
		return key, nil
	}
	info, err := os.Lstat(apiKeyFile)
	if err != nil {
		return "", fmt.Errorf("read API key file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("API key file must be a regular file, not a symlink or special file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("API key file must not be readable by group or others (chmod 0600)")
	}
	file, err := os.Open(apiKeyFile)
	if err != nil {
		return "", fmt.Errorf("read API key file: %w", err)
	}
	defer file.Close()
	// Recheck after opening and require the same file identity. This catches a
	// replacement between Lstat and Open (including a symlink substitution).
	openedInfo, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat API key file: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 {
		return "", errors.New("API key file must remain a private regular file")
	}
	if !os.SameFile(info, openedInfo) {
		return "", errors.New("API key file changed while it was opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxWatchKeyFileSize+1))
	if err != nil {
		return "", fmt.Errorf("read API key file: %w", err)
	}
	if len(data) > maxWatchKeyFileSize {
		return "", fmt.Errorf("API key file exceeds %d bytes", maxWatchKeyFileSize)
	}
	key := strings.TrimSpace(string(data))
	if err := validateApprovalAPIKey(key); err != nil {
		return "", err
	}
	return key, nil
}

func writerIsTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func writeWatchError(w io.Writer, err error) {
	if w == nil || err == nil {
		return
	}
	_, _ = fmt.Fprintf(w, "Error: %s\n", terminalSafe(err.Error()))
}
