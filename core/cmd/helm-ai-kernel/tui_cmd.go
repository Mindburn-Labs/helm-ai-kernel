package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/tui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
)

func init() {
	Register(Subcommand{
		Name:    "tui",
		Aliases: []string{"ui", "dashboard"},
		Usage:   "Open the full-screen operator TUI",
		RunFn:   runTUICommand,
		HelpFn:  printTUIUsage,
	})
}

func printTUIUsage(stdout io.Writer) {
	fmt.Fprintln(stdout, "Usage: helm-ai-kernel tui")
	fmt.Fprintln(stdout, "Open the operator TUI. Requires an interactive terminal.")
	fmt.Fprintln(stdout, "Set HELM_NO_TUI=1 to keep the text front door.")
}

func runTUICommand(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && isHelpRequest(args) {
		printTUIUsage(stdout)
		return 0
	}
	if len(args) > 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel tui")
		return 2
	}
	return runKernelTUI(stdout, stderr)
}

func shouldLaunchTUI(args []string, stdout io.Writer) bool {
	if os.Getenv("HELM_NO_TUI") != "" {
		return false
	}
	file, ok := stdout.(*os.File)
	if !ok {
		return false
	}
	if !tui.Interactive(os.Stdin, file) {
		return false
	}
	if len(args) < 2 {
		return true
	}
	switch args[1] {
	case "tui", "ui", "dashboard":
		return len(args) == 2 || !isHelpRequest(args[2:])
	default:
		return false
	}
}

func runKernelTUI(stdout, stderr io.Writer) int {
	outFile, ok := stdout.(*os.File)
	if !ok || !tui.Interactive(os.Stdin, outFile) {
		fmt.Fprintln(stderr, "Error: tui requires an interactive terminal")
		fmt.Fprintln(stderr, "  hint: unset HELM_NO_TUI, or run helm-ai-kernel help --all")
		return 2
	}
	host := tui.Host{
		Version:          displayVersion(),
		Commit:           displayCommit(),
		Commands:         tuiCommandsFromCatalog(),
		Doctor:           tuiDoctorSnapshot,
		Watch:            tuiWatchSnapshot,
		Decide:           tuiDecide,
		RunCommand:       tuiRunCommand,
		RunCommandCtx:    tuiRunCommandCtx,
		SetupSnapshot:    tuiSetupSnapshot,
		ReceiptsSnapshot: tuiReceiptsSnapshot,
		Stdin:            os.Stdin,
		Stdout:           outFile,
	}
	if err := tui.Run(host); err != nil {
		return ui.WriteError(stderr, ui.Wrapf(err, ui.ExitFailure, "tui", "operator session"))
	}
	return 0
}

func tuiRunCommand(name string, args []string) (string, string, int) {
	return tuiRunCommandCtx(context.Background(), name, args)
}

func tuiRunCommandCtx(ctx context.Context, name string, args []string) (string, string, int) {
	var stdout, stderr bytes.Buffer
	switch name {
	case "tui", "ui", "dashboard":
		fmt.Fprintln(&stdout, "Already in the operator TUI.")
		return stdout.String(), "", 0
	}
	if tui.IsListenerVerb(name, args) {
		fmt.Fprintln(&stderr, tui.ListenerRefuseMessage)
		return "", tui.RedactSecrets(stderr.String()), 2
	}
	if name == "server" && len(args) == 0 {
		name = "serve"
	}
	argv := append([]string{"helm-ai-kernel", name}, args...)
	code := RunWithContext(ctx, argv, &stdout, &stderr)
	return tui.RedactSecrets(stdout.String()), tui.RedactSecrets(stderr.String()), code
}

func tuiDecide(ctx context.Context, id, token string) (string, string, int) {
	var stdout, stderr bytes.Buffer
	action, ok := tui.MatchCeremonyToken(token)
	if !ok {
		fmt.Fprintln(&stderr, "decision must be APPROVE or DENY; no state change was recorded")
		return "", stderr.String(), 2
	}
	items, err := tuiWatchSnapshot(ctx)
	if err != nil {
		fmt.Fprintln(&stderr, tui.RedactSecrets(err.Error()))
		return "", stderr.String(), 1
	}
	var hash string
	found := false
	for _, item := range items {
		if item.ID == id {
			hash = item.Hash
			found = true
			break
		}
	}
	if !found {
		fmt.Fprintln(&stderr, "approval is not pending; no state change was recorded")
		return "", stderr.String(), 1
	}
	rawURL := strings.TrimSpace(os.Getenv(watchURLEnv))
	if rawURL == "" {
		rawURL = defaultWatchURL
	}
	apiKey, err := resolveWatchAPIKey("")
	if err != nil {
		fmt.Fprintln(&stderr, tui.RedactSecrets(err.Error()))
		return "", tui.RedactSecrets(stderr.String()), 2
	}
	httpClient, err := newApprovalHTTPClient(rawURL, apiKey)
	if err != nil {
		fmt.Fprintln(&stderr, tui.RedactSecrets(err.Error()))
		return "", stderr.String(), 1
	}
	var client approvalClient = redactingApprovalClient{delegate: httpClient, secret: apiKey}
	transitioned, err := client.TransitionApproval(ctx, id, strings.ToLower(action), hash, "operator decision via helm-ai-kernel tui ceremony")
	if err != nil {
		fmt.Fprintln(&stderr, tui.RedactSecrets(err.Error()))
		return "", stderr.String(), 1
	}
	fmt.Fprintf(&stdout, "state=%s id=%s\n", transitioned.State, transitioned.ApprovalID)
	return stdout.String(), "", 0
}

func tuiCommandsFromCatalog() []tui.Command {
	catalog := commandCatalog()
	out := make([]tui.Command, 0, len(catalog.Commands))
	for _, cmd := range catalog.Commands {
		out = append(out, tui.Command{
			Name:    cmd.Name,
			Usage:   cmd.Usage,
			Group:   cmd.Group,
			Aliases: append([]string(nil), cmd.Aliases...),
		})
	}
	return out
}

func tuiSetupSnapshot() []tui.SnapshotRow {
	targets := supportMatrix().DirectSetup
	out := make([]tui.SnapshotRow, 0, len(targets))
	for _, target := range targets {
		out = append(out, inspectSetupClientRow(target))
	}
	return out
}

func inspectSetupClientRow(target string) tui.SnapshotRow {
	opts := setupOptions{Target: target, Scope: "user", Operation: "status", NoQuickstart: true}
	var stderr bytes.Buffer
	normalized, code := normalizeSetupOptions(opts, &stderr)
	if code != 0 {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = "inspect failed"
		}
		return tui.SnapshotRow{Name: target, Status: "FAIL", Message: tui.RedactSecrets(msg)}
	}
	summary, err := buildSetupSummary(normalized)
	if err != nil {
		return tui.SnapshotRow{Name: target, Status: "FAIL", Message: tui.RedactSecrets(err.Error())}
	}
	summary.MCPInstalled = setupMCPInstalled(normalized, summary.ClientConfigPath, summary.BinaryPath)
	summary.HookInstalled = setupHookInstalled(normalized, summary.HookConfigPath, summary.BinaryPath)
	observeSetupClientState(normalized, &summary)
	assignSetupLifecycle(&summary)
	status := "WAIT"
	switch summary.ClientState {
	case "native_loaded":
		status = "PASS"
	case "absent", "planned":
		status = "WAIT"
	case "degraded", "recovery_required":
		status = "FAIL"
	default:
		if summary.ClientState != "" {
			status = "WARN"
		}
	}
	msg := summary.ClientState
	if msg == "" {
		msg = "unknown"
	}
	return tui.SnapshotRow{Name: target, Status: status, Message: msg}
}

func tuiReceiptsSnapshot() []tui.SnapshotRow {
	report := probeReceiptsEdge()
	return []tui.SnapshotRow{{
		Name:    "edge",
		Status:  report.Status,
		Message: report.Message,
	}}
}

func tuiDoctorSnapshot() []tui.Check {
	results := collectDoctorResults(false)
	out := make([]tui.Check, 0, len(results))
	for _, r := range results {
		out = append(out, tui.Check{
			Name:       r.Name,
			Status:     string(r.Status),
			Message:    tui.RedactSecrets(r.Message),
			Detail:     tui.RedactSecrets(r.Detail),
			Suggestion: tui.RedactSecrets(r.Suggestion),
		})
	}
	return out
}

func tuiWatchSnapshot(ctx context.Context) ([]tui.Approval, error) {
	rawURL := strings.TrimSpace(os.Getenv(watchURLEnv))
	if rawURL == "" {
		rawURL = defaultWatchURL
	}
	apiKey, err := resolveWatchAPIKey("")
	if err != nil {
		return nil, err
	}
	client, err := newApprovalHTTPClient(rawURL, apiKey)
	if err != nil {
		return nil, err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
	}
	items, err := client.ListApprovals(ctx)
	if err != nil {
		return nil, err
	}
	pending := filterPendingApprovals(items)
	out := make([]tui.Approval, 0, len(pending))
	for _, item := range pending {
		out = append(out, tui.Approval{
			ID:      item.ApprovalID,
			Subject: item.Subject,
			Summary: item.Action,
			State:   string(item.State),
			Hash:    item.CeremonyHash,
		})
	}
	return out, nil
}
