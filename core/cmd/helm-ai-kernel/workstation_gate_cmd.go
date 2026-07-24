// workstation_gate_cmd.go — `helm-ai-kernel workstation gate`: escalating
// shell gate. Blocked commands become pending approvals in the dev profile
// and stay fail-closed denials in the production profile.
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

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

const (
	exitGateAllow           = 0
	exitGatePendingApproval = 3
	exitGateDeny            = 126
)

func runWorkstationGateCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workstation gate", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var profileRaw, command, allowlistPath, dataDir string
	var jsonOut, requestApproval bool
	var rawURL, actor string
	cmd.StringVar(&profileRaw, "profile", string(workstation.ShellGateProfileProduction), "Gate profile: dev escalates blocked commands to pending approvals; anything else is production (deny, fail-closed)")
	cmd.StringVar(&command, "command", "", "Shell command line to gate (alternative to trailing args after --)")
	cmd.StringVar(&allowlistPath, "allowlist", "", "Shell allowlist JSON path (default <data-dir>/workstation/shell-allowlist.json)")
	cmd.StringVar(&dataDir, "data-dir", defaultSetupDataDir(), "HELM local data directory")
	cmd.BoolVar(&jsonOut, "json", false, "Print the gate decision as JSON")
	cmd.BoolVar(&requestApproval, "request-approval", false, "On a pending_approval verdict, create the approval ceremony on the kernel server")
	cmd.StringVar(&rawURL, "url", "", "Kernel server URL for --request-approval (default $HELM_KERNEL_URL or "+defaultWatchURL+")")
	cmd.StringVar(&actor, "actor", "operator.cli", "Actor recorded on the approval request")
	if err := cmd.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if strings.TrimSpace(command) == "" {
		command = strings.Join(cmd.Args(), " ")
	}
	if strings.TrimSpace(command) == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --command or trailing command args are required")
		return 2
	}
	if allowlistPath == "" {
		allowlistPath = workstation.DefaultShellAllowlistPath(dataDir)
	}
	profile := workstation.NormalizeShellGateProfile(profileRaw)
	store := workstation.NewShellAllowlistStore(allowlistPath)
	decision := workstation.GateShellCommandWithStore(profile, command, store)

	if jsonOut {
		data, _ := json.MarshalIndent(decision, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		printGateDecision(stdout, decision, store.Path())
	}

	switch decision.Verdict {
	case workstation.ShellGateVerdictAllow:
		return exitGateAllow
	case workstation.ShellGateVerdictPendingApproval:
		if !requestApproval {
			return exitGatePendingApproval
		}
		if err := requestShellGateApproval(decision, rawURL, actor, stdout); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: approval request failed: %v\n", err)
			return 1
		}
		return exitGatePendingApproval
	default:
		return exitGateDeny
	}
}

func printGateDecision(stdout io.Writer, decision workstation.ShellGateDecision, allowlistPath string) {
	_, _ = fmt.Fprintf(stdout, "%sShell Gate Decision%s\n", ColorBold, ColorReset)
	_, _ = fmt.Fprintf(stdout, "  verdict:   %s\n", decision.Verdict)
	_, _ = fmt.Fprintf(stdout, "  profile:   %s\n", decision.Profile)
	_, _ = fmt.Fprintf(stdout, "  command:   %s\n", decision.Command)
	_, _ = fmt.Fprintf(stdout, "  invoked:   %s\n", strings.Join(decision.Invoked, ", "))
	if len(decision.Blocked) > 0 {
		_, _ = fmt.Fprintf(stdout, "  blocked:   %s\n", strings.Join(decision.Blocked, ", "))
	}
	if decision.Reason != "" {
		_, _ = fmt.Fprintf(stdout, "  reason:    %s\n", decision.Reason)
	}
	_, _ = fmt.Fprintf(stdout, "  allowlist: %s\n", allowlistPath)
}

// requestShellGateApproval turns a pending_approval verdict into an approval
// ceremony on the kernel server, so `watch` can drain it.
func requestShellGateApproval(decision workstation.ShellGateDecision, rawURL, actor string, stdout io.Writer) error {
	if strings.TrimSpace(rawURL) == "" {
		rawURL = strings.TrimSpace(os.Getenv(watchURLEnv))
	}
	if rawURL == "" {
		rawURL = defaultWatchURL
	}
	apiKey, err := resolveWatchAPIKey("")
	if err != nil {
		return err
	}
	client, err := newApprovalHTTPClient(rawURL, apiKey)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ceremony, err := client.CreateApproval(ctx, createApprovalRequest{
		Subject:     "shell_command",
		Action:      "shell_operate",
		RequestedBy: actor,
		Quorum:      1,
		Reason: fmt.Sprintf("shell gate escalation (dev profile): blocked commands [%s] in %q",
			strings.Join(decision.Blocked, ", "), decision.Command),
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "  approval:  %s (pending on server)\n", ceremony.ApprovalID)
	return nil
}
