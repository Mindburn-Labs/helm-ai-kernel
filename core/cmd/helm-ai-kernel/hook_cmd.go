// quantum_posture: the hook accepts a classical Ed25519 seed path and a
// SHA-256 profile digest; signing is handled in hook_decision.go.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shellscan"
)

var (
	hookStdin            = io.Reader(os.Stdin)
	hookWriteReceipt     = writeDecisionReceipt
	hookNow              = func() time.Time { return time.Now().UTC() }
	errHookPolicyProfile = errors.New("hook policy profile unavailable")
	errHookInputTooLarge = errors.New("hook payload exceeds the input limit")
)

type hookOptions struct {
	Client              string
	DataDir             string
	PolicyProfile       string
	PolicyProfileSHA256 string
	SigningSeedFile     string
	JSON                bool
}

func init() {
	Register(Subcommand{
		Name:  "hook",
		Usage: "Handle local agent client hooks",
		RunFn: runHookCmd,
	})
}

func runHookCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printHookUsage(stderr)
		return 2
	}
	switch args[0] {
	case "pre-tool":
		return runHookPreToolCmd(args[1:], hookStdin, stdout, stderr)
	case "help", "--help", "-h":
		printHookUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "hook: unknown subcommand %q\n", args[0])
		printHookUsage(stderr)
		return 2
	}
}

func runHookPreToolCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts := hookOptions{DataDir: defaultSetupDataDir()}
	fs := flag.NewFlagSet("hook pre-tool", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.Client, "client", "", "Client name: claude-code, codex, hermes, or deepseek")
	fs.StringVar(&opts.DataDir, "data-dir", opts.DataDir, "Directory for HELM local state")
	fs.StringVar(&opts.PolicyProfile, "policy-profile", "", "Policy profile JSON path")
	fs.StringVar(&opts.PolicyProfileSHA256, "policy-profile-sha256", "", "Approved SHA-256 digest for the policy profile")
	fs.StringVar(&opts.SigningSeedFile, "signing-seed-file", "", "Path to 0600 file containing a 32-byte Ed25519 seed as hex")
	fs.BoolVar(&opts.JSON, "json", false, "Reserved for structured diagnostics")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	client, err := normalizeSetupTarget(opts.Client)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return 2
	}
	opts.Client = client
	if strings.TrimSpace(opts.DataDir) != "" {
		if abs, err := filepath.Abs(opts.DataDir); err == nil {
			opts.DataDir = abs
		}
	}
	payload, err := decodePreToolPayload(stdin)
	var classifications []hookClassification
	var oversized *hookOversizedPayload
	switch {
	case errors.As(err, &oversized):
		payload = preToolPayload{ToolName: oversized.tool, ToolInput: map[string]any{}}
		classifications = []hookClassification{oversizedToolCallClassification(oversized)}
	case err != nil:
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return 2
	default:
		classifications = classifyBeforeDeadline(payload, workstationPathGuard(opts.DataDir, opts.SigningSeedFile, opts.PolicyProfile))
	}
	if len(classifications) == 0 {
		// An unclassified call is successful progress, so it breaks any
		// consecutive-denial run without changing the fail-closed policy path.
		recordHookDoomLoopOutcome(opts, payload, hookClassification{}, false, stderr)
		return 0
	}
	return decideHookCall(opts, payload, classifications, stdout, stderr)
}

// hookClassificationDeadline bounds how long the hook classifies one call,
// well under the 30 s timeout setup installs: a client may run a call whose
// hook outlives its timeout. hookClassify is the classifier, replaced in
// tests.
var (
	hookClassificationDeadline = 10 * time.Second
	hookClassify               = classifyPreToolPayloads
)

// classifyBeforeDeadline classifies a call, or refuses it as reaching trust
// material when classifying takes longer than the deadline: what the hook
// could not finish reading must not pass under any profile. At the deadline
// the guard is stopped, which ends the classifier's work on the call. A
// classifier that panics is refused the same way, so the hook still decides
// the call and signs a receipt for it.
func classifyBeforeDeadline(payload preToolPayload, guard *shellscan.PathGuard) []hookClassification {
	done, classify := make(chan []hookClassification, 1), hookClassify
	go func() {
		defer func() {
			if failure := recover(); failure != nil {
				done <- trustMaterialClassification(strings.TrimSpace(payload.ToolName), "classification panic", fmt.Sprintf("a call the hook could not classify (the classifier panicked: %v), taken as reaching HELM signing or trust material", failure), nil)
			}
		}()
		done <- classify(payload, guard)
	}()
	timer := time.NewTimer(hookClassificationDeadline)
	defer timer.Stop()
	select {
	case classifications := <-done:
		return classifications
	case <-timer.C:
		guard.Stop()
		return trustMaterialClassification(strings.TrimSpace(payload.ToolName), "classification deadline", fmt.Sprintf("a call the hook did not finish classifying within %s, taken as reaching HELM signing or trust material", hookClassificationDeadline), nil)
	}
}

func printHookUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: helm-ai-kernel hook pre-tool --client <claude-code|codex|hermes|deepseek> [--data-dir DIR] [--policy-profile PATH --policy-profile-sha256 SHA256] [--signing-seed-file PATH]")
}
