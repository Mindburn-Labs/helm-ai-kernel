// quantum_posture: hook decision receipts are signed with the classical
// Ed25519 workstation seed resolved via workstation_signing.go; no
// post-quantum or hybrid primitives are used in this file.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shellscan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

// Shell classification modes.
//
// denylist is the 0.7.x behavior: a command is allowed unless it matches a
// destructive substring. It is the default through 0.7.x so upgrades do not
// break, and remains available afterwards as the escape hatch.
//
// allowlist inverts the posture to match how the same hook already treats
// mcp__ tools — recognized read-only commands pass, everything else is routed
// to the policy engine and denied.
const (
	shellModeDenylist  = "denylist"
	shellModeAllowlist = "allowlist"
)

var (
	hookStdin = io.Reader(os.Stdin)
	hookNow   = func() time.Time { return time.Now().UTC() }
)

type hookOptions struct {
	Client          string
	DataDir         string
	SigningSeedFile string
	JSON            bool
	ShellMode       string
}

type preToolPayload struct {
	ToolName       string         `json:"tool_name"`
	ToolNameCamel  string         `json:"toolName"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolInputCamel map[string]any `json:"toolInput"`
	SessionID      string         `json:"session_id"`
	CWD            string         `json:"cwd"`
}

type hookDecisionOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

type hookClassification struct {
	ShouldDecide bool
	Class        string
	Target       string
	Action       string
	ToolID       string
	Reason       string
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
	fs.StringVar(&opts.Client, "client", "", "Client name: claude-code or codex")
	fs.StringVar(&opts.DataDir, "data-dir", opts.DataDir, "Directory for HELM local state")
	fs.StringVar(&opts.SigningSeedFile, "signing-seed-file", "", "Path to 0600 file containing a 32-byte Ed25519 seed as hex")
	fs.BoolVar(&opts.JSON, "json", false, "Reserved for structured diagnostics")
	fs.StringVar(&opts.ShellMode, "shell-mode", shellModeDenylist, "Shell classification: denylist (default) or allowlist")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	client, err := normalizeSetupTarget(opts.Client)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return 2
	}
	opts.Client = client
	switch mode := strings.ToLower(strings.TrimSpace(opts.ShellMode)); mode {
	case shellModeDenylist, shellModeAllowlist:
		opts.ShellMode = mode
	default:
		// Exit 2 blocks the tool call, so an unreadable configuration fails
		// closed rather than silently reverting to the permissive mode.
		fmt.Fprintf(stderr, "hook pre-tool: unknown --shell-mode %q (want %s or %s)\n", opts.ShellMode, shellModeDenylist, shellModeAllowlist)
		return 2
	}
	if strings.TrimSpace(opts.DataDir) != "" {
		if abs, err := filepath.Abs(opts.DataDir); err == nil {
			opts.DataDir = abs
		}
	}
	payload, err := decodePreToolPayload(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return 2
	}
	// Loaded before classification because allowlist mode needs the profile's
	// Observe.AllowedActions to decide whether to ask. A load failure denies —
	// it is reported separately from a signer failure, which the single
	// downstream error message used to misattribute.
	profile, err := loadHookPolicyProfile(opts.DataDir)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return emitHookDenyOrFail(stdout, stderr, "HELM denied operation: workstation policy profile is unavailable")
	}
	classification := classifyPreToolPayload(payload, opts.ShellMode, profile)
	if !classification.ShouldDecide {
		return 0
	}
	receipt, err := buildHookDecisionReceipt(opts, payload, classification, profile)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return emitHookDenyOrFail(stdout, stderr, "HELM denied operation: local receipt signer is unavailable")
	}
	if receipt.Verdict != contracts.WorkstationVerdictDeny {
		return 0
	}
	receiptPath, err := writeDecisionReceipt("", filepath.Join(opts.DataDir, "receipts", "hooks"), receipt)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: write receipt: %v\n", err)
		return emitHookDenyOrFail(stdout, stderr, "HELM denied operation: receipt persistence is unavailable")
	}
	return emitHookDenyOrFail(stdout, stderr, fmt.Sprintf("HELM denied %s: %s (receipt: %s)", classification.Reason, receipt.ReasonCode, receiptPath))
}

func emitHookDenyOrFail(stdout, stderr io.Writer, reason string) int {
	if err := writeHookDeny(stdout, reason); err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: emit denial: %v\n", err)
		return 2
	}
	return 0
}

func writeHookDeny(stdout io.Writer, reason string) error {
	out := hookDecisionOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       "deny",
		PermissionDecisionReason: reason,
	}}
	return json.NewEncoder(stdout).Encode(out)
}

func printHookUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: helm-ai-kernel hook pre-tool --client <claude-code|codex> [--data-dir DIR] [--signing-seed-file PATH]")
}

func decodePreToolPayload(stdin io.Reader) (preToolPayload, error) {
	var payload preToolPayload
	dec := json.NewDecoder(stdin)
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode hook payload: %w", err)
	}
	if payload.ToolName == "" {
		payload.ToolName = payload.ToolNameCamel
	}
	if payload.ToolInput == nil {
		payload.ToolInput = payload.ToolInputCamel
	}
	if payload.ToolInput == nil {
		payload.ToolInput = map[string]any{}
	}
	return payload, nil
}

// loadHookPolicyProfile reads the workstation profile from the data directory,
// falling back to the built-in observe/draft default when no file is present.
//
// The default is already a usable allowlist — five read-only actions in Observe
// and an empty Operate.Permissions that denies everything else — so allowlist
// mode works before a user edits anything.
func loadHookPolicyProfile(dataDir string) (contracts.WorkstationPolicyProfile, error) {
	if strings.TrimSpace(dataDir) == "" {
		return workstation.LoadPolicyProfileFile("")
	}
	path := filepath.Join(dataDir, "policy", "workstation.json")
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return workstation.LoadPolicyProfileFile("")
		}
		return contracts.WorkstationPolicyProfile{}, fmt.Errorf("stat policy profile %s: %w", path, err)
	}
	return workstation.LoadPolicyProfileFile(path)
}

func classifyPreToolPayload(payload preToolPayload, shellMode string, profile contracts.WorkstationPolicyProfile) hookClassification {
	tool := strings.TrimSpace(payload.ToolName)
	switch {
	case strings.EqualFold(tool, "Bash"):
		return classifyShellCommand(inputString(payload.ToolInput, "command", "cmd"), shellMode, profile)
	case strings.HasPrefix(tool, "mcp__"):
		if isHelmSelfMCPTool(tool) {
			return hookClassification{}
		}
		return hookClassification{
			ShouldDecide: true,
			Class:        "mcp",
			Target:       tool,
			Action:       "mcp_tool_call",
			ToolID:       tool,
			Reason:       "MCP tool call",
		}
	case strings.EqualFold(tool, "Edit"), strings.EqualFold(tool, "Write"), strings.EqualFold(tool, "MultiEdit"), strings.EqualFold(tool, "apply_patch"):
		target := inputString(payload.ToolInput, "file_path", "path", "target_file")
		if target == "" && strings.EqualFold(tool, "apply_patch") {
			target = sensitiveApplyPatchTarget(inputString(payload.ToolInput, "command", "cmd", "patch"))
		}
		if target == "" && strings.EqualFold(tool, "apply_patch") {
			target = "apply_patch"
		}
		if isSensitiveWriteTarget(target) {
			return hookClassification{
				ShouldDecide: true,
				Class:        "secret",
				Target:       target,
				Action:       "file_write",
				ToolID:       tool,
				Reason:       "sensitive file write",
			}
		}
	}
	return hookClassification{}
}

// classifyShellCommand decides whether a Bash call needs a policy decision.
//
// The two modes differ in fail direction, which is the whole point of the flag:
// denylist asks only about commands it recognizes as destructive, so anything
// unrecognized proceeds unrecorded; allowlist asks about everything it cannot
// establish as permitted.
func classifyShellCommand(command, shellMode string, profile contracts.WorkstationPolicyProfile) hookClassification {
	operate := hookClassification{
		ShouldDecide: true,
		Class:        "shell-operate",
		Target:       command,
		Action:       "shell_operate",
		ToolID:       "shell",
		Reason:       "shell operation",
	}

	if !strings.EqualFold(shellMode, shellModeAllowlist) {
		if isDestructiveShellCommand(command) {
			return operate
		}
		return hookClassification{}
	}

	// Ordering is load-bearing. The metacharacter check runs before allowlist
	// matching so that "git status && rm -rf /" is rejected on the chaining
	// rather than accepted on its first two tokens. Because this runs first,
	// ClassifyReadOnly only ever sees a single simple command.
	if !shellscan.StaticallyAnalyzable(command) {
		return hookClassification{
			ShouldDecide: true,
			Class:        "shell-unanalyzable",
			Target:       command,
			Action:       workstation.ActionShellUnanalyzable,
			ToolID:       "shell",
			Reason:       "shell command that cannot be statically analyzed",
		}
	}
	if action, ok := shellscan.ClassifyReadOnly(command); ok && observeActionAllowed(profile, action) {
		return hookClassification{}
	}
	return operate
}

// observeActionAllowed bridges shellscan's action IDs to the profile's
// Observe.AllowedActions. Before this existed the field was populated by the
// profile constructor and read by nothing.
func observeActionAllowed(profile contracts.WorkstationPolicyProfile, action string) bool {
	for _, allowed := range profile.Observe.AllowedActions {
		if strings.EqualFold(strings.TrimSpace(allowed), action) {
			return true
		}
	}
	return false
}

func buildHookDecisionReceipt(opts hookOptions, payload preToolPayload, classification hookClassification, profile contracts.WorkstationPolicyProfile) (*contracts.WorkstationPolicyDecisionReceipt, error) {
	effectType, effectMode, defaultAction, defaultTool := workstation.EffectDefaults(classification.Class)
	action := firstNonEmptyString(classification.Action, defaultAction)
	toolID := firstNonEmptyString(classification.ToolID, payload.ToolName, defaultTool)
	req := contracts.WorkstationDecisionRequest{
		RunID:        firstNonEmptyString(payload.SessionID, "hook-pre-tool"),
		ActorID:      "agent.local",
		WorkspaceID:  firstNonEmptyString(payload.CWD, "local-workstation"),
		AgentSurface: opts.Client,
		ToolID:       toolID,
		Action:       action,
		EffectType:   effectType,
		EffectMode:   effectMode,
		Target:       classification.Target,
		OccurredAt:   hookNow(),
		Metadata: map[string]string{
			"client": opts.Client,
			"tool":   payload.ToolName,
		},
	}
	seed, err := resolveWorkstationSigningSeed(opts.DataDir, "", opts.SigningSeedFile)
	if err != nil {
		return nil, fmt.Errorf("load workstation signing key: %w", err)
	}
	return workstation.Decide(profile, req, workstation.DecisionOptions{SigningSeed: seed})
}

func inputString(input map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := input[key]; ok {
			if s, ok := v.(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func isDestructiveShellCommand(command string) bool {
	c := strings.ToLower(strings.TrimSpace(command))
	if c == "" {
		return false
	}
	needles := []string{
		"rm -rf ",
		"rm -fr ",
		"rm -r ",
		"git reset --hard",
		"git clean -fd",
		"git clean -xdf",
		"mkfs",
		"dd if=",
		"kubectl delete",
		"docker rm -f",
		"drop table",
		"truncate table",
	}
	for _, needle := range needles {
		if strings.Contains(c, needle) || strings.HasPrefix(c, strings.TrimSpace(needle)) {
			return true
		}
	}
	return false
}

func sensitiveApplyPatchTarget(command string) string {
	for _, line := range strings.Split(command, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"*** Add File:", "*** Update File:", "*** Delete File:"} {
			if strings.HasPrefix(line, prefix) {
				target := strings.TrimSpace(strings.TrimPrefix(line, prefix))
				if isSensitiveWriteTarget(target) {
					return target
				}
			}
		}
	}
	return ""
}

func isHelmSelfMCPTool(tool string) bool {
	t := strings.ToLower(tool)
	return strings.Contains(t, "helm-ai-kernel") || strings.Contains(t, "helm_ai_kernel") || strings.Contains(t, "helm-ai-kernel-governance")
}

func isSensitiveWriteTarget(path string) bool {
	p := strings.ToLower(strings.TrimSpace(path))
	if p == "" {
		return false
	}
	sensitive := []string{
		".env",
		".pem",
		".key",
		"id_rsa",
		"id_ed25519",
		".git/",
		".git\\",
	}
	for _, needle := range sensitive {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}
