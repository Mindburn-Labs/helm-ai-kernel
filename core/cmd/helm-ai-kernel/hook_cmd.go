package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

var (
	hookStdin = io.Reader(os.Stdin)
	hookNow   = func() time.Time { return time.Now().UTC() }
)

type hookOptions struct {
	Client  string
	DataDir string
	JSON    bool
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
	normalizedDataDir, err := normalizeSetupDataDir(opts.DataDir)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: invalid --data-dir: %v\n", err)
		return 2
	}
	opts.DataDir = normalizedDataDir
	if opts.Client == "codex" {
		recoveryRequired, recoveryErr := setupRecoveryRequired(opts.DataDir)
		if recoveryErr != nil || recoveryRequired {
			reason := "HELM local Codex setup recovery is pending; tool use is denied until `setup recover` completes"
			if recoveryErr != nil {
				reason = "HELM local Codex setup recovery state is invalid; tool use is denied until it is inspected"
				fmt.Fprintf(stderr, "hook pre-tool: inspect Codex setup recovery state: %v\n", recoveryErr)
			}
			_ = json.NewEncoder(stdout).Encode(hookDecisionOutput{HookSpecificOutput: hookSpecificOutput{
				HookEventName:            "PreToolUse",
				PermissionDecision:       "deny",
				PermissionDecisionReason: reason,
			}})
			return 0
		}
		if err := requireCodexProjectRuntimeAdmission(opts.DataDir); err != nil {
			fmt.Fprintf(stderr, "hook pre-tool: inspect Codex project runtime provenance: %v\n", err)
			return emitHookDeny(stdout, "HELM local Codex setup provenance is invalid; tool use is denied until it is repaired")
		}
	}
	payload, err := decodePreToolPayload(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return emitHookDeny(stdout, "HELM could not decode the selected tool effect; tool use is denied")
	}
	classification := classifyPreToolPayload(payload)
	if !classification.ShouldDecide {
		return 0
	}
	receipt, err := buildHookDecisionReceipt(opts, payload, classification)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return emitHookDeny(stdout, "HELM could not evaluate the selected tool effect; tool use is denied")
	}
	if receipt.Verdict != contracts.WorkstationVerdictDeny {
		return 0
	}
	receiptPath, err := writeHookDecisionReceipt(opts.DataDir, receipt)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: write receipt: %v\n", err)
		return emitHookDeny(stdout, "HELM denied the selected tool effect because its decision receipt could not be persisted")
	}
	reason := fmt.Sprintf("HELM denied %s: %s (receipt: %s)", classification.Reason, receipt.ReasonCode, receiptPath)
	out := hookDecisionOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       "deny",
		PermissionDecisionReason: reason,
	}}
	_ = json.NewEncoder(stdout).Encode(out)
	return 0
}

// emitHookDeny deliberately returns the hook's successful protocol exit code:
// clients consume the structured deny decision, while a non-zero command exit
// is client-version dependent and must never become an accidental allow.
func emitHookDeny(stdout io.Writer, reason string) int {
	_ = json.NewEncoder(stdout).Encode(hookDecisionOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       "deny",
		PermissionDecisionReason: reason,
	}})
	return 0
}

// writeHookDecisionReceipt confines hook-generated receipts to the already
// normalized HELM data directory. The generic workstation writer deliberately
// supports arbitrary operator-selected --out paths, so it must not be used by
// an unattended client hook.
func writeHookDecisionReceipt(dataDir string, receipt *contracts.WorkstationPolicyDecisionReceipt) (string, error) {
	if receipt == nil || !safeHookDecisionFilename(receipt.DecisionID) {
		return "", fmt.Errorf("hook decision receipt id is invalid")
	}
	receiptDir := filepath.Join(dataDir, "receipts", "hooks")
	if err := ensureSetupAuthoritySubdirectory(dataDir, filepath.Join("receipts", "hooks")); err != nil {
		return "", fmt.Errorf("prepare hook receipt directory: %w", err)
	}
	data, err := canonicalize.JCS(receipt)
	if err != nil {
		return "", err
	}
	path := filepath.Join(receiptDir, receipt.DecisionID+".json")
	if filepath.Base(path) != receipt.DecisionID+".json" {
		return "", fmt.Errorf("hook decision receipt path escapes its data directory")
	}
	if err := writeSetupPrivateFile(path, append(data, '\n')); err != nil {
		return "", err
	}
	return path, nil
}

func safeHookDecisionFilename(value string) bool {
	if value == "" || filepath.Base(value) != value || strings.ContainsRune(value, '\x00') {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '-') {
			return false
		}
	}
	return true
}

func printHookUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: helm-ai-kernel hook pre-tool --client <claude-code|codex> [--data-dir DIR]")
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
	payload.ToolName = strings.TrimSpace(payload.ToolName)
	if payload.ToolName == "" {
		return payload, fmt.Errorf("hook payload is missing tool_name")
	}
	if payload.ToolInput == nil {
		payload.ToolInput = payload.ToolInputCamel
	}
	if payload.ToolInput == nil {
		payload.ToolInput = map[string]any{}
	}
	return payload, nil
}

func classifyPreToolPayload(payload preToolPayload) hookClassification {
	tool := strings.TrimSpace(payload.ToolName)
	switch {
	case strings.EqualFold(tool, "Bash"):
		command := inputString(payload.ToolInput, "command", "cmd")
		if isDestructiveShellCommand(command) {
			return hookClassification{
				ShouldDecide: true,
				Class:        "shell-operate",
				Target:       command,
				Action:       "shell_operate",
				ToolID:       "shell",
				Reason:       "shell operation",
			}
		}
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

func buildHookDecisionReceipt(opts hookOptions, payload preToolPayload, classification hookClassification) (*contracts.WorkstationPolicyDecisionReceipt, error) {
	effectType, effectMode, defaultAction, defaultTool := workstation.EffectDefaults(classification.Class)
	action := firstNonEmptyString(classification.Action, defaultAction)
	toolID := firstNonEmptyString(classification.ToolID, payload.ToolName, defaultTool)
	profile, err := workstation.LoadPolicyProfileFile("")
	if err != nil {
		return nil, err
	}
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
	return workstation.Decide(profile, req, workstation.DecisionOptions{})
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
	// A self-call skip prevents the hook from recursively governing the
	// governance server. It is intentionally an exact server namespace, not a
	// substring: a foreign MCP server can otherwise name itself
	// "evil-helm-ai-kernel" and escape the hook entirely.
	prefix := "mcp__" + setupMCPServerName + "__"
	t := strings.ToLower(strings.TrimSpace(tool))
	return strings.HasPrefix(t, prefix) && len(t) > len(prefix)
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
