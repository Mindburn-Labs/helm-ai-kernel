// quantum_posture: hook decision receipts are signed with the classical
// Ed25519 workstation seed resolved via workstation_signing.go; no
// post-quantum or hybrid primitives are used in this file.

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shellscan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

var (
	hookStdin            = io.Reader(os.Stdin)
	hookNow              = func() time.Time { return time.Now().UTC() }
	errHookPolicyProfile = errors.New("hook policy profile unavailable")
)

type hookOptions struct {
	Client              string
	DataDir             string
	PolicyProfile       string
	PolicyProfileSHA256 string
	SigningSeedFile     string
	JSON                bool
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
	ShouldDecide            bool
	Class                   string
	Target                  string
	Action                  string
	ToolID                  string
	Reason                  string
	Metadata                map[string]string
	RequiresShellPermission bool
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
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return 2
	}
	classification := classifyPreToolPayload(payload)
	if !classification.ShouldDecide {
		return 0
	}
	classifications := []hookClassification{classification}
	if classification.RequiresShellPermission {
		classifications = append(classifications, hookClassification{
			ShouldDecide: true,
			Class:        "shell-operate",
			Target:       inputString(payload.ToolInput, "command", "cmd"),
			Action:       "shell_operate",
			ToolID:       "shell",
			Reason:       "compound shell operation",
			Metadata:     classification.Metadata,
		})
	}
	for _, decision := range classifications {
		receipt, err := buildHookDecisionReceipt(opts, payload, decision)
		if err != nil {
			fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
			reason := "HELM denied operation: local receipt signer is unavailable"
			if errors.Is(err, errHookPolicyProfile) {
				reason = "HELM denied operation: policy profile is unavailable"
			}
			return emitHookDenyOrFail(stdout, stderr, reason)
		}
		receiptPath, err := writeDecisionReceipt("", filepath.Join(opts.DataDir, "receipts", "hooks"), receipt)
		if err != nil {
			fmt.Fprintf(stderr, "hook pre-tool: write receipt: %v\n", err)
			return emitHookDenyOrFail(stdout, stderr, "HELM denied operation: receipt persistence is unavailable")
		}
		if receipt.Verdict == contracts.WorkstationVerdictDeny {
			return emitHookDenyOrFail(stdout, stderr, fmt.Sprintf("HELM denied %s: %s (receipt: %s)", decision.Reason, receipt.ReasonCode, receiptPath))
		}
	}
	return 0
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
	fmt.Fprintln(w, "Usage: helm-ai-kernel hook pre-tool --client <claude-code|codex> [--data-dir DIR] [--policy-profile PATH --policy-profile-sha256 SHA256] [--signing-seed-file PATH]")
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

func classifyPreToolPayload(payload preToolPayload) hookClassification {
	tool := strings.TrimSpace(payload.ToolName)
	switch {
	case strings.EqualFold(tool, "Bash"):
		command := inputString(payload.ToolInput, "command", "cmd")
		// Structural (AST-based) pre-flight classification. The classifier is
		// advisory input only: it decides whether the command reaches the
		// existing signed decision path; the permit/receipt verdict is still
		// produced by workstation.Decide, fail-closed as before.
		if scan := shellscan.ClassifyAt(command, payload.CWD); scan.Decide {
			class := "shell-operate"
			target := command
			action := "shell_operate"
			reason := "shell operation: " + scan.Reason
			if scan.SensitiveTarget != "" {
				class = "sensitive-file-write"
				target = scan.SensitiveTarget
				action = "file_write"
				reason = "sensitive file operation"
			}
			return hookClassification{
				ShouldDecide:            true,
				Class:                   class,
				Target:                  target,
				Action:                  action,
				ToolID:                  "shell",
				Reason:                  reason,
				Metadata:                shellscanReceiptMetadata(scan),
				RequiresShellPermission: scan.SensitiveTarget != "" && len(scan.Commands) > 1,
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
				Class:        "sensitive-file-write",
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
	targetFingerprint := fingerprintHookTarget(classification.Target)
	profile, profileDigest, err := workstation.LoadPolicyProfileFileWithDigest(opts.PolicyProfile)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errHookPolicyProfile, err)
	}
	if strings.TrimSpace(opts.PolicyProfile) != "" {
		approvedDigest := strings.TrimSpace(opts.PolicyProfileSHA256)
		if approvedDigest == "" {
			return nil, fmt.Errorf("%w: custom policy profile has no approved digest", errHookPolicyProfile)
		}
		if approvedDigest != profileDigest {
			return nil, fmt.Errorf("%w: custom policy profile digest does not match installed configuration", errHookPolicyProfile)
		}
	}
	requestID, err := newHookRequestID()
	if err != nil {
		return nil, fmt.Errorf("generate hook request ID: %w", err)
	}
	req := contracts.WorkstationDecisionRequest{
		RequestID:    requestID,
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
	for key, value := range classification.Metadata {
		req.Metadata[key] = value
	}
	seed, err := resolveWorkstationSigningSeed(opts.DataDir, "", opts.SigningSeedFile)
	if err != nil {
		return nil, fmt.Errorf("load workstation signing key: %w", err)
	}
	persistedMetadata := map[string]string{
		"target_binding": "sha256:utf-8",
	}
	if profileDigest != "" {
		persistedMetadata["policy_profile_sha256"] = profileDigest
	}
	if effectType == contracts.EffectTypeWorkstationMCPToolCall {
		canonicalInput, err := canonicalize.JCS(payload.ToolInput)
		if err != nil {
			return nil, fmt.Errorf("canonicalize MCP tool input: %w", err)
		}
		persistedMetadata["mcp_input_binding"] = "jcs-sha256"
		persistedMetadata["mcp_input_sha256"] = canonicalize.ComputeArtifactHash(canonicalInput)
	}
	return workstation.Decide(profile, req, workstation.DecisionOptions{
		SigningSeed:       seed,
		PersistedTarget:   targetFingerprint,
		PersistedMetadata: persistedMetadata,
	})
}

func newHookRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "hook_" + hex.EncodeToString(value[:]), nil
}

func fingerprintHookTarget(target string) string {
	sum := sha256.Sum256([]byte(target))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func shellscanReceiptMetadata(scan shellscan.Result) map[string]string {
	commands := make([]string, 0, len(scan.Commands))
	for _, command := range scan.Commands {
		entry := command.Name
		if command.Via != "" {
			entry += " via " + command.Via
		}
		commands = append(commands, entry)
	}
	return map[string]string{
		"shellscan.parse_ok": strconv.FormatBool(scan.ParseOK),
		"shellscan.signals":  strings.Join(scan.Signals, ","),
		"shellscan.commands": strings.Join(commands, ","),
	}
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
		".claude/settings.json",
		".codex/hooks.json",
		".claude\\settings.json",
		".codex\\hooks.json",
	}
	for _, needle := range sensitive {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}
