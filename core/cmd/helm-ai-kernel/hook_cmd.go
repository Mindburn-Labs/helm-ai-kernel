// quantum_posture: hook decision receipts are signed with the classical
// Ed25519 workstation seed resolved via workstation_signing.go; no
// post-quantum or hybrid primitives are used in this file.

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

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/actioninbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
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
	if tripped, runLength := recordHookDoomLoop(opts, payload, classification, stderr); tripped {
		return emitHookDenyOrFail(stdout, stderr, doomLoopSteeringText(classification, runLength))
	}
	receipt, err := buildHookDecisionReceipt(opts, payload, classification)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return emitHookDenyOrFail(stdout, stderr, failClosedSteeringText(
			"HELM denied operation: local receipt signer is unavailable",
			actioninbox.ReasonSignerUnavailable,
			"HELM cannot sign a local decision receipt, so the operation fails closed.",
			"Do not retry until the signer is fixed. Run `helm-ai-kernel doctor` or `helm-ai-kernel setup`, or pass --signing-seed-file.",
			"Escalate to the human operator; signer repair is an operator action, not an agent action.",
		))
	}
	if receipt.Verdict != contracts.WorkstationVerdictDeny {
		return 0
	}
	receiptPath, err := writeDecisionReceipt("", filepath.Join(opts.DataDir, "receipts", "hooks"), receipt)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: write receipt: %v\n", err)
		return emitHookDenyOrFail(stdout, stderr, failClosedSteeringText(
			"HELM denied operation: receipt persistence is unavailable",
			actioninbox.ReasonReceiptPersistence,
			"HELM cannot persist the signed decision receipt, so the operation fails closed.",
			"Do not retry until receipt storage is fixed; check the data directory is writable.",
			"Escalate to the human operator; storage repair is an operator action, not an agent action.",
		))
	}
	feedback := actioninbox.DenyFeedbackFor(receipt.ReasonCode, receipt.CreatedAt)
	return emitHookDenyOrFail(stdout, stderr, fmt.Sprintf("HELM denied %s: %s (receipt: %s) %s",
		classification.Reason, receipt.ReasonCode, receiptPath, actioninbox.RenderSteeringText(feedback)))
}

// failClosedSteeringText keeps the operator-facing prefix intact (tests and
// runbooks grep for it) and appends model-actionable steering guidance.
func failClosedSteeringText(prefix, code, explanation, remediation, escalation string) string {
	return prefix + " " + actioninbox.RenderSteeringText(actioninbox.DenialRecord{
		SchemaVersion: actioninbox.DenyFeedbackSchemaVersion,
		ReasonCode:    code,
		Explanation:   explanation,
		Remediation:   remediation,
		Escalation:    escalation,
		DecidedAt:     hookNow(),
	})
}

// doomLoopSteeringText renders the circuit-breaker denial. The breaker only
// ever adds denials on top of the policy decision path; it never authorizes.
func doomLoopSteeringText(classification hookClassification, runLength int) string {
	d := actioninbox.DenialRecord{
		SchemaVersion: actioninbox.DenyFeedbackSchemaVersion,
		ReasonCode:    actioninbox.ReasonDoomLoopDetected,
		Explanation: fmt.Sprintf("The identical call (%s via %s) has been attempted %d consecutive times in this session without progress; the doom-loop circuit breaker forced an escalation.",
			classification.Action, classification.ToolID, runLength),
		Remediation: "Stop retrying the identical call. Change the approach, gather the missing information, or abandon the attempt.",
		Escalation:  "Ask the human operator to review the repeated attempts and either take over or reset the circuit breaker by changing the approach.",
		DecidedAt:   hookNow(),
	}
	return "HELM denied " + classification.Reason + ": " + actioninbox.RenderSteeringText(d)
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

// hookDoomLoopFile is the on-disk circuit-breaker state for the pre-tool
// hook. The hook process is stateless between invocations, so the identical-
// call run is persisted per session under the HELM data dir. The state is
// advisory evidence for the breaker only; losing it never weakens the base
// policy decision path, which remains fail-closed on its own.
type hookDoomLoopFile struct {
	Sessions map[string]*hookDoomLoopSession `json:"sessions"`
}

type hookDoomLoopSession struct {
	LastSignature string     `json:"last_signature"`
	RunLength     int        `json:"run_length"`
	Tripped       bool       `json:"tripped"`
	TripCount     int        `json:"trip_count,omitempty"`
	LastTrippedAt *time.Time `json:"last_tripped_at,omitempty"`
}

// recordHookDoomLoop counts consecutive identical classified calls for the
// session and reports whether the circuit breaker has tripped. Identical
// means the same normalized tool/action/target signature. The hook observes
// attempts, not settled results, which is strictly more conservative than
// the settled-call semantics of the control-plane breaker.
func recordHookDoomLoop(opts hookOptions, payload preToolPayload, classification hookClassification, stderr io.Writer) (bool, int) {
	if strings.TrimSpace(opts.DataDir) == "" {
		// No local state dir (e.g. HOME-less environment): the breaker is
		// disabled rather than writing state into the caller's CWD.
		return false, 0
	}
	signature := actioninbox.SignatureFor(classification.ToolID, classification.Action, classification.Target)
	sessionID := strings.TrimSpace(payload.SessionID)
	if sessionID == "" {
		sessionID = "_default"
	}
	path := filepath.Join(opts.DataDir, "state", "hook-doomloop.json")
	state := loadHookDoomLoopState(path, stderr)
	sess, ok := state.Sessions[sessionID]
	if !ok {
		sess = &hookDoomLoopSession{}
		state.Sessions[sessionID] = sess
	}
	if sess.LastSignature == signature {
		sess.RunLength++
	} else {
		sess.LastSignature = signature
		sess.RunLength = 1
	}
	if sess.RunLength >= actioninbox.DefaultDoomLoopThreshold && !sess.Tripped {
		sess.Tripped = true
		sess.TripCount++
		now := hookNow()
		sess.LastTrippedAt = &now
	}
	if err := saveHookDoomLoopState(path, state); err != nil {
		// Best-effort persistence: the base policy decision path is
		// unaffected and remains fail-closed; log and continue.
		fmt.Fprintf(stderr, "hook pre-tool: persist doom-loop state: %v\n", err)
	}
	return sess.Tripped, sess.RunLength
}

func loadHookDoomLoopState(path string, stderr io.Writer) *hookDoomLoopFile {
	state := &hookDoomLoopFile{Sessions: map[string]*hookDoomLoopSession{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		return state
	}
	if err := json.Unmarshal(raw, state); err != nil || state.Sessions == nil {
		fmt.Fprintf(stderr, "hook pre-tool: doom-loop state unreadable, starting fresh: %v\n", err)
		return &hookDoomLoopFile{Sessions: map[string]*hookDoomLoopSession{}}
	}
	return state
}

func saveHookDoomLoopState(path string, state *hookDoomLoopFile) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".hook-doomloop-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
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
