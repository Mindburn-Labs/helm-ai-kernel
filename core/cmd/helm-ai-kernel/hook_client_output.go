package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/actioninbox"
)

type hookDecisionOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// withDoomLoopSteering appends circuit-breaker escalation guidance to an
// already-denied outcome when the breaker has latched for this call signature.
// The base denial (policy or fail-closed) is always preserved; the breaker
// only adds steering, never authority.
func withDoomLoopSteering(tripped bool, classification hookClassification, runLength int, base string) string {
	if !tripped {
		return base
	}
	return base + " " + doomLoopSteeringText(classification, runLength)
}

// failClosedSteeringText keeps the operator-facing prefix intact and appends
// model-actionable steering guidance.
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

// doomLoopSteeringText renders circuit-breaker escalation guidance. The
// breaker only enriches a denial that already exists; it never authorizes and
// never denies on its own.
func doomLoopSteeringText(classification hookClassification, runLength int) string {
	d := actioninbox.DenialRecord{
		SchemaVersion: actioninbox.DenyFeedbackSchemaVersion,
		ReasonCode:    actioninbox.ReasonDoomLoopDetected,
		Explanation: fmt.Sprintf("The identical call (%s via %s) has now been denied %d consecutive times in this session; the doom-loop circuit breaker is forcing escalation.",
			classification.Action, classification.ToolID, runLength),
		Remediation: "Stop retrying the identical call. Change the approach, gather the missing information, or abandon the attempt.",
		Escalation:  "Ask the human operator to review the repeated denials and either take over or adjust policy.",
		DecidedAt:   hookNow(),
	}
	return actioninbox.RenderSteeringText(d)
}

func emitHookDenyOrFail(stdout, stderr io.Writer, client, reason string) int {
	if client == "hermes" {
		if err := writeHermesHookBlock(stdout, reason); err != nil {
			fmt.Fprintf(stderr, "hook pre-tool: emit denial: %v\n", err)
			return hermesBlockExitCode
		}
		// Hermes honors {"action":"block"} and treats exit 2 as a block even
		// when stdout is empty. Claude hookSpecificOutput + exit 0 is not a
		// Hermes block — that combination is fail-open.
		return hermesBlockExitCode
	}
	if client == "deepseek" {
		if err := writeDeepSeekHookDeny(stdout, stderr, reason); err != nil {
			fmt.Fprintf(stderr, "hook pre-tool: emit denial: %v\n", err)
			return deepseekBlockExitCode
		}
		// DSH parseHookOutput blocks on exit 2 and takes the reason from
		// stderr. Structured stdout is parsed only on exit 0, and
		// {"kind":"deny"} is never read. writeDeepSeekHookDeny keeps the
		// native JSON on stdout and writes the same HELM reason on stderr.
		// Claude hookSpecificOutput + exit 0 is not a DSH block.
		return deepseekBlockExitCode
	}
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

func writeHermesHookBlock(stdout io.Writer, reason string) error {
	return json.NewEncoder(stdout).Encode(hermesHookBlock{
		Action:  "block",
		Message: reason,
	})
}

func writeDeepSeekHookDeny(stdout, stderr io.Writer, reason string) error {
	if err := json.NewEncoder(stdout).Encode(deepseekHookDeny{
		Kind:   "deny",
		Reason: reason,
	}); err != nil {
		_ = writeDeepSeekHookReason(stderr, reason)
		return err
	}
	return writeDeepSeekHookReason(stderr, reason)
}

func writeDeepSeekHookReason(stderr io.Writer, reason string) error {
	if stderr == nil || strings.TrimSpace(reason) == "" {
		return nil
	}
	_, err := fmt.Fprintln(stderr, reason)
	return err
}

const hermesBlockExitCode = 2
const deepseekBlockExitCode = 2

type hermesHookBlock struct {
	Action  string `json:"action"`
	Message string `json:"message"`
}

type deepseekHookDeny struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

// hermesPreToolCallBlocks mirrors the NousResearch/hermes-agent shell hook
// interpreter (agent/shell_hooks.py): exit 2 blocks; stdout {"action":"block"}
// or Claude-style {"decision":"block"} blocks. Claude Code hookSpecificOutput
// JSON with exit 0 is valid JSON that is not a block directive, so Hermes
// proceeds. This function exists so tests can prove that fail-open shape.
func hermesPreToolCallBlocks(stdout string, exitCode int) bool {
	if exitCode == hermesBlockExitCode {
		return true
	}
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return false
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(stdout), &data); err != nil {
		return false
	}
	if action, _ := data["action"].(string); action == "block" {
		return true
	}
	if decision, _ := data["decision"].(string); decision == "block" {
		return true
	}
	return false
}

// deepseekParseHookOutput mirrors DSH parseHookOutput for a shell-hook hop:
// exit 2 is a block and the reason is taken from stderr. Structured stdout
// is parsed only on exit 0, and {"kind":"deny"} is never read. Claude Code
// hookSpecificOutput JSON with exit 0 is therefore not a DSH block. This
// function exists so tests can prove that honest shape; it does not claim a
// live DeepSeek session already observed DENY.
func deepseekParseHookOutput(stdout, stderr string, exitCode int) (block bool, reason string) {
	if exitCode == deepseekBlockExitCode {
		return true, strings.TrimSpace(stderr)
	}
	return false, ""
}

func deepseekPreToolBlocks(stdout string, exitCode int) bool {
	block, _ := deepseekParseHookOutput(stdout, "", exitCode)
	return block
}
