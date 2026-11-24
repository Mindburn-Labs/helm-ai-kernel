package main

import (
	"maps"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shellscan"
)

type hookClassification struct {
	ShouldDecide            bool
	Class                   string
	Target                  string
	Action                  string
	ToolID                  string
	Reason                  string
	Metadata                map[string]string
	RequiresShellPermission bool
	// TrustMaterial marks a call that reaches the hook's own signing or
	// trust material. It is denied under every profile.
	TrustMaterial bool
	// InputTooLarge marks a call whose payload exceeded hookMaxInputBytes and
	// was not read in full. It is denied under every profile, and InputRead
	// says what was read.
	InputTooLarge bool
	InputRead     *hookOversizedPayload
}

func classifyPreToolPayload(payload preToolPayload) hookClassification {
	classifications := classifyPreToolPayloads(payload, nil)
	if len(classifications) == 0 {
		return hookClassification{}
	}
	return classifications[0]
}

// classifyPreToolPayloads returns the decisions one tool call needs. An empty
// result means the call is an observe- or draft-class action that passes
// without a receipt. guard names the signer's own files; a call that reaches
// them gets a single decision that no profile allows.
func classifyPreToolPayloads(payload preToolPayload, guard *shellscan.PathGuard) []hookClassification {
	tool := strings.TrimSpace(payload.ToolName)
	kind := hookToolKindOf(tool)
	if kind == hookToolShell {
		command, ok := shellCommandText(payload.ToolInput)
		if !ok {
			// A command that is missing or is not a string cannot be read, so
			// what the call would run is unknown: an opaque shell operation,
			// after the signer's files have been looked for in all of it.
			if target, reason, found := guardedToolTarget(guard, hookToolUnknown, payload, newSearchCall(payload)); found {
				return trustMaterialClassification(tool, target, reason, nil)
			}
			return []hookClassification{opaqueShellClassification(canonicalToolInput(payload.ToolInput), "the command is missing or is not a string")}
		}
		// Structural (AST-based) pre-flight classification. The classifier is
		// advisory input only: it decides whether the command reaches the
		// existing signed decision path; the permit/receipt verdict is still
		// produced by workstation.Decide, fail-closed as before.
		scan := shellscan.ClassifyAt(command, payload.CWD, shellscan.WithPathGuard(guard))
		return shellClassifications(tool, command, scan)
	}
	search := newSearchCall(payload)
	if target, reason, ok := guardedToolTarget(guard, kind, payload, search); ok {
		return trustMaterialClassification(tool, target, reason, nil)
	}
	switch kind {
	case hookToolMCP:
		// Claude/Codex emit mcp__server__tool. Hermes has used that shape and
		// the older mcp_server_tool form. mcp__ is a prefix of mcp_. Only the
		// HELM server that setup installs is exempt; it governs its own tools.
		if isHelmSelfMCPTool(tool) {
			return nil
		}
		return []hookClassification{{
			ShouldDecide: true,
			Class:        "mcp",
			Target:       tool,
			Action:       "mcp_tool_call",
			ToolID:       tool,
			Reason:       "MCP tool call",
		}}
	case hookToolWrite:
		target := inputString(payload.ToolInput, "file_path", "path", "target_file", "notebook_path")
		patch := strings.EqualFold(tool, "apply_patch") || strings.EqualFold(tool, "patch")
		if target == "" && patch {
			target = sensitiveApplyPatchTarget(inputString(payload.ToolInput, "command", "cmd", "patch", "diff"), payload.CWD)
		}
		if target == "" && patch {
			target = "apply_patch"
		}
		if isSensitiveWriteTarget(target, payload.CWD) {
			return []hookClassification{{
				ShouldDecide: true,
				Class:        "sensitive-file-write",
				Target:       target,
				Action:       "file_write",
				ToolID:       tool,
				Reason:       "sensitive file write",
			}}
		}
		return nil
	case hookToolRead:
		return readToolClassifications(tool, payload, search)
	case hookToolFetch:
		return fetchToolClassifications(tool, payload)
	case hookToolCode:
		return codeToolClassifications(tool, payload)
	case hookToolImage:
		return imageToolClassifications(tool, payload)
	case hookToolMCPResource:
		return mcpResourceClassifications(tool, payload)
	}
	return unknownToolClassifications(tool)
}

// hookClassificationFromShellscanFact turns one scanner fact into a decision.
// scanMetadata describes the whole scan; each decision gets its own copy.
func hookClassificationFromShellscanFact(fact shellscan.EffectFact, scanMetadata map[string]string) (hookClassification, bool) {
	metadata := maps.Clone(scanMetadata)
	switch fact.Class {
	case "network":
		return hookClassification{
			ShouldDecide: true,
			Class:        "network",
			Target:       fact.Target,
			Action:       fact.Action,
			ToolID:       "network.egress",
			Reason:       fact.Reason,
			Metadata:     metadata,
		}, true
	case "secret":
		return hookClassification{
			ShouldDecide: true,
			Class:        "secret",
			Target:       fact.Target,
			Action:       fact.Action,
			ToolID:       "secret.read",
			Reason:       fact.Reason,
			Metadata:     metadata,
		}, true
	default:
		return hookClassification{}, false
	}
}

func shellscanGenericClassification(command string, scan shellscan.Result, scanMetadata map[string]string) hookClassification {
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
		Metadata:                maps.Clone(scanMetadata),
		RequiresShellPermission: scan.RequiresShellPermission,
	}
}

func appendRequiredShellPermission(classifications []hookClassification, command string) []hookClassification {
	if len(classifications) == 0 {
		return nil
	}
	decisions := make([]hookClassification, 0, len(classifications)+1)
	for _, classification := range classifications {
		decisions = append(decisions, classification)
		if classification.RequiresShellPermission {
			decisions = append(decisions, hookClassification{
				ShouldDecide: true,
				Class:        "shell-operate",
				Target:       command,
				Action:       "shell_operate",
				ToolID:       "shell",
				Reason:       "compound shell operation",
				Metadata:     classification.Metadata,
			})
		}
	}
	return decisions
}

// oversizedToolCallClassification is the one decision for a call whose
// payload exceeded hookMaxInputBytes. The call was not classified, so it is
// decided as a call into a tool the hook cannot see into (the MCP tool-call
// effect type) and refused. It names the tool when the payload named it
// before the limit, and the call binding carries the digest of the bytes
// read.
func oversizedToolCallClassification(oversized *hookOversizedPayload) hookClassification {
	return hookClassification{
		ShouldDecide:  true,
		Class:         "mcp",
		Target:        "tool input over " + strconv.Itoa(hookMaxInputBytes) + " bytes",
		Action:        "oversized_tool_call",
		ToolID:        firstNonEmptyString(oversized.tool, "unknown"),
		Reason:        "tool call whose input exceeds what the hook reads",
		Metadata:      map[string]string{"tool_input_limit_bytes": strconv.Itoa(hookMaxInputBytes)},
		InputTooLarge: true,
		InputRead:     oversized,
	}
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

func sensitiveApplyPatchTarget(command, cwd string) string {
	for _, target := range applyPatchTargets(command) {
		if isSensitiveWriteTarget(target, cwd) {
			return target
		}
	}
	return ""
}

// isHelmSelfMCPTool matches only the exact server segment setup installs
// (mcp__<server>__<tool>). A substring or prefix match would exempt any
// third-party server whose declared name merely contains "helm-ai-kernel".
// Setup never installs the HELM server for clients that use the older
// mcp_<server>_<tool> form, so that form is never exempt.
func isHelmSelfMCPTool(tool string) bool {
	rest, ok := strings.CutPrefix(tool, "mcp__")
	if !ok {
		return false
	}
	server, _, found := strings.Cut(rest, "__")
	return found && server == setupMCPServerName
}

// isSensitiveWriteTarget shares shellscan's normalized rules, so the Write
// tool and a shell write to the same file are classified alike.
func isSensitiveWriteTarget(path, cwd string) bool {
	_, ok := shellscan.SensitiveWriteTarget(path, cwd)
	return ok
}
