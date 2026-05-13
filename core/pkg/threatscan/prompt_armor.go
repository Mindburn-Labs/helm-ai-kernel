package threatscan

import (
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// promptArmorRules detects injected instruction blocks before they reach a tool
// decision. The implementation stays deterministic/offline to preserve scanner
// replay guarantees while modeling PromptArmor's detect-before-agent step.
func promptArmorRules() []Rule {
	return []Rule{
		{
			ID:       "PROMPT_ARMOR_TOOL_HIJACK",
			Class:    contracts.ThreatClassPromptInjection,
			Severity: contracts.ThreatSeverityHigh,
			Match:    promptArmorToolHijackSpans,
			Notes:    "Detected PromptArmor-style injected instruction that tries to redirect a tool call or exfiltrate context",
		},
	}
}

func promptArmorToolHijackSpans(input, normalized string) []contracts.MatchedSpan {
	if !hasAnyPromptArmorCue(normalized, promptArmorBoundaryCues) {
		return nil
	}
	if !hasAnyPromptArmorCue(normalized, promptArmorAgentCues) {
		return nil
	}
	if !hasAnyPromptArmorCue(normalized, promptArmorActionCues) {
		return nil
	}
	if !hasAnyPromptArmorCue(normalized, promptArmorTargetCues) {
		return nil
	}

	matched := make([]contracts.MatchedSpan, 0, 3)
	matched = append(matched, firstPromptArmorSpan(input, normalized, promptArmorBoundaryCues))
	matched = append(matched, firstPromptArmorSpan(input, normalized, promptArmorAgentCues))
	matched = append(matched, firstPromptArmorSpan(input, normalized, promptArmorActionCues))
	matched = append(matched, firstPromptArmorSpan(input, normalized, promptArmorTargetCues))
	return compactPromptArmorSpans(matched)
}

var promptArmorBoundaryCues = []string{
	"ignore the above",
	"ignore everything above",
	"ignore previous",
	"disregard previous",
	"new instructions",
	"new task:",
	"system message:",
	"developer message:",
	"hidden instruction",
	"instructions for ai",
	"when you read this",
	"when processing this",
}

var promptArmorAgentCues = []string{
	"agent",
	"assistant",
	"model",
	"llm",
	"ai",
	"tool",
	"function",
}

var promptArmorActionCues = []string{
	"call",
	"use",
	"invoke",
	"execute",
	"run",
	"send",
	"exfiltrate",
	"upload",
	"post to",
}

var promptArmorTargetCues = []string{
	"tool",
	"function",
	"webhook",
	"api key",
	"access token",
	"oauth token",
	"secret",
}

func hasAnyPromptArmorCue(normalized string, cues []string) bool {
	for _, cue := range cues {
		if strings.Contains(normalized, cue) {
			return true
		}
	}
	return false
}

func firstPromptArmorSpan(input, normalized string, cues []string) contracts.MatchedSpan {
	for _, cue := range cues {
		if spans := caseInsensitiveContains(normalized, cue); len(spans) > 0 {
			span := spans[0]
			if span.Start >= 0 && span.End <= len(input) {
				span.Text = input[span.Start:span.End]
			}
			return span
		}
	}
	return contracts.MatchedSpan{}
}

func compactPromptArmorSpans(spans []contracts.MatchedSpan) []contracts.MatchedSpan {
	out := make([]contracts.MatchedSpan, 0, len(spans))
	seen := make(map[string]struct{}, len(spans))
	for _, span := range spans {
		if span.End <= span.Start {
			continue
		}
		key := strings.ToLower(span.Text)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, span)
	}
	return out
}
