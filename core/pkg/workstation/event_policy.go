package workstation

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/netdest"
)

func normalizeEvents(profile contracts.WorkstationPolicyProfile, events []ToolEvent) (
	[]contracts.AgentToolAction,
	[]contracts.AgentMemoryEffect,
	[]contracts.AgentRecurringLoopEffect,
	[]contracts.AgentDeniedEffect,
) {
	toolActions := make([]contracts.AgentToolAction, 0, len(events))
	var memoryEffects []contracts.AgentMemoryEffect
	var recurringEffects []contracts.AgentRecurringLoopEffect
	var deniedEffects []contracts.AgentDeniedEffect

	for i, event := range events {
		normalizeEvent(&event, i)
		evaluatedVerdict, evaluatedReasonCode, evaluatedReason := EvaluateEvent(profile, event)
		verdict, reasonCode, reason := evaluatedVerdict, evaluatedReasonCode, evaluatedReason
		// The declared verdict and reason code below record the observed event,
		// but are untrusted. A complete learning receipt is emitted only when the
		// recorded code agrees with the evaluation that produced it.
		if event.Verdict != "" {
			verdict = strings.ToUpper(event.Verdict)
		}
		if event.ReasonCode != "" {
			reasonCode = event.ReasonCode
		}
		action := contracts.AgentToolAction{
			ActionID:    event.EventID,
			ToolID:      event.ToolID,
			Action:      event.Action,
			EffectType:  event.EffectType,
			EffectMode:  event.EffectMode,
			Status:      firstNonEmpty(event.Status, "observed"),
			Verdict:     verdict,
			ReasonCode:  reasonCode,
			Target:      event.Target,
			OccurredAt:  event.OccurredAt,
			Metadata:    event.Metadata,
			TaintLabels: sortedStrings(event.TaintLabels),
		}
		toolActions = append(toolActions, action)
		if event.MemoryEffect != nil {
			mem := *event.MemoryEffect
			if mem.EffectID == "" {
				mem.EffectID = event.EventID
			}
			normalizeMemoryEffect(&mem, profile)
			mem.Verdict = verdict
			mem.ReasonCode = reasonCode
			mem.ObservedOnly = true
			mem.TaintLabels = sortedStrings(mem.TaintLabels)
			memoryEffects = append(memoryEffects, mem)
		}
		if event.RecurringLoopEffect != nil {
			loop := *event.RecurringLoopEffect
			if loop.EffectID == "" {
				loop.EffectID = event.EventID
			}
			loop.Verdict = verdict
			loop.ReasonCode = reasonCode
			loop.ObservedOnly = true
			loop.ToolScope = sortedStrings(loop.ToolScope)
			recurringEffects = append(recurringEffects, loop)
		}
		if verdict == contracts.WorkstationVerdictDeny {
			denied := contracts.AgentDeniedEffect{
				EffectID:   event.EventID,
				EffectType: event.EffectType,
				ToolID:     event.ToolID,
				Action:     event.Action,
				ReasonCode: reasonCode,
				Reason:     firstNonEmpty(event.Reason, reason),
				OccurredAt: event.OccurredAt,
			}
			if evaluatedVerdict == contracts.WorkstationVerdictDeny && reasonCode == evaluatedReasonCode {
				denied = evaluatedDeniedEffect(profile, event, evaluatedReasonCode, evaluatedReason)
			}
			deniedEffects = append(deniedEffects, denied)
		}
	}
	return toolActions, memoryEffects, recurringEffects, deniedEffects
}

func EvaluateEvent(profile contracts.WorkstationPolicyProfile, event ToolEvent) (verdict, reasonCode, reason string) {
	if taintedOperateEvent(event) {
		return contracts.WorkstationVerdictDeny, "TAINTED_CONTEXT_REQUIRES_DENY", "tainted context cannot authorize operate-class effects"
	}
	if event.EffectType == contracts.EffectTypeWorkstationFileWrite || event.EffectType == contracts.EffectTypeWorkstationFileDraft || event.Type == "file_write" || event.Type == "draft_edit" {
		if event.EffectMode == contracts.WorkstationEffectModeOperate {
			if verdict, reasonCode, reason := evaluateOperatePermission(profile, event); verdict != contracts.WorkstationVerdictAllow {
				return verdict, reasonCode, reason
			}
		}
		if !draftTargetAllowed(profile.Draft.WorkspaceRoots, event.Target) {
			return contracts.WorkstationVerdictDeny, "DRAFT_TARGET_OUTSIDE_WORKSPACE_SCOPE", "draft target is outside the configured workspace scope"
		}
		return contracts.WorkstationVerdictAllow, "", ""
	}
	if event.EffectType == contracts.EffectTypeWorkstationNetworkEgress || event.Type == "network_egress" {
		if len(profile.Egress.Allowlist) == 0 {
			return contracts.WorkstationVerdictDeny, "EGRESS_ALLOWLIST_EMPTY", "network egress allowlist is empty"
		}
		// A target that is not one concrete endpoint is refused before any
		// comparison, so no allowlist entry can be written to match it.
		destination, err := netdest.Parse(strings.TrimSpace(event.Target))
		if err != nil {
			return contracts.WorkstationVerdictDeny, "EGRESS_DESTINATION_UNDETERMINED", "network destination could not be determined"
		}
		if !egressAllowed(profile.Egress.Allowlist, destination) {
			return contracts.WorkstationVerdictDeny, "EGRESS_DESTINATION_NOT_ALLOWED", "network destination is outside the workstation allowlist"
		}
		return evaluateOperatePermission(profile, event)
	}
	if event.EffectType == contracts.EffectTypeWorkstationMemoryWrite || event.Type == "memory_write" {
		if verdict, reasonCode, reason := evaluateOperatePermission(profile, event); verdict != contracts.WorkstationVerdictAllow {
			return verdict, reasonCode, reason
		}
		if event.MemoryEffect != nil {
			memoryClass := strings.TrimSpace(event.MemoryEffect.MemoryClass)
			if memoryClass != "" && len(profile.Memory.AllowedClasses) > 0 && !containsFold(profile.Memory.AllowedClasses, memoryClass) {
				return contracts.WorkstationVerdictDeny, "MEMORY_CLASS_DISALLOWED", "memory class is not allowed by workstation policy"
			}
			ttl := event.MemoryEffect.TTLDays
			if ttl == 0 {
				ttl = profile.Memory.DefaultTTLDays
			}
			if profile.Memory.MaxTTLDays > 0 && ttl > profile.Memory.MaxTTLDays {
				return contracts.WorkstationVerdictDeny, "MEMORY_TTL_EXCEEDS_POLICY", "memory TTL exceeds workstation policy"
			}
		}
		return contracts.WorkstationVerdictAllow, "", ""
	}
	if event.EffectType == contracts.EffectTypeWorkstationRecurringLoop || event.Type == "recurring_loop" {
		if verdict, reasonCode, reason := evaluateOperatePermission(profile, event); verdict != contracts.WorkstationVerdictAllow {
			return verdict, reasonCode, reason
		}
		if event.RecurringLoopEffect != nil {
			if profile.Loops.RequireSchedule && strings.TrimSpace(event.RecurringLoopEffect.Schedule) == "" {
				return contracts.WorkstationVerdictDeny, "RECURRING_LOOP_MISSING_SCHEDULE", "recurring loop requires schedule"
			}
			if profile.Loops.RequireMaxRuntime && strings.TrimSpace(event.RecurringLoopEffect.MaxRuntime) == "" {
				return contracts.WorkstationVerdictDeny, "RECURRING_LOOP_MISSING_MAX_RUNTIME", "recurring loop requires max runtime"
			}
			if profile.Loops.RequireToolScope && len(event.RecurringLoopEffect.ToolScope) == 0 {
				return contracts.WorkstationVerdictDeny, "RECURRING_LOOP_MISSING_TOOL_SCOPE", "recurring loop requires tool scope"
			}
			if profile.Loops.RequireExpiration && event.RecurringLoopEffect.ExpiresAt.IsZero() {
				return contracts.WorkstationVerdictDeny, "RECURRING_LOOP_MISSING_EXPIRATION", "recurring loop requires expiration"
			}
		}
		return contracts.WorkstationVerdictAllow, "", ""
	}
	if event.EffectMode == contracts.WorkstationEffectModeOperate || isOperateEffect(event.EffectType, event.Type) {
		return evaluateOperatePermission(profile, event)
	}
	return contracts.WorkstationVerdictAllow, "", ""
}

func evaluateOperatePermission(profile contracts.WorkstationPolicyProfile, event ToolEvent) (verdict, reasonCode, reason string) {
	if len(profile.Operate.Permissions) == 0 {
		return contracts.WorkstationVerdictDeny, "OPERATE_PERMISSIONS_EMPTY", "operate permissions are empty"
	}
	required := workstationPermissionForEffect(event.EffectType, event.Type, event.Action)
	if !permissionGranted(profile.Operate.Permissions, event.EffectType, required) {
		return contracts.WorkstationVerdictDeny, "OPERATE_PERMISSION_NOT_GRANTED", "operate permission is not granted for effect"
	}
	return contracts.WorkstationVerdictAllow, "", ""
}

func normalizeMemoryEffect(effect *contracts.AgentMemoryEffect, profile contracts.WorkstationPolicyProfile) {
	if effect.TTLDays == 0 {
		effect.TTLDays = profile.Memory.DefaultTTLDays
	}
	if strings.TrimSpace(effect.Sensitivity) == "" {
		effect.Sensitivity = firstNonEmpty(effect.DataClass, contracts.DataClassInternal)
	}
	if strings.TrimSpace(effect.DataClass) == "" {
		effect.DataClass = dataClassForSensitivity(effect.Sensitivity)
	}
}

func dataClassForSensitivity(sensitivity string) string {
	switch strings.ToLower(strings.TrimSpace(sensitivity)) {
	case "public":
		return contracts.DataClassPublic
	case "restricted", "secret", "credential", "credentials", "high":
		return contracts.DataClassRestricted
	case "confidential", "sensitive", "pii", "medium":
		return contracts.DataClassConfidential
	default:
		return contracts.DataClassInternal
	}
}

func DefaultObserveDraftProfile() contracts.WorkstationPolicyProfile {
	return contracts.WorkstationPolicyProfile{
		ID:   contracts.PolicyProfileWorkstationObserveDraftV1,
		Mode: "observe_only",
		Observe: contracts.WorkstationObservePolicy{AllowedActions: []string{
			"git.status",
			"git.diff",
			"shell.read",
			"shell.test",
			"shell.build",
		}},
		Draft: contracts.WorkstationDraftPolicy{
			WorkspaceRoots:          []string{"."},
			AllowGeneratedArtifacts: true,
		},
		Operate: contracts.WorkstationOperatePolicy{Permissions: []string{}},
		Egress:  contracts.WorkstationEgressPolicy{Allowlist: []contracts.WorkstationEgressDestination{}},
		Memory: contracts.WorkstationMemoryPolicy{
			DefaultTTLDays: 30,
			MaxTTLDays:     30,
			AllowedClasses: []string{
				"M1_EPISODIC",
				"M3_SEMANTIC",
				"M4_PROCEDURAL",
			},
		},
		Loops: contracts.WorkstationRecurringPolicy{
			RequireSchedule:   true,
			RequireMaxRuntime: true,
			RequireToolScope:  true,
			RequireExpiration: true,
		},
	}
}

func normalizeEvent(event *ToolEvent, idx int) {
	if event.EventID == "" {
		event.EventID = deterministicID("event", fmt.Sprintf("%d", idx), event.Type, event.ToolID, event.Action, event.Target)
	}
	if event.ToolID == "" {
		event.ToolID = firstNonEmpty(event.Type, "unknown")
	}
	if event.Action == "" {
		event.Action = firstNonEmpty(event.Type, "observed")
	}
	if event.EffectType == "" {
		event.EffectType = effectTypeForEvent(*event)
	}
	if event.EffectMode == "" {
		event.EffectMode = effectModeForEvent(*event)
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Unix(0, 0).UTC()
	}
}

func effectTypeForEvent(event ToolEvent) string {
	switch event.Type {
	case "file_write", "draft_edit":
		return contracts.EffectTypeWorkstationFileWrite
	case "network_egress":
		return contracts.EffectTypeWorkstationNetworkEgress
	case "mcp_tool_call":
		return contracts.EffectTypeWorkstationMCPToolCall
	case "memory_write":
		return contracts.EffectTypeWorkstationMemoryWrite
	case "recurring_loop":
		return contracts.EffectTypeWorkstationRecurringLoop
	case "deploy_publish":
		return contracts.EffectTypeWorkstationDeployPublish
	case "secret_read":
		return contracts.EffectTypeWorkstationSecretRead
	case "payment_initiate":
		return contracts.EffectTypeWorkstationPaymentInitiate
	case "prompt_injection", "tainted_context":
		return contracts.EffectTypeWorkstationTaintedContext
	default:
		return contracts.EffectTypeWorkstationShellCommand
	}
}

func effectModeForEvent(event ToolEvent) string {
	switch event.Type {
	case "file_write", "draft_edit":
		return contracts.WorkstationEffectModeDraft
	case "network_egress", "mcp_tool_call", "memory_write", "recurring_loop", "deploy_publish", "secret_read", "payment_initiate":
		return contracts.WorkstationEffectModeOperate
	default:
		return contracts.WorkstationEffectModeObserve
	}
}

func isOperateEffect(effectType, eventType string) bool {
	switch effectType {
	case contracts.EffectTypeWorkstationNetworkEgress,
		contracts.EffectTypeWorkstationMCPToolCall,
		contracts.EffectTypeWorkstationMemoryWrite,
		contracts.EffectTypeWorkstationRecurringLoop,
		contracts.EffectTypeWorkstationDeployPublish,
		contracts.EffectTypeWorkstationSecretRead,
		contracts.EffectTypeWorkstationPaymentInitiate:
		return true
	}
	switch eventType {
	case "network_egress", "mcp_tool_call", "memory_write", "recurring_loop", "deploy_publish", "secret_read", "payment_initiate", "shell_operate":
		return true
	default:
		return false
	}
}

func taintedOperateEvent(event ToolEvent) bool {
	if !isOperateEffect(event.EffectType, event.Type) && event.EffectMode != contracts.WorkstationEffectModeOperate {
		return false
	}
	for _, label := range event.TaintLabels {
		switch strings.ToLower(strings.TrimSpace(label)) {
		case "prompt_injection", "tainted_context", "untrusted_tool_output":
			return true
		}
	}
	return false
}

func workstationPermissionForEffect(effectType, eventType, action string) string {
	switch effectType {
	case contracts.EffectTypeWorkstationNetworkEgress:
		return contracts.WorkstationPermissionNetworkEgress
	case contracts.EffectTypeWorkstationFileDraft, contracts.EffectTypeWorkstationFileWrite:
		return contracts.WorkstationPermissionFileWrite
	case contracts.EffectTypeWorkstationMCPToolCall:
		return contracts.WorkstationPermissionMCPMutate
	case contracts.EffectTypeWorkstationMemoryWrite:
		return contracts.WorkstationPermissionMemoryWrite
	case contracts.EffectTypeWorkstationRecurringLoop:
		return contracts.WorkstationPermissionLoopRegister
	case contracts.EffectTypeWorkstationDeployPublish:
		return contracts.WorkstationPermissionDeployPublish
	case contracts.EffectTypeWorkstationSecretRead:
		return contracts.WorkstationPermissionSecretRead
	case contracts.EffectTypeWorkstationPaymentInitiate:
		return contracts.WorkstationPermissionPaymentInitiate
	case contracts.EffectTypeWorkstationShellCommand:
		if strings.EqualFold(eventType, "shell_operate") || strings.Contains(strings.ToLower(action), "operate") {
			return contracts.WorkstationPermissionShellOperate
		}
	}
	switch eventType {
	case "network_egress":
		return contracts.WorkstationPermissionNetworkEgress
	case "file_write", "draft_edit":
		return contracts.WorkstationPermissionFileWrite
	case "mcp_tool_call":
		return contracts.WorkstationPermissionMCPMutate
	case "memory_write":
		return contracts.WorkstationPermissionMemoryWrite
	case "recurring_loop":
		return contracts.WorkstationPermissionLoopRegister
	case "deploy_publish":
		return contracts.WorkstationPermissionDeployPublish
	case "secret_read":
		return contracts.WorkstationPermissionSecretRead
	case "payment_initiate":
		return contracts.WorkstationPermissionPaymentInitiate
	case "shell_operate":
		return contracts.WorkstationPermissionShellOperate
	default:
		return effectType
	}
}

func permissionGranted(permissions []string, effectType, required string) bool {
	for _, permission := range permissions {
		if strings.EqualFold(permission, effectType) || strings.EqualFold(permission, required) {
			return true
		}
	}
	return false
}

func draftTargetAllowed(roots []string, target string) bool {
	target = filepath.Clean(strings.TrimSpace(target))
	if target == "." || target == "" {
		return true
	}
	if filepath.IsAbs(target) {
		for _, root := range roots {
			root = filepath.Clean(strings.TrimSpace(root))
			if root == "" || root == "." || !filepath.IsAbs(root) {
				continue
			}
			if target == root || strings.HasPrefix(target, root+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}
	if target == ".." || strings.HasPrefix(target, ".."+string(filepath.Separator)) {
		return false
	}
	for _, root := range roots {
		root = filepath.Clean(strings.TrimSpace(root))
		if root == "." || root == "" {
			return true
		}
		if !filepath.IsAbs(root) && (target == root || strings.HasPrefix(target, root+string(filepath.Separator))) {
			return true
		}
	}
	return false
}

// egressAllowed compares a parsed destination with the allowlist. Each entry
// host goes through the same canonical form as the destination, so the two
// cannot differ by case, a trailing dot, punycode or IPv6 spelling. An entry
// whose host is not a bare host name or address matches nothing. Ports are
// not compared: an entry allows its host on every port.
func egressAllowed(allowlist []contracts.WorkstationEgressDestination, destination netdest.Destination) bool {
	for _, entry := range allowlist {
		host, err := netdest.CanonicalHost(strings.TrimSpace(entry.Host))
		if err != nil || host != destination.Host {
			continue
		}
		if entry.Protocol == "" || strings.EqualFold(strings.TrimSpace(entry.Protocol), destination.Scheme) {
			return true
		}
	}
	return false
}
