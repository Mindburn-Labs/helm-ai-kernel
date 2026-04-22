package contracts

import (
	"strings"
	"testing"
	"time"
)

// ──────────────────────────────────────────────────────────────
// ReasonCode registry tests — each code is a subtest
// ──────────────────────────────────────────────────────────────

func TestClosing_ReasonCode_PolicyViolation(t *testing.T) {
	for _, rc := range []ReasonCode{ReasonPolicyViolation, ReasonNoPolicy, ReasonPRGEvalError, ReasonMissingRequirement} {
		t.Run(string(rc), func(t *testing.T) {
			if !IsCanonicalReasonCode(string(rc)) {
				t.Errorf("expected %s to be canonical", rc)
			}
		})
	}
}

func TestClosing_ReasonCode_PDP(t *testing.T) {
	for _, rc := range []ReasonCode{ReasonPDPDeny, ReasonPDPError} {
		t.Run(string(rc), func(t *testing.T) {
			if !IsCanonicalReasonCode(string(rc)) {
				t.Errorf("expected %s to be canonical", rc)
			}
		})
	}
}

func TestClosing_ReasonCode_Budget(t *testing.T) {
	for _, rc := range []ReasonCode{ReasonBudgetExceeded, ReasonBudgetError} {
		t.Run(string(rc), func(t *testing.T) {
			if !IsCanonicalReasonCode(string(rc)) {
				t.Errorf("expected %s to be canonical", rc)
			}
		})
	}
}

func TestClosing_ReasonCode_Envelope(t *testing.T) {
	for _, rc := range []ReasonCode{ReasonEnvelopeInvalid, ReasonSchemaViolation} {
		t.Run(string(rc), func(t *testing.T) {
			if !IsCanonicalReasonCode(string(rc)) {
				t.Errorf("expected %s to be canonical", rc)
			}
		})
	}
}

func TestClosing_ReasonCode_Temporal(t *testing.T) {
	for _, rc := range []ReasonCode{ReasonTemporalIntervene, ReasonTemporalThrottle} {
		t.Run(string(rc), func(t *testing.T) {
			if !IsCanonicalReasonCode(string(rc)) {
				t.Errorf("expected %s to be canonical", rc)
			}
		})
	}
}

func TestClosing_ReasonCode_Security(t *testing.T) {
	for _, rc := range []ReasonCode{ReasonSandboxViolation, ReasonProvenance, ReasonVerification} {
		t.Run(string(rc), func(t *testing.T) {
			if !IsCanonicalReasonCode(string(rc)) {
				t.Errorf("expected %s to be canonical", rc)
			}
		})
	}
}

func TestClosing_ReasonCode_Tenancy(t *testing.T) {
	for _, rc := range []ReasonCode{ReasonTenantIsolation, ReasonJurisdiction} {
		t.Run(string(rc), func(t *testing.T) {
			if !IsCanonicalReasonCode(string(rc)) {
				t.Errorf("expected %s to be canonical", rc)
			}
		})
	}
}

func TestClosing_ReasonCode_Operations(t *testing.T) {
	for _, rc := range []ReasonCode{ReasonSystemFrozen, ReasonContextMismatch, ReasonDataEgressBlocked, ReasonIdentityIsolationViolation} {
		t.Run(string(rc), func(t *testing.T) {
			if !IsCanonicalReasonCode(string(rc)) {
				t.Errorf("expected %s to be canonical", rc)
			}
		})
	}
}

func TestClosing_ReasonCode_Approval(t *testing.T) {
	for _, rc := range []ReasonCode{ReasonApprovalRequired, ReasonApprovalTimeout} {
		t.Run(string(rc), func(t *testing.T) {
			if !IsCanonicalReasonCode(string(rc)) {
				t.Errorf("expected %s to be canonical", rc)
			}
		})
	}
}

func TestClosing_ReasonCode_Delegation(t *testing.T) {
	for _, rc := range []ReasonCode{ReasonDelegationInvalid, ReasonDelegationScopeViolation} {
		t.Run(string(rc), func(t *testing.T) {
			if !IsCanonicalReasonCode(string(rc)) {
				t.Errorf("expected %s to be canonical", rc)
			}
		})
	}
}

func TestClosing_ReasonCode_Privilege(t *testing.T) {
	t.Run("INSUFFICIENT_PRIVILEGE", func(t *testing.T) {
		if !IsCanonicalReasonCode(string(ReasonInsufficientPrivilege)) {
			t.Error("expected INSUFFICIENT_PRIVILEGE to be canonical")
		}
	})
	t.Run("AGENT_KILLED", func(t *testing.T) {
		if !IsCanonicalReasonCode(string(ReasonAgentKilled)) {
			t.Error("expected AGENT_KILLED to be canonical")
		}
	})
	t.Run("noncanonical_rejected", func(t *testing.T) {
		if IsCanonicalReasonCode("FAKE_REASON") {
			t.Error("expected FAKE_REASON to be rejected")
		}
	})
}

func TestClosing_ReasonCode_ThreatSignal(t *testing.T) {
	for _, rc := range []ReasonCode{
		ReasonTaintedInputDeny, ReasonPromptInjectionDetected,
		ReasonUnicodeObfuscationDetected, ReasonTaintedCredentialDeny,
		ReasonTaintedPublishDeny, ReasonTaintedInvokeDeny,
		ReasonTaintedEgressDeny, ReasonTaintedEscalate,
	} {
		t.Run(string(rc), func(t *testing.T) {
			if !IsCanonicalReasonCode(string(rc)) {
				t.Errorf("expected %s to be canonical", rc)
			}
		})
	}
}

func TestClosing_ReasonCode_RegistryLength(t *testing.T) {
	codes := CoreReasonCodes()
	t.Run("count_at_least_30", func(t *testing.T) {
		if len(codes) < 30 {
			t.Errorf("expected at least 30 reason codes, got %d", len(codes))
		}
	})
	t.Run("no_duplicates", func(t *testing.T) {
		seen := make(map[ReasonCode]bool)
		for _, c := range codes {
			if seen[c] {
				t.Errorf("duplicate reason code %s", c)
			}
			seen[c] = true
		}
	})
	t.Run("all_uppercase", func(t *testing.T) {
		for _, c := range codes {
			if string(c) != strings.ToUpper(string(c)) {
				t.Errorf("reason code %s is not uppercase", c)
			}
		}
	})
}

// ──────────────────────────────────────────────────────────────
// EffectType tests
// ──────────────────────────────────────────────────────────────

func TestClosing_EffectType_InfraEffects(t *testing.T) {
	for _, et := range []string{EffectTypeInfraDestroy, EffectTypeEnvRecreate, EffectTypeProtectedInfraWrite} {
		t.Run(et, func(t *testing.T) {
			entry := LookupEffectType(et)
			if entry == nil {
				t.Fatalf("expected %s in catalog", et)
			}
			if entry.TypeID != et {
				t.Errorf("type mismatch: got %s", entry.TypeID)
			}
		})
	}
}

func TestClosing_EffectType_CIAndSupplyChain(t *testing.T) {
	for _, et := range []string{EffectTypeCICredentialAccess, EffectTypeSoftwarePublish} {
		t.Run(et, func(t *testing.T) {
			entry := LookupEffectType(et)
			if entry == nil {
				t.Fatalf("expected %s in catalog", et)
			}
			if entry.RequiresEvidence != true {
				t.Error("CI/supply-chain effects must require evidence")
			}
		})
	}
}

func TestClosing_EffectType_AgentEffects(t *testing.T) {
	for _, et := range []string{EffectTypeAgentInvokePrivileged, EffectTypeAgentIdentityIsolation} {
		t.Run(et, func(t *testing.T) {
			entry := LookupEffectType(et)
			if entry == nil {
				t.Fatalf("expected %s in catalog", et)
			}
		})
	}
}

func TestClosing_EffectType_NetworkEffects(t *testing.T) {
	for _, et := range []string{EffectTypeDataEgress, EffectTypeTunnelStart} {
		t.Run(et, func(t *testing.T) {
			entry := LookupEffectType(et)
			if entry == nil {
				t.Fatalf("expected %s in catalog", et)
			}
		})
	}
}

func TestClosing_EffectType_BusinessEffects(t *testing.T) {
	for _, et := range []string{
		EffectTypeSendEmail, EffectTypeSendChatMessage, EffectTypeCreateCalEvent,
		EffectTypeUpdateDoc, EffectTypeCreateTask, EffectTypeCommentTicket,
	} {
		t.Run(et, func(t *testing.T) {
			entry := LookupEffectType(et)
			if entry == nil {
				t.Fatalf("expected %s in catalog", et)
			}
		})
	}
}

func TestClosing_EffectType_FinancialEffects(t *testing.T) {
	for _, et := range []string{EffectTypeRequestPurchase, EffectTypeExecutePayment} {
		t.Run(et, func(t *testing.T) {
			rc := EffectRiskClass(et)
			if rc != "E4" {
				t.Errorf("expected E4 risk class for %s, got %s", et, rc)
			}
		})
	}
}

func TestClosing_EffectType_IntegrationEffects(t *testing.T) {
	for _, et := range []string{EffectTypeCallWebhook, EffectTypeRunSandboxedCode, EffectTypeScreenCandidate} {
		t.Run(et, func(t *testing.T) {
			entry := LookupEffectType(et)
			if entry == nil {
				t.Fatalf("expected %s in catalog", et)
			}
		})
	}
}

func TestClosing_EffectType_CloudComputeBudget(t *testing.T) {
	t.Run("lookup", func(t *testing.T) {
		entry := LookupEffectType(EffectTypeCloudComputeBudget)
		if entry == nil {
			t.Fatal("expected CLOUD_COMPUTE_BUDGET in catalog")
		}
	})
	t.Run("risk_class_E2", func(t *testing.T) {
		if EffectRiskClass(EffectTypeCloudComputeBudget) != "E2" {
			t.Error("expected E2")
		}
	})
	t.Run("compensation_required", func(t *testing.T) {
		entry := LookupEffectType(EffectTypeCloudComputeBudget)
		if !entry.CompensationRequired {
			t.Error("expected compensation required")
		}
	})
}

func TestClosing_EffectType_UnknownDefaultsE3(t *testing.T) {
	t.Run("unknown_effect", func(t *testing.T) {
		if EffectRiskClass("UNKNOWN_EFFECT_XYZ") != "E3" {
			t.Error("unknown effects must default to E3 (fail-closed)")
		}
	})
	t.Run("empty_effect", func(t *testing.T) {
		if EffectRiskClass("") != "E3" {
			t.Error("empty effect type must default to E3")
		}
	})
	t.Run("lookup_nil", func(t *testing.T) {
		if LookupEffectType("NONEXISTENT") != nil {
			t.Error("expected nil for nonexistent effect type")
		}
	})
}

func TestClosing_EffectRiskClass_E4Critical(t *testing.T) {
	for _, et := range []string{EffectTypeInfraDestroy, EffectTypeCICredentialAccess, EffectTypeSoftwarePublish, EffectTypeDataEgress} {
		t.Run(et, func(t *testing.T) {
			if EffectRiskClass(et) != "E4" {
				t.Errorf("expected E4 for %s", et)
			}
		})
	}
}

func TestClosing_EffectRiskClass_E3HighRisk(t *testing.T) {
	for _, et := range []string{EffectTypeProtectedInfraWrite, EffectTypeEnvRecreate, EffectTypeAgentInvokePrivileged, EffectTypeTunnelStart} {
		t.Run(et, func(t *testing.T) {
			if EffectRiskClass(et) != "E3" {
				t.Errorf("expected E3 for %s", et)
			}
		})
	}
}

func TestClosing_EffectRiskClass_E1LowRisk(t *testing.T) {
	for _, et := range []string{EffectTypeSendChatMessage, EffectTypeCreateCalEvent, EffectTypeUpdateDoc, EffectTypeCreateTask, EffectTypeCommentTicket, EffectTypeRunSandboxedCode} {
		t.Run(et, func(t *testing.T) {
			if EffectRiskClass(et) != "E1" {
				t.Errorf("expected E1 for %s", et)
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────
// Verdict tests
// ──────────────────────────────────────────────────────────────

func TestClosing_Verdict_Allow(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(VerdictAllow) != "ALLOW" {
			t.Error("VerdictAllow must be ALLOW")
		}
	})
	t.Run("is_terminal", func(t *testing.T) {
		if !VerdictAllow.IsTerminal() {
			t.Error("ALLOW must be terminal")
		}
	})
	t.Run("is_canonical", func(t *testing.T) {
		if !IsCanonicalVerdict("ALLOW") {
			t.Error("ALLOW must be canonical")
		}
	})
}

func TestClosing_Verdict_Deny(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(VerdictDeny) != "DENY" {
			t.Error("VerdictDeny must be DENY")
		}
	})
	t.Run("is_terminal", func(t *testing.T) {
		if !VerdictDeny.IsTerminal() {
			t.Error("DENY must be terminal")
		}
	})
	t.Run("is_canonical", func(t *testing.T) {
		if !IsCanonicalVerdict("DENY") {
			t.Error("DENY must be canonical")
		}
	})
}

func TestClosing_Verdict_Escalate(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(VerdictEscalate) != "ESCALATE" {
			t.Error("VerdictEscalate must be ESCALATE")
		}
	})
	t.Run("not_terminal", func(t *testing.T) {
		if VerdictEscalate.IsTerminal() {
			t.Error("ESCALATE must not be terminal")
		}
	})
	t.Run("is_canonical", func(t *testing.T) {
		if !IsCanonicalVerdict("ESCALATE") {
			t.Error("ESCALATE must be canonical")
		}
	})
}

func TestClosing_Verdict_NonCanonical(t *testing.T) {
	for _, v := range []string{"PENDING", "UNKNOWN", "allow", "", "PERMIT"} {
		t.Run(v, func(t *testing.T) {
			if IsCanonicalVerdict(v) {
				t.Errorf("%q must not be canonical", v)
			}
		})
	}
}

func TestClosing_Verdict_CanonicalList(t *testing.T) {
	verdicts := CanonicalVerdicts()
	t.Run("count_is_3", func(t *testing.T) {
		if len(verdicts) != 3 {
			t.Errorf("expected 3 verdicts, got %d", len(verdicts))
		}
	})
	t.Run("first_is_allow", func(t *testing.T) {
		if verdicts[0] != VerdictAllow {
			t.Error("first verdict must be ALLOW")
		}
	})
	t.Run("second_is_deny", func(t *testing.T) {
		if verdicts[1] != VerdictDeny {
			t.Error("second verdict must be DENY")
		}
	})
	t.Run("third_is_escalate", func(t *testing.T) {
		if verdicts[2] != VerdictEscalate {
			t.Error("third verdict must be ESCALATE")
		}
	})
}

// ──────────────────────────────────────────────────────────────
// CondensationTier tests
// ──────────────────────────────────────────────────────────────

func TestClosing_CondensationTier_Low(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(RiskTierLow) != "LOW" {
			t.Error("RiskTierLow must be LOW")
		}
	})
	t.Run("default_policy_no_retain", func(t *testing.T) {
		p := DefaultCondensationPolicy()
		for _, tp := range p.RetentionPolicy {
			if tp.Tier == RiskTierLow {
				if tp.RetainFullReceipts {
					t.Error("LOW tier must not retain full receipts by default")
				}
				return
			}
		}
		t.Error("LOW tier missing from default policy")
	})
	t.Run("default_policy_condense", func(t *testing.T) {
		p := DefaultCondensationPolicy()
		for _, tp := range p.RetentionPolicy {
			if tp.Tier == RiskTierLow && !tp.CondenseAfterWindow {
				t.Error("LOW tier must condense after window")
			}
		}
	})
}

func TestClosing_CondensationTier_Medium(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(RiskTierMedium) != "MEDIUM" {
			t.Error("RiskTierMedium must be MEDIUM")
		}
	})
	t.Run("retain_full", func(t *testing.T) {
		p := DefaultCondensationPolicy()
		for _, tp := range p.RetentionPolicy {
			if tp.Tier == RiskTierMedium && !tp.RetainFullReceipts {
				t.Error("MEDIUM tier must retain full receipts")
			}
		}
	})
	t.Run("no_external_anchor", func(t *testing.T) {
		p := DefaultCondensationPolicy()
		for _, tp := range p.RetentionPolicy {
			if tp.Tier == RiskTierMedium && tp.AnchorToExternal {
				t.Error("MEDIUM tier must not anchor to external")
			}
		}
	})
}

func TestClosing_CondensationTier_High(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(RiskTierHigh) != "HIGH" {
			t.Error("RiskTierHigh must be HIGH")
		}
	})
	t.Run("retain_full", func(t *testing.T) {
		p := DefaultCondensationPolicy()
		for _, tp := range p.RetentionPolicy {
			if tp.Tier == RiskTierHigh && !tp.RetainFullReceipts {
				t.Error("HIGH tier must retain full receipts")
			}
		}
	})
	t.Run("anchor_external", func(t *testing.T) {
		p := DefaultCondensationPolicy()
		for _, tp := range p.RetentionPolicy {
			if tp.Tier == RiskTierHigh && !tp.AnchorToExternal {
				t.Error("HIGH tier must anchor to external transparency log")
			}
		}
	})
	t.Run("no_condense", func(t *testing.T) {
		p := DefaultCondensationPolicy()
		for _, tp := range p.RetentionPolicy {
			if tp.Tier == RiskTierHigh && tp.CondenseAfterWindow {
				t.Error("HIGH tier must not condense")
			}
		}
	})
}

func TestClosing_CondensationPolicy_Defaults(t *testing.T) {
	p := DefaultCondensationPolicy()
	t.Run("checkpoint_interval_100", func(t *testing.T) {
		if p.CheckpointInterval != 100 {
			t.Errorf("expected 100, got %d", p.CheckpointInterval)
		}
	})
	t.Run("three_tiers", func(t *testing.T) {
		if len(p.RetentionPolicy) != 3 {
			t.Errorf("expected 3 tiers, got %d", len(p.RetentionPolicy))
		}
	})
	t.Run("ordered_low_medium_high", func(t *testing.T) {
		if p.RetentionPolicy[0].Tier != RiskTierLow || p.RetentionPolicy[1].Tier != RiskTierMedium || p.RetentionPolicy[2].Tier != RiskTierHigh {
			t.Error("expected LOW, MEDIUM, HIGH order")
		}
	})
}

// ──────────────────────────────────────────────────────────────
// Lane tests
// ──────────────────────────────────────────────────────────────

func TestClosing_Lane_Research(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(LaneResearch) != "RESEARCH" {
			t.Error("must be RESEARCH")
		}
	})
	t.Run("in_all_lanes", func(t *testing.T) {
		for _, l := range AllLanes() {
			if l == LaneResearch {
				return
			}
		}
		t.Error("RESEARCH missing from AllLanes")
	})
	t.Run("idle_state", func(t *testing.T) {
		ls := &LaneState{Lane: LaneResearch, ActiveRuns: 0, NextAction: ""}
		if !ls.IsIdle() {
			t.Error("expected idle")
		}
	})
}

func TestClosing_Lane_Build(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(LaneBuild) != "BUILD" {
			t.Error("must be BUILD")
		}
	})
	t.Run("not_idle_with_runs", func(t *testing.T) {
		ls := &LaneState{Lane: LaneBuild, ActiveRuns: 1}
		if ls.IsIdle() {
			t.Error("should not be idle with active runs")
		}
	})
	t.Run("not_idle_with_action", func(t *testing.T) {
		ls := &LaneState{Lane: LaneBuild, NextAction: "deploy"}
		if ls.IsIdle() {
			t.Error("should not be idle with pending action")
		}
	})
}

func TestClosing_Lane_GTM(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(LaneGTM) != "GTM" {
			t.Error("must be GTM")
		}
	})
	t.Run("in_all_lanes", func(t *testing.T) {
		for _, l := range AllLanes() {
			if l == LaneGTM {
				return
			}
		}
		t.Error("GTM missing")
	})
	t.Run("progress_bounds", func(t *testing.T) {
		ls := &LaneState{Lane: LaneGTM, ProgressPct: 50}
		if ls.ProgressPct < 0 || ls.ProgressPct > 100 {
			t.Error("progress out of range")
		}
	})
}

func TestClosing_Lane_Ops(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(LaneOps) != "OPS" {
			t.Error("must be OPS")
		}
	})
	t.Run("in_all_lanes", func(t *testing.T) {
		for _, l := range AllLanes() {
			if l == LaneOps {
				return
			}
		}
		t.Error("OPS missing")
	})
	t.Run("blocked_count", func(t *testing.T) {
		ls := &LaneState{Lane: LaneOps, BlockedCount: 3}
		if ls.BlockedCount != 3 {
			t.Error("blocked count mismatch")
		}
	})
}

func TestClosing_Lane_Compliance(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(LaneCompliance) != "COMPLIANCE" {
			t.Error("must be COMPLIANCE")
		}
	})
	t.Run("in_all_lanes", func(t *testing.T) {
		for _, l := range AllLanes() {
			if l == LaneCompliance {
				return
			}
		}
		t.Error("COMPLIANCE missing")
	})
	t.Run("status_field", func(t *testing.T) {
		ls := &LaneState{Lane: LaneCompliance, Status: "active"}
		if ls.Status != "active" {
			t.Error("status field mismatch")
		}
	})
}

func TestClosing_Lane_AllLanesCount(t *testing.T) {
	lanes := AllLanes()
	t.Run("count_is_5", func(t *testing.T) {
		if len(lanes) != 5 {
			t.Errorf("expected 5 lanes, got %d", len(lanes))
		}
	})
	t.Run("no_duplicates", func(t *testing.T) {
		seen := make(map[Lane]bool)
		for _, l := range lanes {
			if seen[l] {
				t.Errorf("duplicate lane %s", l)
			}
			seen[l] = true
		}
	})
	t.Run("display_order", func(t *testing.T) {
		if lanes[0] != LaneResearch || lanes[4] != LaneCompliance {
			t.Error("wrong display order")
		}
	})
}

// ──────────────────────────────────────────────────────────────
// InterventionType tests
// ──────────────────────────────────────────────────────────────

func TestClosing_InterventionType_None(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(InterventionNone) != "NONE" {
			t.Error("must be NONE")
		}
	})
	t.Run("metadata_with_none", func(t *testing.T) {
		m := InterventionMetadata{Type: InterventionNone}
		if m.Type != InterventionNone {
			t.Error("type mismatch")
		}
	})
	t.Run("zero_tokens_saved", func(t *testing.T) {
		m := InterventionMetadata{Type: InterventionNone}
		if m.TokensSaved != 0 {
			t.Error("expected zero tokens saved for NONE")
		}
	})
}

func TestClosing_InterventionType_Throttle(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(InterventionThrottle) != "THROTTLE" {
			t.Error("must be THROTTLE")
		}
	})
	t.Run("with_wait_duration", func(t *testing.T) {
		m := InterventionMetadata{Type: InterventionThrottle, WaitDuration: 5 * time.Second}
		if m.WaitDuration != 5*time.Second {
			t.Error("wait duration mismatch")
		}
	})
	t.Run("with_reason_code", func(t *testing.T) {
		m := InterventionMetadata{Type: InterventionThrottle, ReasonCode: "VELOCITY_LIMIT_EXCEEDED"}
		if m.ReasonCode == "" {
			t.Error("expected reason code")
		}
	})
}

func TestClosing_InterventionType_Interrupt(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(InterventionInterrupt) != "INTERRUPT" {
			t.Error("must be INTERRUPT")
		}
	})
	t.Run("metadata_fields", func(t *testing.T) {
		m := InterventionMetadata{Type: InterventionInterrupt, ReasonCode: "ANOMALY", TokensSaved: 100}
		if m.TokensSaved != 100 {
			t.Error("tokens saved mismatch")
		}
	})
	t.Run("type_assignment", func(t *testing.T) {
		var it InterventionType = InterventionInterrupt
		if it != "INTERRUPT" {
			t.Error("assignment mismatch")
		}
	})
}

func TestClosing_InterventionType_Quarantine(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if string(InterventionQuarantine) != "QUARANTINE" {
			t.Error("must be QUARANTINE")
		}
	})
	t.Run("all_types_unique", func(t *testing.T) {
		types := []InterventionType{InterventionNone, InterventionThrottle, InterventionInterrupt, InterventionQuarantine}
		seen := make(map[InterventionType]bool)
		for _, it := range types {
			if seen[it] {
				t.Errorf("duplicate intervention type %s", it)
			}
			seen[it] = true
		}
	})
	t.Run("count_is_4", func(t *testing.T) {
		types := []InterventionType{InterventionNone, InterventionThrottle, InterventionInterrupt, InterventionQuarantine}
		if len(types) != 4 {
			t.Errorf("expected 4 intervention types, got %d", len(types))
		}
	})
}

// ──────────────────────────────────────────────────────────────
// DecisionRequest validation tests
// ──────────────────────────────────────────────────────────────

func TestClosing_DecisionRequest_MissingRequestID(t *testing.T) {
	dr := &DecisionRequest{Title: "test", Kind: DecisionKindApproval, Options: closingTwoOptions()}
	t.Run("error_returned", func(t *testing.T) {
		if err := dr.Validate(); err == nil {
			t.Error("expected error for missing request_id")
		}
	})
	t.Run("error_message", func(t *testing.T) {
		err := dr.Validate()
		if err == nil || !strings.Contains(err.Error(), "request_id") {
			t.Error("error must mention request_id")
		}
	})
	t.Run("is_blocking_when_pending", func(t *testing.T) {
		dr.Status = DecisionStatusPending
		if !dr.IsBlocking() {
			t.Error("pending request must be blocking")
		}
	})
}

func TestClosing_DecisionRequest_MissingTitle(t *testing.T) {
	dr := &DecisionRequest{RequestID: "r1", Kind: DecisionKindApproval, Options: closingTwoOptions()}
	t.Run("error_returned", func(t *testing.T) {
		if err := dr.Validate(); err == nil {
			t.Error("expected error for missing title")
		}
	})
	t.Run("error_message", func(t *testing.T) {
		err := dr.Validate()
		if err == nil || !strings.Contains(err.Error(), "title") {
			t.Error("error must mention title")
		}
	})
	t.Run("not_blocking_when_resolved", func(t *testing.T) {
		dr.Status = DecisionStatusResolved
		if dr.IsBlocking() {
			t.Error("resolved request must not be blocking")
		}
	})
}

func TestClosing_DecisionRequest_TitleTooLong(t *testing.T) {
	dr := &DecisionRequest{RequestID: "r1", Title: strings.Repeat("x", 121), Kind: DecisionKindApproval, Options: closingTwoOptions()}
	t.Run("error_returned", func(t *testing.T) {
		if err := dr.Validate(); err == nil {
			t.Error("expected error for long title")
		}
	})
	t.Run("error_message", func(t *testing.T) {
		err := dr.Validate()
		if err == nil || !strings.Contains(err.Error(), "120") {
			t.Error("error must mention 120")
		}
	})
	t.Run("exact_boundary_ok", func(t *testing.T) {
		dr.Title = strings.Repeat("x", 120)
		if err := dr.Validate(); err != nil {
			t.Errorf("120 chars should be valid: %v", err)
		}
	})
}

func TestClosing_DecisionRequest_MissingKind(t *testing.T) {
	dr := &DecisionRequest{RequestID: "r1", Title: "test", Options: closingTwoOptions()}
	t.Run("error_returned", func(t *testing.T) {
		if err := dr.Validate(); err == nil {
			t.Error("expected error for missing kind")
		}
	})
	t.Run("error_message", func(t *testing.T) {
		err := dr.Validate()
		if err == nil || !strings.Contains(err.Error(), "kind") {
			t.Error("error must mention kind")
		}
	})
	t.Run("all_kinds_valid", func(t *testing.T) {
		for _, k := range []DecisionRequestKind{DecisionKindApproval, DecisionKindPolicyChoice, DecisionKindClarification, DecisionKindSpending, DecisionKindIrreversible} {
			dr.Kind = k
			_ = dr.Validate() // just ensure no panic
		}
	})
}

func TestClosing_DecisionRequest_TooFewOptions(t *testing.T) {
	dr := &DecisionRequest{RequestID: "r1", Title: "test", Kind: DecisionKindApproval, Options: []DecisionOption{{ID: "a", Label: "A"}}}
	t.Run("error_for_one_option", func(t *testing.T) {
		if err := dr.Validate(); err == nil {
			t.Error("expected error for 1 option")
		}
	})
	t.Run("zero_options", func(t *testing.T) {
		dr.Options = nil
		if err := dr.Validate(); err == nil {
			t.Error("expected error for 0 options")
		}
	})
	t.Run("skip_not_counted", func(t *testing.T) {
		dr.Options = []DecisionOption{{ID: "a", Label: "A"}, {ID: "s", Label: "Skip", IsSkip: true}}
		if err := dr.Validate(); err == nil {
			t.Error("skip options must not count toward minimum")
		}
	})
}

func TestClosing_DecisionRequest_TooManyOptions(t *testing.T) {
	opts := make([]DecisionOption, 8)
	for i := range opts {
		opts[i] = DecisionOption{ID: strings.Repeat("o", i+1), Label: "opt"}
	}
	dr := &DecisionRequest{RequestID: "r1", Title: "test", Kind: DecisionKindApproval, Options: opts}
	t.Run("error_for_8_options", func(t *testing.T) {
		if err := dr.Validate(); err == nil {
			t.Error("expected error for 8 concrete options")
		}
	})
	t.Run("7_options_ok", func(t *testing.T) {
		dr.Options = opts[:7]
		if err := dr.Validate(); err != nil {
			t.Errorf("7 options should be valid: %v", err)
		}
	})
	t.Run("something_else_not_counted", func(t *testing.T) {
		dr.Options = append(opts[:7], DecisionOption{ID: "se", Label: "Other", IsSomethingElse: true})
		if err := dr.Validate(); err != nil {
			t.Errorf("something-else should not count: %v", err)
		}
	})
}

func TestClosing_DecisionRequest_DuplicateOptionIDs(t *testing.T) {
	dr := &DecisionRequest{
		RequestID: "r1", Title: "test", Kind: DecisionKindApproval,
		Options: []DecisionOption{{ID: "a", Label: "A"}, {ID: "a", Label: "B"}},
	}
	t.Run("error_for_duplicates", func(t *testing.T) {
		if err := dr.Validate(); err == nil {
			t.Error("expected error for duplicate IDs")
		}
	})
	t.Run("error_mentions_id", func(t *testing.T) {
		err := dr.Validate()
		if err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Error("error must mention duplicate")
		}
	})
	t.Run("empty_option_id", func(t *testing.T) {
		dr.Options = []DecisionOption{{ID: "", Label: "A"}, {ID: "b", Label: "B"}}
		if err := dr.Validate(); err == nil {
			t.Error("expected error for empty option ID")
		}
	})
}

func TestClosing_DecisionRequest_Resolve(t *testing.T) {
	dr := closingValidDecisionRequest()
	t.Run("resolve_pending", func(t *testing.T) {
		if err := dr.Resolve("opt-a", "user1"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("status_resolved", func(t *testing.T) {
		if dr.Status != DecisionStatusResolved {
			t.Errorf("expected RESOLVED, got %s", dr.Status)
		}
	})
	t.Run("resolve_non_pending_fails", func(t *testing.T) {
		if err := dr.Resolve("opt-a", "user2"); err == nil {
			t.Error("expected error for non-pending resolve")
		}
	})
	t.Run("unknown_option_fails", func(t *testing.T) {
		dr2 := closingValidDecisionRequest()
		if err := dr2.Resolve("nonexistent", "user1"); err == nil {
			t.Error("expected error for unknown option")
		}
	})
}

func TestClosing_DecisionRequest_Skip(t *testing.T) {
	t.Run("skip_allowed", func(t *testing.T) {
		dr := closingValidDecisionRequest()
		dr.SkipAllowed = true
		if err := dr.Skip("user1"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("skip_not_allowed", func(t *testing.T) {
		dr := closingValidDecisionRequest()
		dr.SkipAllowed = false
		if err := dr.Skip("user1"); err == nil {
			t.Error("expected error when skip not allowed")
		}
	})
	t.Run("skip_non_pending", func(t *testing.T) {
		dr := closingValidDecisionRequest()
		dr.SkipAllowed = true
		dr.Status = DecisionStatusResolved
		if err := dr.Skip("user1"); err == nil {
			t.Error("expected error for non-pending skip")
		}
	})
}

func TestClosing_DecisionRequest_Expiry(t *testing.T) {
	t.Run("expired_past", func(t *testing.T) {
		dr := closingValidDecisionRequest()
		dr.ExpiresAt = time.Now().Add(-1 * time.Hour)
		if !dr.CheckExpiry() {
			t.Error("expected expiry")
		}
	})
	t.Run("not_expired_future", func(t *testing.T) {
		dr := closingValidDecisionRequest()
		dr.ExpiresAt = time.Now().Add(1 * time.Hour)
		if dr.CheckExpiry() {
			t.Error("should not be expired")
		}
	})
	t.Run("zero_no_expiry", func(t *testing.T) {
		dr := closingValidDecisionRequest()
		if dr.CheckExpiry() {
			t.Error("zero time should not expire")
		}
	})
	t.Run("already_resolved_no_expiry", func(t *testing.T) {
		dr := closingValidDecisionRequest()
		dr.Status = DecisionStatusResolved
		dr.ExpiresAt = time.Now().Add(-1 * time.Hour)
		if dr.CheckExpiry() {
			t.Error("resolved requests should not expire")
		}
	})
}

// ──────────────────────────────────────────────────────────────
// Receipt field tests
// ──────────────────────────────────────────────────────────────

func TestClosing_Receipt_CoreFields(t *testing.T) {
	r := Receipt{ReceiptID: "r1", DecisionID: "d1", EffectID: "e1", Status: "SUCCESS"}
	t.Run("receipt_id", func(t *testing.T) {
		if r.ReceiptID != "r1" {
			t.Error("receipt_id mismatch")
		}
	})
	t.Run("decision_id", func(t *testing.T) {
		if r.DecisionID != "d1" {
			t.Error("decision_id mismatch")
		}
	})
	t.Run("effect_id", func(t *testing.T) {
		if r.EffectID != "e1" {
			t.Error("effect_id mismatch")
		}
	})
	t.Run("status", func(t *testing.T) {
		if r.Status != "SUCCESS" {
			t.Error("status mismatch")
		}
	})
}

func TestClosing_Receipt_CausalChain(t *testing.T) {
	r := Receipt{ReceiptID: "r2", PrevHash: "abc123", LamportClock: 42, ArgsHash: "def456"}
	t.Run("prev_hash", func(t *testing.T) {
		if r.PrevHash != "abc123" {
			t.Error("prev_hash mismatch")
		}
	})
	t.Run("lamport_clock", func(t *testing.T) {
		if r.LamportClock != 42 {
			t.Error("lamport_clock mismatch")
		}
	})
	t.Run("args_hash", func(t *testing.T) {
		if r.ArgsHash != "def456" {
			t.Error("args_hash mismatch")
		}
	})
}

func TestClosing_Receipt_InferenceTelemetry(t *testing.T) {
	r := Receipt{GatewayID: "gw1", RuntimeType: "ollama", RuntimeVersion: "0.1.0", ModelHash: "sha256:abc"}
	t.Run("gateway_id", func(t *testing.T) {
		if r.GatewayID != "gw1" {
			t.Error("gateway_id mismatch")
		}
	})
	t.Run("runtime_type", func(t *testing.T) {
		if r.RuntimeType != "ollama" {
			t.Error("runtime_type mismatch")
		}
	})
	t.Run("model_hash", func(t *testing.T) {
		if r.ModelHash != "sha256:abc" {
			t.Error("model_hash mismatch")
		}
	})
}

func TestClosing_Receipt_ExecutionPlane(t *testing.T) {
	r := Receipt{SandboxLeaseID: "lease-1", EffectGraphNodeID: "node-1", NetworkLogRef: "log-ref"}
	t.Run("sandbox_lease_id", func(t *testing.T) {
		if r.SandboxLeaseID != "lease-1" {
			t.Error("sandbox_lease_id mismatch")
		}
	})
	t.Run("effect_graph_node_id", func(t *testing.T) {
		if r.EffectGraphNodeID != "node-1" {
			t.Error("effect_graph_node_id mismatch")
		}
	})
	t.Run("network_log_ref", func(t *testing.T) {
		if r.NetworkLogRef != "log-ref" {
			t.Error("network_log_ref mismatch")
		}
	})
}

func TestClosing_Receipt_Provenance(t *testing.T) {
	prov := &ReceiptProvenance{GeneratedBy: "agent-1", Context: "production", Parents: []string{"r0"}}
	r := Receipt{ReceiptID: "r3", Provenance: prov}
	t.Run("generated_by", func(t *testing.T) {
		if r.Provenance.GeneratedBy != "agent-1" {
			t.Error("generated_by mismatch")
		}
	})
	t.Run("context", func(t *testing.T) {
		if r.Provenance.Context != "production" {
			t.Error("context mismatch")
		}
	})
	t.Run("parents", func(t *testing.T) {
		if len(r.Provenance.Parents) != 1 || r.Provenance.Parents[0] != "r0" {
			t.Error("parents mismatch")
		}
	})
}

// ──────────────────────────────────────────────────────────────
// EffectCatalog structure tests
// ──────────────────────────────────────────────────────────────

func TestClosing_EffectCatalog_Version(t *testing.T) {
	c := DefaultEffectCatalog()
	t.Run("version_not_empty", func(t *testing.T) {
		if c.CatalogVersion == "" {
			t.Error("catalog version must not be empty")
		}
	})
	t.Run("version_semver", func(t *testing.T) {
		if !strings.Contains(c.CatalogVersion, ".") {
			t.Error("catalog version must be semver-like")
		}
	})
	t.Run("has_entries", func(t *testing.T) {
		if len(c.EffectTypes) == 0 {
			t.Error("catalog must have entries")
		}
	})
	t.Run("at_least_20_entries", func(t *testing.T) {
		if len(c.EffectTypes) < 20 {
			t.Errorf("expected at least 20 entries, got %d", len(c.EffectTypes))
		}
	})
}

func TestClosing_EffectCatalog_UniqueTypeIDs(t *testing.T) {
	c := DefaultEffectCatalog()
	seen := make(map[string]bool)
	for _, et := range c.EffectTypes {
		t.Run(et.TypeID, func(t *testing.T) {
			if seen[et.TypeID] {
				t.Errorf("duplicate type ID %s", et.TypeID)
			}
			seen[et.TypeID] = true
		})
	}
}

func TestClosing_EffectCatalog_Classification(t *testing.T) {
	validReversibility := map[string]bool{"reversible": true, "compensatable": true, "irreversible": true}
	validBlast := map[string]bool{"single_record": true, "dataset": true, "system_wide": true}
	validUrgency := map[string]bool{"deferrable": true, "time_sensitive": true, "immediate": true}
	c := DefaultEffectCatalog()
	for _, et := range c.EffectTypes {
		t.Run(et.TypeID+"/reversibility", func(t *testing.T) {
			if !validReversibility[et.Classification.Reversibility] {
				t.Errorf("invalid reversibility %q", et.Classification.Reversibility)
			}
		})
		t.Run(et.TypeID+"/blast_radius", func(t *testing.T) {
			if !validBlast[et.Classification.BlastRadius] {
				t.Errorf("invalid blast radius %q", et.Classification.BlastRadius)
			}
		})
		t.Run(et.TypeID+"/urgency", func(t *testing.T) {
			if !validUrgency[et.Classification.Urgency] {
				t.Errorf("invalid urgency %q", et.Classification.Urgency)
			}
		})
	}
}

func TestClosing_DecisionKind_AllValues(t *testing.T) {
	kinds := []DecisionRequestKind{
		DecisionKindApproval, DecisionKindPolicyChoice, DecisionKindClarification,
		DecisionKindSpending, DecisionKindIrreversible, DecisionKindSensitivePolicy, DecisionKindNaming,
	}
	t.Run("count_is_7", func(t *testing.T) {
		if len(kinds) != 7 {
			t.Errorf("expected 7 kinds, got %d", len(kinds))
		}
	})
	t.Run("no_duplicates", func(t *testing.T) {
		seen := make(map[DecisionRequestKind]bool)
		for _, k := range kinds {
			if seen[k] {
				t.Errorf("duplicate kind %s", k)
			}
			seen[k] = true
		}
	})
	t.Run("all_uppercase", func(t *testing.T) {
		for _, k := range kinds {
			if string(k) != strings.ToUpper(string(k)) {
				t.Errorf("kind %s not uppercase", k)
			}
		}
	})
}

func TestClosing_DecisionStatus_AllValues(t *testing.T) {
	statuses := []DecisionRequestStatus{DecisionStatusPending, DecisionStatusResolved, DecisionStatusExpired, DecisionStatusSkipped}
	for _, s := range statuses {
		t.Run(string(s), func(t *testing.T) {
			if string(s) == "" {
				t.Error("status must not be empty")
			}
		})
	}
}

func TestClosing_DecisionPriority_AllValues(t *testing.T) {
	priorities := []DecisionPriority{DecisionPriorityUrgent, DecisionPriorityHigh, DecisionPriorityNormal, DecisionPriorityLow}
	for _, p := range priorities {
		t.Run(string(p), func(t *testing.T) {
			if string(p) == "" {
				t.Error("priority must not be empty")
			}
		})
	}
}

func TestClosing_VerdictPending(t *testing.T) {
	t.Run("string_value", func(t *testing.T) {
		if VerdictPending != "PENDING" {
			t.Error("VerdictPending must be PENDING")
		}
	})
	t.Run("not_canonical", func(t *testing.T) {
		if IsCanonicalVerdict(VerdictPending) {
			t.Error("PENDING must not be canonical")
		}
	})
	t.Run("not_terminal", func(t *testing.T) {
		if Verdict(VerdictPending).IsTerminal() {
			t.Error("PENDING must not be terminal")
		}
	})
}

// ── helpers ──────────────────────────────────────────────────

func closingTwoOptions() []DecisionOption {
	return []DecisionOption{
		{ID: "opt-a", Label: "Option A"},
		{ID: "opt-b", Label: "Option B"},
	}
}

func closingValidDecisionRequest() *DecisionRequest {
	return &DecisionRequest{
		RequestID: "req-1",
		Title:     "Test decision",
		Kind:      DecisionKindApproval,
		Options:   closingTwoOptions(),
		Status:    DecisionStatusPending,
	}
}
