package workstation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestBuildScopeAuditMixedReceiptsAllBoundaries(t *testing.T) {
	dir := t.TempDir()
	permissive := permissiveScopeAuditProfile()
	result, err := BuildReceipt(scopeAuditManifest(), DiffSummary{
		ChangedFiles: []contracts.AgentChangedFile{{Path: "docs/scope-audit.md", Status: "modified", Additions: 3}},
	}, ValidationArtifact{}, []ToolEvent{
		{
			EventID:    "evt_shell_observe",
			Type:       "shell_command",
			ToolID:     "shell",
			Action:     "git.status",
			EffectType: contracts.EffectTypeWorkstationShellCommand,
			EffectMode: contracts.WorkstationEffectModeObserve,
			Status:     "completed",
			Target:     "git status --short",
			OccurredAt: time.Date(2026, 5, 20, 15, 0, 30, 0, time.UTC),
		},
		scopeAuditEvent("evt_network_allow", "network_egress", contracts.EffectTypeWorkstationNetworkEgress, "network.egress", "https://api.github.com/repos/Mindburn-Labs/helm", nil),
		scopeAuditEvent("evt_mcp_allow", "mcp_tool_call", contracts.EffectTypeWorkstationMCPToolCall, "mcp.trusted.tool", "mcp://trusted-server/tool", nil),
		scopeAuditMemoryEvent("evt_memory_allow"),
		scopeAuditLoopEvent("evt_loop_allow"),
		scopeAuditEvent("evt_secret_allow", "secret_read", contracts.EffectTypeWorkstationSecretRead, "secret.read", "secret://prod/stripe", map[string]string{
			"secret_ref":    "vault://prod/stripe",
			"redaction_ref": "redaction://secret/prod/stripe",
			"api_token":     "raw-secret-token",
		}),
		scopeAuditEvent("evt_deploy_allow", "deploy_publish", contracts.EffectTypeWorkstationDeployPublish, "deploy.publish", "deploy://prod/web", map[string]string{
			"environment":      "production",
			"artifact_digest":  "sha256:deploy",
			"approval_ref":     "approval://deploy/1",
			"rollback_ref":     "rollback://deploy/1",
			"verification_ref": "verify://deploy/1",
		}),
		scopeAuditEvent("evt_payment_allow", "payment_initiate", contracts.EffectTypeWorkstationPaymentInitiate, "payment.initiate", "stripe://charge/1000", map[string]string{
			"amount":           "1000",
			"currency":         "USD",
			"counterparty_ref": "customer://cust_123",
			"spend_cap_ref":    "spend-cap://default",
			"idempotency_key":  "pay_123",
			"ledger_ref":       "ledger://entry/123",
		}),
		scopeAuditEvent("evt_tainted_mcp", "mcp_tool_call", contracts.EffectTypeWorkstationMCPToolCall, "unknown.mcp.tool", "mcp://unknown-server/tool", nil).WithTaint("prompt_injection"),
	}, permissive, map[string]string{ManifestFile: strings.Repeat("a", 64)}, ImportOptions{})
	if err != nil {
		t.Fatalf("BuildReceipt() error = %v", err)
	}
	importPath := filepath.Join(dir, "agent-run.json")
	if err := WriteResult(importPath, result); err != nil {
		t.Fatalf("WriteResult() error = %v", err)
	}
	paymentDecision, err := Decide(DefaultObserveDraftProfile(), contracts.WorkstationDecisionRequest{
		RequestID:  "deny-payment",
		RunID:      "run-payment-deny",
		ToolID:     "payment.initiate",
		Action:     "payment_initiate",
		EffectType: contracts.EffectTypeWorkstationPaymentInitiate,
		EffectMode: contracts.WorkstationEffectModeOperate,
		Target:     "stripe://charge/2500",
		Metadata:   map[string]string{"api_token": "raw-secret-token"},
		OccurredAt: time.Date(2026, 5, 20, 16, 0, 0, 0, time.UTC),
	}, DecisionOptions{})
	if err != nil {
		t.Fatalf("Decide(payment) error = %v", err)
	}
	writeJSONFixture(t, filepath.Join(dir, "payment-deny.json"), paymentDecision)

	report, err := BuildScopeAudit(dir)
	if err != nil {
		t.Fatalf("BuildScopeAudit() error = %v", err)
	}
	if report.ReportVersion != ScopeAuditReportVersion {
		t.Fatalf("report version = %q", report.ReportVersion)
	}
	if report.Summary.AgentRunReceipts != 1 || report.Summary.DecisionReceipts != 1 {
		t.Fatalf("receipt counts = %+v", report.Summary)
	}
	for _, boundary := range scopeAuditBoundaries {
		if findBoundary(t, report, boundary).Total == 0 {
			t.Fatalf("boundary %s has zero total in %+v", boundary, report.Boundaries)
		}
	}
	if findBoundary(t, report, "payment").Denied == 0 {
		t.Fatalf("payment boundary missing denied count: %+v", findBoundary(t, report, "payment"))
	}
	if report.Summary.UnknownMCPActions == 0 || report.Summary.TaintedActions == 0 {
		t.Fatalf("expected unknown and tainted MCP counts, got %+v", report.Summary)
	}
	if report.Summary.OutOfScopeAttempts < 2 {
		t.Fatalf("expected denied and tainted attempts, got %+v", report.Summary)
	}
	if report.Summary.MemoryWrites != 1 || report.Summary.RecurringLoops != 1 {
		t.Fatalf("expected memory and loop details, got %+v", report.Summary)
	}
	if !hasMissingControl(report, "payment.amount") || !hasMissingControl(report, "operate.permissions") {
		t.Fatalf("expected payment metadata and operate permission controls, got %+v", report.MissingControls)
	}
	raw, err := canonicalize.JCS(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "raw-secret-token") {
		t.Fatalf("scope audit leaked raw secret metadata: %s", string(raw))
	}
	if !strings.Contains(string(raw), "[redacted]") {
		t.Fatalf("scope audit missing redacted marker: %s", string(raw))
	}
	again, err := BuildScopeAudit(dir)
	if err != nil {
		t.Fatal(err)
	}
	rawAgain, err := canonicalize.JCS(again)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(rawAgain) {
		t.Fatal("scope audit canonical JSON is not deterministic")
	}
}

func TestScopeAuditArtifactExport(t *testing.T) {
	dir := t.TempDir()
	decision, err := Decide(DefaultObserveDraftProfile(), decisionRequest("secret", "secret://prod/api"), DecisionOptions{})
	if err != nil {
		t.Fatalf("Decide(secret) error = %v", err)
	}
	writeJSONFixture(t, filepath.Join(dir, "secret-deny.json"), decision)
	report, err := BuildScopeAudit(dir)
	if err != nil {
		t.Fatalf("BuildScopeAudit() error = %v", err)
	}
	out := filepath.Join(t.TempDir(), "scope-audit")
	export, err := WriteScopeAuditArtifacts(report, out, true)
	if err != nil {
		t.Fatalf("WriteScopeAuditArtifacts() error = %v", err)
	}
	for _, path := range []string{export.ReportPath, export.MarkdownPath, export.EvidenceRefsPath, filepath.Join(export.EvidencePackDir, "00_INDEX.json"), filepath.Join(export.EvidencePackDir, "12_REPORTS", "scope-audit.json")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}
	data, err := os.ReadFile(export.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ScopeAuditReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("scope audit JSON invalid: %v", err)
	}
	if decoded.Summary.DeniedActions == 0 || export.EvidencePackRootHash == "" {
		t.Fatalf("unexpected export summary=%+v root=%s", decoded.Summary, export.EvidencePackRootHash)
	}
}

func TestBuildScopeAuditRejectsEmptyInputDirectory(t *testing.T) {
	if _, err := BuildScopeAudit(t.TempDir()); err == nil {
		t.Fatal("expected empty input directory error")
	}
}

func findBoundary(t *testing.T, report ScopeAuditReport, boundary string) BoundarySummary {
	t.Helper()
	for _, candidate := range report.Boundaries {
		if candidate.Boundary == boundary {
			return candidate
		}
	}
	t.Fatalf("boundary %s not found", boundary)
	return BoundarySummary{}
}

func hasMissingControl(report ScopeAuditReport, control string) bool {
	for _, candidate := range report.MissingControls {
		if candidate.Control == control {
			return true
		}
	}
	return false
}

func scopeAuditManifest() RunManifest {
	completed := time.Date(2026, 5, 20, 15, 10, 0, 0, time.UTC)
	return RunManifest{
		RunID:         "run_scope_audit",
		Goal:          "Exercise every workstation scope audit boundary.",
		ActorID:       "agent.codex.local",
		ActorType:     "agent",
		WorkspaceID:   "workspace-demo",
		WorkspacePath: "/workspace/demo",
		Repository:    "helm-ai-kernel",
		AgentSurface:  "codex",
		PolicyProfile: contracts.PolicyProfileWorkstationObserveDraftV1,
		StartedAt:     time.Date(2026, 5, 20, 15, 0, 0, 0, time.UTC),
		CompletedAt:   &completed,
	}
}

func permissiveScopeAuditProfile() contracts.WorkstationPolicyProfile {
	profile := DefaultObserveDraftProfile()
	profile.Mode = "high_risk_effect_capable"
	profile.Operate.Permissions = []string{
		contracts.WorkstationPermissionNetworkEgress,
		contracts.WorkstationPermissionMCPMutate,
		contracts.WorkstationPermissionMemoryWrite,
		contracts.WorkstationPermissionLoopRegister,
		contracts.WorkstationPermissionDeployPublish,
		contracts.WorkstationPermissionSecretRead,
		contracts.WorkstationPermissionPaymentInitiate,
	}
	profile.Egress.Allowlist = []contracts.WorkstationEgressDestination{{Host: "api.github.com", Protocol: "https"}}
	return profile
}

func scopeAuditEvent(eventID, eventType, effectType, toolID, target string, metadata map[string]string) ToolEvent {
	return ToolEvent{
		EventID:    eventID,
		Type:       eventType,
		ToolID:     toolID,
		Action:     eventType,
		EffectType: effectType,
		EffectMode: contracts.WorkstationEffectModeOperate,
		Status:     "completed",
		Target:     target,
		Metadata:   metadata,
		OccurredAt: time.Date(2026, 5, 20, 15, 1, 0, 0, time.UTC),
	}
}

func scopeAuditMemoryEvent(eventID string) ToolEvent {
	event := scopeAuditEvent(eventID, "memory_write", contracts.EffectTypeWorkstationMemoryWrite, "memory.write", "", nil)
	event.MemoryEffect = &contracts.AgentMemoryEffect{
		EffectID:    "mem_scope_audit",
		MemoryClass: "M4_PROCEDURAL",
		DataClass:   contracts.DataClassInternal,
		Sensitivity: "internal",
		TTLDays:     7,
		ContentHash: "sha256:scope-audit-memory",
		Purpose:     "remember scope audit rule",
		ReviewState: "PENDING",
	}
	return event
}

func scopeAuditLoopEvent(eventID string) ToolEvent {
	event := scopeAuditEvent(eventID, "recurring_loop", contracts.EffectTypeWorkstationRecurringLoop, "automation.register", "", nil)
	event.RecurringLoopEffect = &contracts.AgentRecurringLoopEffect{
		EffectID:   "loop_scope_audit",
		Schedule:   "FREQ=DAILY;BYHOUR=9",
		MaxRuntime: "15m",
		ToolScope:  []string{"shell.read"},
		ExpiresAt:  time.Date(2026, 6, 20, 15, 0, 0, 0, time.UTC),
	}
	return event
}

func (event ToolEvent) WithTaint(labels ...string) ToolEvent {
	event.TaintLabels = append(event.TaintLabels, labels...)
	return event
}
