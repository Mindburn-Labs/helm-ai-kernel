package main

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shadow"
)

func TestBuildInventoryProjectsAndSorts(t *testing.T) {
	report := &shadow.Report{
		ScanRoot: "/scan/root",
		Findings: []shadow.Finding{
			{Kind: "mcp_config", Vendor: "mcp", Path: "b/.mcp.json", Severity: "MEDIUM"},
			{Kind: "helm_absent", Vendor: "openai", Language: "python", Path: "z/agent.py", Line: 3},
			{Kind: "sdk_import", Vendor: "anthropic", Language: "python", Path: "a/agent.py", Line: 1},
			{Kind: "sdk_import", Vendor: "helm", Language: "python", Path: "a/governed.py", Line: 2},
			{Kind: "api_key", Vendor: "openai", Path: "a/agent.py", Line: 9},
			{Kind: "mcp_config", Vendor: "mcp", Path: "a/.mcp.json", Severity: "MEDIUM"},
		},
	}
	report.Grade = shadow.ComputeGrade(report)

	inv := buildInventory(report)

	if inv.Version != "autoconfigure-inventory/v1" {
		t.Fatalf("version = %q", inv.Version)
	}
	if len(inv.AgentSurface) != 2 {
		t.Fatalf("agent surface = %d, want 2 (helm vendor excluded)", len(inv.AgentSurface))
	}
	if inv.AgentSurface[0].Path != "a/agent.py" || inv.AgentSurface[1].Path != "z/agent.py" {
		t.Fatalf("agent surface not sorted by path: %#v", inv.AgentSurface)
	}
	if len(inv.MCPServers) != 2 || inv.MCPServers[0].ConfigPath != "a/.mcp.json" {
		t.Fatalf("mcp servers not sorted: %#v", inv.MCPServers)
	}
	if len(inv.SecretExposures) != 1 || inv.SecretExposures[0].Line != 9 {
		t.Fatalf("secret exposures = %#v", inv.SecretExposures)
	}
}

func TestBuildPolicyDraftIsDefaultDenyAndNeverSelfApproves(t *testing.T) {
	inv := AutoconfigureInventory{
		ScanRoot: "/scan/root",
		AgentSurface: []AgentSurfaceEntry{
			{Vendor: "openai", Path: "agent.py", Kind: "helm_absent"},
		},
		MCPServers: []MCPServerEntry{
			{ConfigPath: ".mcp.json", Severity: "MEDIUM"},
		},
		SecretExposures: []SecretExposureEntry{
			{Path: "agent.py", Line: 9, Vendor: "openai"},
		},
	}

	draft, plan := buildPolicyDraft(inv)

	if !draft.Draft || !draft.RequiresHumanReview {
		t.Fatal("policy draft must be marked draft and require human review")
	}
	if draft.DefaultVerdict != "DENY" {
		t.Fatalf("default verdict = %q, want DENY", draft.DefaultVerdict)
	}
	if len(draft.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(draft.Rules))
	}
	for _, r := range draft.Rules {
		if r.RecommendedVerdict == "ALLOW" {
			t.Fatalf("autoconfigure must never draft an ALLOW rule, got %#v", r)
		}
	}

	if !plan.Draft || len(plan.Servers) != 1 {
		t.Fatalf("quarantine plan = %#v", plan)
	}
	prepared := plan.Servers[0].PreparedApproval
	if prepared["approver_id"] != "" || prepared["approval_receipt_id"] != "" {
		t.Fatal("prepared approval must have empty approver fields — HELM never approves itself")
	}
}
