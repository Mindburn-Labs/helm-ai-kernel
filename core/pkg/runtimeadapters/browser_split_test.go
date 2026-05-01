package runtimeadapters

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

func TestBrowserSplitAdapterAllowsLowRiskPlannerBoundAction(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewBrowserSplitAdapter(BrowserSplitConfig{
		Graph: graph,
		Policy: BrowserSplitPolicy{
			AllowedDomains: []string{"example.com"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := adapter.InterceptBrowserAction(context.Background(), &BrowserSplitRequest{
		PrincipalID: "browser-agent",
		Observation: BrowserSplitObservation{
			URL:          "https://app.example.com/inbox",
			DOMHash:      "sha256:dom",
			SentinelRisk: 12,
		},
		Plan: BrowserSplitPlan{
			ToolName:    "browser.click",
			PlannerRef:  "sha256:planner",
			SideEffect:  true,
			Destination: "https://app.example.com/inbox",
		},
	})
	if err != nil {
		t.Fatalf("intercept failed: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allow, got deny: %+v", resp.DenyReason)
	}
	if resp.ProofGraphNode == "" {
		t.Fatal("expected proof graph node")
	}
	if _, ok := graph.Get(resp.ProofGraphNode); !ok {
		t.Fatal("proof node not found")
	}
}

func TestBrowserSplitAdapterDeniesHighRiskSideEffect(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewBrowserSplitAdapter(BrowserSplitConfig{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := adapter.InterceptBrowserAction(context.Background(), &BrowserSplitRequest{
		PrincipalID: "browser-agent",
		Observation: BrowserSplitObservation{
			URL:              "https://example.com",
			SentinelRisk:     95,
			SentinelFindings: []string{"hidden-instruction"},
		},
		Plan: BrowserSplitPlan{
			ToolName:   "browser.submit",
			PlannerRef: "sha256:planner",
			SideEffect: true,
		},
	})
	if err != nil {
		t.Fatalf("intercept failed: %v", err)
	}
	if resp.Allowed {
		t.Fatal("expected high-risk side effect to be denied")
	}
	if resp.DenyReason == nil || resp.DenyReason.Code != ReasonCognitiveFirewallSentinelDeny {
		t.Fatalf("expected sentinel deny, got %+v", resp.DenyReason)
	}
}

func TestBrowserSplitAdapterRequiresPlannerRefForSideEffects(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewBrowserSplitAdapter(BrowserSplitConfig{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := adapter.InterceptBrowserAction(context.Background(), &BrowserSplitRequest{
		PrincipalID: "browser-agent",
		Observation: BrowserSplitObservation{
			URL:          "https://example.com",
			SentinelRisk: 5,
		},
		Plan: BrowserSplitPlan{
			ToolName:   "browser.fill",
			SideEffect: true,
		},
	})
	if err != nil {
		t.Fatalf("intercept failed: %v", err)
	}
	if resp.Allowed {
		t.Fatal("expected side effect without planner ref to be denied")
	}
	if resp.DenyReason == nil || resp.DenyReason.Code != ReasonCognitiveFirewallPlannerRefMissing {
		t.Fatalf("expected planner ref deny, got %+v", resp.DenyReason)
	}
}

func TestBrowserSplitAdapterDeniesBlockedDomain(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewBrowserSplitAdapter(BrowserSplitConfig{
		Graph: graph,
		Policy: BrowserSplitPolicy{
			AllowedDomains: []string{"example.com"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := adapter.InterceptBrowserAction(context.Background(), &BrowserSplitRequest{
		PrincipalID: "browser-agent",
		Observation: BrowserSplitObservation{
			URL:          "https://evil.example",
			SentinelRisk: 1,
		},
		Plan: BrowserSplitPlan{
			ToolName:   "browser.navigate",
			PlannerRef: "sha256:planner",
		},
	})
	if err != nil {
		t.Fatalf("intercept failed: %v", err)
	}
	if resp.Allowed {
		t.Fatal("expected out-of-scope domain to be denied")
	}
	if resp.DenyReason == nil || resp.DenyReason.Code != ReasonCognitiveFirewallDomainDeny {
		t.Fatalf("expected domain deny, got %+v", resp.DenyReason)
	}
}

func TestBrowserSplitAdapterInterceptMetadata(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewBrowserSplitAdapter(BrowserSplitConfig{Graph: graph})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := adapter.Intercept(context.Background(), &AdaptedRequest{
		RuntimeType: BrowserSplitRuntimeType,
		ToolName:    "browser.submit",
		PrincipalID: "browser-agent",
		Arguments:   map[string]any{"url": "https://example.com/checkout"},
		Metadata: map[string]string{
			"browser.sentinel_risk": "80",
			"browser.planner_ref":   "sha256:planner",
			"browser.side_effect":   "true",
		},
	})
	if err != nil {
		t.Fatalf("intercept failed: %v", err)
	}
	if resp.Allowed {
		t.Fatal("expected metadata-driven high-risk side effect to be denied")
	}
}

var _ RuntimeAdapter = (*BrowserSplitAdapter)(nil)
