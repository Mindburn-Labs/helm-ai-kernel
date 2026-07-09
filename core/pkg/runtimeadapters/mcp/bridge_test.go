package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	mcpcore "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtimeadapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

// operateProfile grants the mcp.mutate permission so MCP tool calls can reach
// ALLOW (the default observe/draft profile denies all operate-class calls).
func operateProfile() contracts.WorkstationPolicyProfile {
	p := workstation.DefaultObserveDraftProfile()
	p.Operate.Permissions = []string{contracts.WorkstationPermissionMCPMutate}
	return p
}

func fixedClock() func() time.Time {
	t := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func newAdapter(t *testing.T, cfg BridgeConfig) (*MCPAdapter, *proofgraph.Graph) {
	t.Helper()
	graph := proofgraph.NewGraph()
	adapter, err := NewMCPAdapter(Config{Graph: graph, Bridge: NewGovernedBridge(cfg)})
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	return adapter, graph
}

// Smoke 1: a safe read is ALLOWED (policy grants mcp permission; not a write).
func TestGovernedBridgeAllowsSafeRead(t *testing.T) {
	adapter, graph := newAdapter(t, BridgeConfig{Profile: operateProfile(), Now: fixedClock()})
	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "linear.get_issue",
		Arguments: map[string]any{"issue_id": "ENG-1"}, PrincipalID: "ve-assistant",
	}
	resp, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatalf("intercept: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected ALLOW, got deny: %+v", resp.DenyReason)
	}
	if resp.ReceiptID == "" || resp.DecisionID == "" {
		t.Errorf("expected receipt + decision refs, got %+v", resp)
	}
	node, ok := graph.Get(resp.ProofGraphNode)
	if !ok || node.Kind != proofgraph.NodeTypeEffect {
		t.Errorf("expected an EFFECT proof node, got %+v", node)
	}
}

// Smoke 2: a write with no operate permission is DENIED (fail-closed policy).
func TestGovernedBridgeDeniesUnpermittedWrite(t *testing.T) {
	// Default observe/draft profile: no operate permissions.
	adapter, _ := newAdapter(t, BridgeConfig{Now: fixedClock()})
	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "gmail.send",
		Arguments: map[string]any{"to": "bob@example.com"}, PrincipalID: "ve-assistant",
	}
	resp, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatalf("intercept: %v", err)
	}
	if resp.Allowed {
		t.Fatal("expected DENY for unpermitted write")
	}
	if resp.DenyReason == nil || resp.DenyReason.Code == "" {
		t.Errorf("expected a deny reason code, got %+v", resp.DenyReason)
	}
}

// Smoke 3: a bounded write that policy allows is ESCALATED for approval, then
// ALLOWED once approval evidence is bound to the request.
func TestGovernedBridgeEscalatesThenAllowsWrite(t *testing.T) {
	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "linear.create_issue",
		Arguments:   map[string]any{"team_id": "T1", "title": "Ship it"},
		PrincipalID: "ve-assistant",
	}
	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// Without approval: ESCALATE.
	approvals := NewMemoryApprovalStore()
	adapter, _ := newAdapter(t, BridgeConfig{Profile: operateProfile(), Approvals: approvals, Now: fixedClock()})
	resp, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatalf("intercept: %v", err)
	}
	if resp.Allowed {
		t.Fatal("expected ESCALATE (not allowed) before approval")
	}
	if resp.DenyReason == nil || resp.DenyReason.Code != string(contracts.ReasonApprovalRequired) {
		t.Fatalf("expected APPROVAL_REQUIRED, got %+v", resp.DenyReason)
	}
	if resp.DenyReason.Actionable != "request_approval" {
		t.Errorf("escalation must be actionable via request_approval, got %q", resp.DenyReason.Actionable)
	}

	// Bind approval evidence to this exact request, then retry: ALLOW.
	approvals.Grant(inputHash, ApprovalEvidence{ApproverID: "ivan", ApprovalHash: "abc", GrantedScope: "linear.create_issue"})
	adapter2, _ := newAdapter(t, BridgeConfig{Profile: operateProfile(), Approvals: approvals, Now: fixedClock()})
	resp2, err := adapter2.Intercept(context.Background(), req)
	if err != nil {
		t.Fatalf("intercept after approval: %v", err)
	}
	if !resp2.Allowed {
		t.Fatalf("expected ALLOW after approval, got %+v", resp2.DenyReason)
	}
}

// Replay: an approved bounded WRITE is single-use. A second identical dispatch
// (real or fixed clock — the nonce is clock-independent) is denied as a replay.
func TestGovernedBridgeWriteIsSingleUse(t *testing.T) {
	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "linear.create_issue",
		Arguments: map[string]any{"team_id": "T1", "title": "Ship it"}, PrincipalID: "ve-assistant",
	}
	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	approvals := NewMemoryApprovalStore()
	approvals.Grant(inputHash, ApprovalEvidence{ApproverID: "ivan"})
	bridge := NewGovernedBridge(BridgeConfig{Profile: operateProfile(), Approvals: approvals, Now: fixedClock()})
	graph := proofgraph.NewGraph()
	adapter, err := NewMCPAdapter(Config{Graph: graph, Bridge: bridge})
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	first, err := adapter.Intercept(context.Background(), req)
	if err != nil || !first.Allowed {
		t.Fatalf("first approved write should ALLOW: %v %+v", err, first.DenyReason)
	}
	second, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatalf("second intercept: %v", err)
	}
	if second.Allowed {
		t.Fatal("expected a second identical write to be denied as single-use replay")
	}
	if second.DenyReason == nil || second.DenyReason.Code != string(contracts.ReasonPlanTransactionConflict) {
		t.Fatalf("expected canonical replay reason, got %+v", second.DenyReason)
	}
}

// Reads are idempotent: the same read may be retried and is allowed each time
// (reads do not consume the single-use nonce).
func TestGovernedBridgeAllowsReadRetry(t *testing.T) {
	bridge := NewGovernedBridge(BridgeConfig{Profile: operateProfile(), Now: fixedClock()})
	graph := proofgraph.NewGraph()
	adapter, err := NewMCPAdapter(Config{Graph: graph, Bridge: bridge})
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "linear.get_issue",
		Arguments: map[string]any{"issue_id": "ENG-1"}, PrincipalID: "ve-assistant",
	}
	for i := 0; i < 2; i++ {
		resp, err := adapter.Intercept(context.Background(), req)
		if err != nil || !resp.Allowed {
			t.Fatalf("read attempt %d should ALLOW: %v %+v", i, err, resp.DenyReason)
		}
	}
}

// fakeConnector records dispatches and can be told to fail.
type fakeConnector struct {
	id      string
	fail    bool
	calls   int
	lastArg map[string]any
}

func (f *fakeConnector) ID() string { return f.id }
func (f *fakeConnector) Execute(_ context.Context, _ *effects.EffectPermit, _ string, params map[string]any) (any, error) {
	f.calls++
	f.lastArg = params
	if f.fail {
		return nil, errTestDispatch
	}
	return map[string]any{"ok": true}, nil
}

var errTestDispatch = errTest("connector boom")

type errTest string

func (e errTest) Error() string { return string(e) }

// Dispatch path: an allowed read with a bound connector is executed, and the
// connector's output is canonicalized into the effect record.
func TestGovernedBridgeDispatchesThroughConnector(t *testing.T) {
	conn := &fakeConnector{id: "linear"}
	bridge := NewGovernedBridge(BridgeConfig{Profile: operateProfile(), Connector: conn, Now: fixedClock()})
	graph := proofgraph.NewGraph()
	adapter, _ := NewMCPAdapter(Config{Graph: graph, Bridge: bridge})
	resp, err := adapter.Intercept(context.Background(), &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "linear.get_issue",
		Arguments: map[string]any{"issue_id": "ENG-1"}, PrincipalID: "ve-assistant",
	})
	if err != nil || !resp.Allowed {
		t.Fatalf("expected ALLOW+dispatch: %v %+v", err, resp.DenyReason)
	}
	if conn.calls != 1 {
		t.Fatalf("expected connector to be called once, got %d", conn.calls)
	}
	if resp.Result == nil {
		t.Error("expected dispatched output in Result")
	}
}

// Dispatch failure: the connector error is recorded; the call is not reported as
// a clean allow-with-output (Result stays nil, truth lives in the effect node).
func TestGovernedBridgeRecordsDispatchFailure(t *testing.T) {
	conn := &fakeConnector{id: "linear", fail: true}
	bridge := NewGovernedBridge(BridgeConfig{Profile: operateProfile(), Connector: conn, Now: fixedClock()})
	graph := proofgraph.NewGraph()
	adapter, _ := NewMCPAdapter(Config{Graph: graph, Bridge: bridge})
	resp, err := adapter.Intercept(context.Background(), &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "linear.get_issue",
		Arguments: map[string]any{"issue_id": "ENG-1"}, PrincipalID: "ve-assistant",
	})
	if err != nil {
		t.Fatalf("intercept: %v", err)
	}
	if resp.Result != nil {
		t.Errorf("dispatch failed — Result must be nil, got %v", resp.Result)
	}
}

// Boundary gate: an execution firewall with an unapproved server / non-allowlisted
// tool refuses the call BEFORE policy is consulted (fail-closed at the boundary).
func TestGovernedBridgeBoundaryRefusesUnapprovedCall(t *testing.T) {
	// Empty catalog + default quarantine: no server approved, no tool registered.
	firewall := mcpcore.NewExecutionFirewall(nil, nil, "epoch-test")
	adapter, _ := newAdapter(t, BridgeConfig{
		Firewall: firewall,
		ServerID: "unapproved-server",
		Profile:  operateProfile(), // policy WOULD allow — boundary must still refuse
		Now:      fixedClock(),
	})
	resp, err := adapter.Intercept(context.Background(), &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "linear.get_issue", PrincipalID: "ve-assistant",
	})
	if err != nil {
		t.Fatalf("intercept: %v", err)
	}
	if resp.Allowed {
		t.Fatal("expected boundary to refuse an unapproved-server / non-allowlisted call")
	}
	if resp.DenyReason == nil || resp.DenyReason.Code == "" {
		t.Errorf("expected a boundary reason code, got %+v", resp.DenyReason)
	}
}

// No bridge configured: adapter stays deny-only and fail-closed.
func TestAdapterWithoutBridgeIsFailClosed(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := NewMCPAdapter(Config{Graph: graph})
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	resp, err := adapter.Intercept(context.Background(), &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "linear.get_issue", PrincipalID: "ve-assistant",
	})
	if err != nil {
		t.Fatalf("intercept: %v", err)
	}
	if resp.Allowed || resp.DenyReason == nil || resp.DenyReason.Code != "BRIDGE_NOT_CONFIGURED" {
		t.Fatalf("expected BRIDGE_NOT_CONFIGURED deny, got %+v", resp)
	}
}
