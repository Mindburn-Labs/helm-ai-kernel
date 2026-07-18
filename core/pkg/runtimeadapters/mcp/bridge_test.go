package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	githubconnector "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	mcpcore "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtimeadapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

type fakeEffectReservationBoundary struct {
	mu             sync.Mutex
	current        approvalceremony.EffectReservationEvent
	states         []approvalceremony.EffectReservationState
	failNotStarted bool
}

func (f *fakeEffectReservationBoundary) Admit(_ context.Context, admission approvalceremony.DispatchAdmissionRecord) (approvalceremony.EffectReservationEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current.State == "" {
		f.current = approvalceremony.EffectReservationEvent{
			Sequence: 1, State: approvalceremony.EffectReservationStateAdmitted, Admission: admission,
		}
		f.states = append(f.states, f.current.State)
	}
	return f.current, nil
}

func (f *fakeEffectReservationBoundary) Recover(_ context.Context, admissionID string) (approvalceremony.EffectReservationEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current.Admission.Admission.AdmissionID != admissionID {
		return approvalceremony.EffectReservationEvent{}, fmt.Errorf("reservation not found")
	}
	return f.current, nil
}

func (f *fakeEffectReservationBoundary) MarkStarted(_ context.Context, admissionID string, meta approvalceremony.EffectTransitionMeta) (approvalceremony.EffectReservationEvent, error) {
	return f.transition(admissionID, approvalceremony.EffectReservationStateStarted, meta)
}

func (f *fakeEffectReservationBoundary) MarkNotStarted(_ context.Context, admissionID string, meta approvalceremony.EffectTransitionMeta) (approvalceremony.EffectReservationEvent, error) {
	if f.failNotStarted {
		return approvalceremony.EffectReservationEvent{}, fmt.Errorf("NOT_STARTED storage unavailable")
	}
	return f.transition(admissionID, approvalceremony.EffectReservationStateNotStarted, meta)
}

func (f *fakeEffectReservationBoundary) MarkUncertain(_ context.Context, admissionID string, meta approvalceremony.EffectTransitionMeta) (approvalceremony.EffectReservationEvent, error) {
	return f.transition(admissionID, approvalceremony.EffectReservationStateUncertain, meta)
}

func (f *fakeEffectReservationBoundary) transition(admissionID string, state approvalceremony.EffectReservationState, meta approvalceremony.EffectTransitionMeta) (approvalceremony.EffectReservationEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current.Admission.Admission.AdmissionID != admissionID {
		return approvalceremony.EffectReservationEvent{}, fmt.Errorf("reservation not found")
	}
	if f.current.State == state && state == approvalceremony.EffectReservationStateStarted {
		return f.current, approvalceremony.ErrEffectReservationAlreadyStarted
	}
	f.current.Sequence++
	f.current.State = state
	f.current.ReasonCode = meta.ReasonCode
	f.current.ConnectorExecutionRef = meta.ConnectorExecutionRef
	f.states = append(f.states, state)
	return f.current, nil
}

type fakeLifecycleConnector struct {
	id    string
	calls int
	fail  bool
}

func (f *fakeLifecycleConnector) ID() string { return f.id }
func (f *fakeLifecycleConnector) PermitScope(toolName string, _ map[string]any) (effects.EffectType, effects.EffectScope, string, error) {
	return effects.EffectTypeWrite, effects.EffectScope{AllowedAction: toolName, AllowedParams: []string{"exact=fake"}}, "fake:resource", nil
}
func (f *fakeLifecycleConnector) Execute(context.Context, *effects.EffectPermit, string, map[string]any) (any, error) {
	return nil, fmt.Errorf("legacy execution path used")
}

type fakeLifecycleWithoutPermitScope struct {
	id    string
	calls int
}

func (f *fakeLifecycleWithoutPermitScope) ID() string { return f.id }
func (f *fakeLifecycleWithoutPermitScope) Execute(context.Context, *effects.EffectPermit, string, map[string]any) (any, error) {
	return nil, fmt.Errorf("legacy execution path used")
}
func (f *fakeLifecycleWithoutPermitScope) ExecuteWithLifecycle(context.Context, *effects.EffectPermit, string, map[string]any, effects.ExecutionLifecycle) (any, error) {
	f.calls++
	return map[string]any{"ok": true}, nil
}
func (f *fakeLifecycleConnector) ExecuteWithLifecycle(ctx context.Context, _ *effects.EffectPermit, _ string, _ map[string]any, lifecycle effects.ExecutionLifecycle) (any, error) {
	f.calls++
	if err := lifecycle.MarkStarted(ctx, effects.ExecutionLifecycleMeta{ConnectorExecutionRef: "fake-request-a"}); err != nil {
		return nil, err
	}
	if f.fail {
		return nil, fmt.Errorf("connector response lost")
	}
	return map[string]any{"ok": true}, nil
}

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
	effect  effects.EffectType
}

func (f *fakeConnector) ID() string { return f.id }
func (f *fakeConnector) PermitScope(toolName string, _ map[string]any) (effects.EffectType, effects.EffectScope, string, error) {
	effectType := f.effect
	if effectType == "" {
		effectType = effects.EffectTypeRead
		if DefaultWriteClassifier(toolName, nil) {
			effectType = effects.EffectTypeWrite
		}
	}
	return effectType, effects.EffectScope{AllowedAction: toolName}, toolName, nil
}

func TestGovernedBridgeUsesConnectorEffectClassInsteadOfVerbHeuristic(t *testing.T) {
	declaredWrite := &fakeConnector{id: "system", effect: effects.EffectTypeWrite}
	writeAdapter, _ := newAdapter(t, BridgeConfig{Profile: operateProfile(), Connector: declaredWrite, Now: fixedClock()})
	writeResponse, err := writeAdapter.Intercept(context.Background(), &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "system.apply", Arguments: map[string]any{"target": "prod"}, PrincipalID: "ve-assistant",
	})
	if err != nil {
		t.Fatal(err)
	}
	if writeResponse.Allowed || writeResponse.DenyReason == nil || writeResponse.DenyReason.Code != string(contracts.ReasonApprovalRequired) {
		t.Fatalf("connector-declared write bypassed approval: %+v", writeResponse)
	}
	if declaredWrite.calls != 0 {
		t.Fatalf("unapproved connector-declared write calls = %d", declaredWrite.calls)
	}

	declaredRead := &fakeConnector{id: "report", effect: effects.EffectTypeRead}
	readAdapter, _ := newAdapter(t, BridgeConfig{Profile: operateProfile(), Connector: declaredRead, Now: fixedClock()})
	readResponse, err := readAdapter.Intercept(context.Background(), &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "report.create_preview", Arguments: map[string]any{"report": "weekly"}, PrincipalID: "ve-assistant",
	})
	if err != nil || !readResponse.Allowed || declaredRead.calls != 1 {
		t.Fatalf("connector-declared read = %+v calls=%d err=%v", readResponse, declaredRead.calls, err)
	}
}
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

func TestGovernedBridgeDurablyReservesLifecycleAwareWrite(t *testing.T) {
	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "github.create_issue",
		Arguments: map[string]any{"repo": "owner/repo", "title": "Ship it"}, PrincipalID: "ve-assistant",
	}
	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		t.Fatal(err)
	}
	admission := approvalceremony.DispatchAdmissionRecord{Admission: contracts.ApprovalDispatchAdmission{
		AdmissionID: "dispatch-admission-a", AdmissionHash: "admission-hash-a", EffectHash: inputHash,
		ConnectorAuthority: contracts.ApprovalConnectorAuthority{
			ConnectorID: "github", ConnectorAction: req.ToolName,
		},
	}}
	approvals := NewMemoryApprovalStore()
	approvals.Grant(inputHash, ApprovalEvidence{
		ApproverID: "ivan", ApprovalHash: admission.Admission.AdmissionHash, GrantedScope: req.ToolName,
		DispatchAdmission: &admission,
	})
	reservations := &fakeEffectReservationBoundary{}
	connector := &fakeLifecycleConnector{id: "github"}
	adapter, _ := newAdapter(t, BridgeConfig{
		Profile: operateProfile(), Approvals: approvals, Connector: connector,
		EffectReservations: reservations, Now: func() time.Time { return time.Now().UTC() },
	})
	response, err := adapter.Intercept(context.Background(), req)
	if err != nil || !response.Allowed {
		t.Fatalf("durably governed write = %+v, %v", response, err)
	}
	if connector.calls != 1 {
		t.Fatalf("lifecycle connector calls = %d, want 1", connector.calls)
	}
	reservations.mu.Lock()
	states := append([]approvalceremony.EffectReservationState(nil), reservations.states...)
	reservations.mu.Unlock()
	if len(states) != 2 || states[0] != approvalceremony.EffectReservationStateAdmitted || states[1] != approvalceremony.EffectReservationStateStarted {
		t.Fatalf("reservation states = %v, want ADMITTED -> STARTED", states)
	}
}

func TestGovernedBridgeExecutesRealGitHubConnectorAfterDurableStart(t *testing.T) {
	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "github.create_issue",
		Arguments: map[string]any{
			"repo": "owner/repo", "title": "Ship it", "body": "governed",
			"labels": []any{"release"},
		},
		PrincipalID: "ve-assistant",
	}
	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		t.Fatal(err)
	}
	admission := approvalceremony.DispatchAdmissionRecord{Admission: contracts.ApprovalDispatchAdmission{
		AdmissionID: "dispatch-admission-github-e2e", AdmissionHash: "admission-hash-github-e2e", EffectHash: inputHash,
		ConnectorAuthority: contracts.ApprovalConnectorAuthority{ConnectorID: "github", ConnectorAction: req.ToolName},
	}}
	approvals := NewMemoryApprovalStore()
	approvals.Grant(inputHash, ApprovalEvidence{
		ApproverID: "ivan", ApprovalHash: admission.Admission.AdmissionHash, GrantedScope: req.ToolName,
		DispatchAdmission: &admission,
	})
	reservations := &fakeEffectReservationBoundary{}
	var networkCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reservations.mu.Lock()
		state := reservations.current.State
		reservations.mu.Unlock()
		if state != approvalceremony.EffectReservationStateStarted {
			t.Errorf("GitHub HTTP request observed in state %s, want STARTED", state)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/repos/owner/repo/issues" {
			t.Errorf("GitHub request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		networkCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"number":42,"html_url":"https://github.test/owner/repo/issues/42"}`))
	}))
	defer server.Close()

	connector := githubconnector.NewConnector(githubconnector.Config{
		BaseURL: server.URL, ConnectorID: "github", Token: "test-token",
	})
	adapter, _ := newAdapter(t, BridgeConfig{
		Profile: operateProfile(), Approvals: approvals, Connector: connector,
		EffectReservations: reservations, Now: func() time.Time { return time.Now().UTC() },
	})
	response, err := adapter.Intercept(context.Background(), req)
	if err != nil || !response.Allowed {
		t.Fatalf("real GitHub governed write = %+v, %v", response, err)
	}
	if networkCalls.Load() != 1 {
		t.Fatalf("GitHub network calls = %d, want 1", networkCalls.Load())
	}
	reservations.mu.Lock()
	states := append([]approvalceremony.EffectReservationState(nil), reservations.states...)
	reservations.mu.Unlock()
	if len(states) != 2 || states[0] != approvalceremony.EffectReservationStateAdmitted || states[1] != approvalceremony.EffectReservationStateStarted {
		t.Fatalf("real GitHub reservation states = %v, want ADMITTED -> STARTED", states)
	}
}

func TestGovernedBridgeRefusesWriteConnectorWithoutLifecycleSeam(t *testing.T) {
	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "linear.create_issue",
		Arguments: map[string]any{"team_id": "T1", "title": "Ship it"}, PrincipalID: "ve-assistant",
	}
	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		t.Fatal(err)
	}
	admission := approvalceremony.DispatchAdmissionRecord{Admission: contracts.ApprovalDispatchAdmission{
		AdmissionID: "dispatch-admission-b", AdmissionHash: "admission-hash-b", EffectHash: inputHash,
		ConnectorAuthority: contracts.ApprovalConnectorAuthority{
			ConnectorID: "linear", ConnectorAction: req.ToolName,
		},
	}}
	approvals := NewMemoryApprovalStore()
	approvals.Grant(inputHash, ApprovalEvidence{
		ApproverID: "ivan", ApprovalHash: admission.Admission.AdmissionHash, GrantedScope: req.ToolName,
		DispatchAdmission: &admission,
	})
	reservations := &fakeEffectReservationBoundary{}
	connector := &fakeConnector{id: "linear"}
	adapter, _ := newAdapter(t, BridgeConfig{
		Profile: operateProfile(), Approvals: approvals, Connector: connector,
		EffectReservations: reservations, Now: fixedClock(),
	})
	response, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if response.Allowed || connector.calls != 0 {
		t.Fatalf("unsupported lifecycle connector response=%+v calls=%d", response, connector.calls)
	}
	reservations.mu.Lock()
	state := reservations.current.State
	reservations.mu.Unlock()
	if state != approvalceremony.EffectReservationStateNotStarted {
		t.Fatalf("unsupported connector reservation state = %s, want NOT_STARTED", state)
	}
}

func TestGovernedBridgeRefusesDurableWriteWithoutConnectorPermitScope(t *testing.T) {
	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "github.create_issue",
		Arguments: map[string]any{"repo": "owner/repo", "title": "Ship it"}, PrincipalID: "ve-assistant",
	}
	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		t.Fatal(err)
	}
	admission := approvalceremony.DispatchAdmissionRecord{Admission: contracts.ApprovalDispatchAdmission{
		AdmissionID: "dispatch-admission-no-permit-scope", AdmissionHash: "admission-hash-no-permit-scope", EffectHash: inputHash,
		ConnectorAuthority: contracts.ApprovalConnectorAuthority{ConnectorID: "github", ConnectorAction: req.ToolName},
	}}
	approvals := NewMemoryApprovalStore()
	approvals.Grant(inputHash, ApprovalEvidence{
		ApproverID: "ivan", ApprovalHash: admission.Admission.AdmissionHash, GrantedScope: req.ToolName,
		DispatchAdmission: &admission,
	})
	reservations := &fakeEffectReservationBoundary{}
	connector := &fakeLifecycleWithoutPermitScope{id: "github"}
	adapter, _ := newAdapter(t, BridgeConfig{
		Profile: operateProfile(), Approvals: approvals, Connector: connector,
		EffectReservations: reservations, Now: fixedClock(),
	})
	response, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if response.Allowed || response.DenyReason == nil || response.DenyReason.Code != "CONNECTOR_PERMIT_SCOPE_UNSUPPORTED" {
		t.Fatalf("missing permit scope response = %+v", response)
	}
	if connector.calls != 0 {
		t.Fatalf("connector calls = %d, want 0", connector.calls)
	}
	reservations.mu.Lock()
	state := reservations.current.State
	reservations.mu.Unlock()
	if state != "" {
		t.Fatalf("reservation state = %s, want no admission", state)
	}
}

func TestGovernedBridgeRefusesUnclassifiedConnectorCallInDurableMode(t *testing.T) {
	connector := &fakeLifecycleWithoutPermitScope{id: "system"}
	reservations := &fakeEffectReservationBoundary{}
	adapter, _ := newAdapter(t, BridgeConfig{
		Profile: operateProfile(), Connector: connector, EffectReservations: reservations, Now: fixedClock(),
	})
	response, err := adapter.Intercept(context.Background(), &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "system.apply", Arguments: map[string]any{"target": "prod"}, PrincipalID: "ve-assistant",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Allowed || response.DenyReason == nil || response.DenyReason.Code != "CONNECTOR_PERMIT_SCOPE_UNSUPPORTED" {
		t.Fatalf("unclassified durable call response = %+v", response)
	}
	if connector.calls != 0 {
		t.Fatalf("unclassified durable connector calls = %d", connector.calls)
	}
}

func TestGovernedBridgeDoesNotClaimNotStartedWhenPersistenceFails(t *testing.T) {
	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "github.create_issue",
		Arguments: map[string]any{"repo": "owner/repo", "title": "Ship it"}, PrincipalID: "ve-assistant",
	}
	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		t.Fatal(err)
	}
	admission := approvalceremony.DispatchAdmissionRecord{Admission: contracts.ApprovalDispatchAdmission{
		AdmissionID: "dispatch-admission-resolution-failure", AdmissionHash: "admission-hash-resolution-failure", EffectHash: inputHash,
		ConnectorAuthority: contracts.ApprovalConnectorAuthority{ConnectorID: "github", ConnectorAction: req.ToolName},
	}}
	approvals := NewMemoryApprovalStore()
	approvals.Grant(inputHash, ApprovalEvidence{
		ApproverID: "ivan", ApprovalHash: admission.Admission.AdmissionHash, GrantedScope: req.ToolName, DispatchAdmission: &admission,
	})
	reservations := &fakeEffectReservationBoundary{failNotStarted: true}
	adapter, _ := newAdapter(t, BridgeConfig{
		Profile: operateProfile(), Approvals: approvals, Connector: &fakeConnector{id: "github"},
		EffectReservations: reservations, Now: fixedClock(),
	})
	response, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if response.Allowed || response.DenyReason == nil || response.DenyReason.Code != "EFFECT_LIFECYCLE_UNCERTAIN" ||
		response.DenyReason.Actionable != "reconcile_effect" {
		t.Fatalf("failed NOT_STARTED persistence response = %+v", response)
	}
	reservations.mu.Lock()
	state := reservations.current.State
	reservations.mu.Unlock()
	if state != approvalceremony.EffectReservationStateUncertain {
		t.Fatalf("failed NOT_STARTED persistence state = %s, want UNCERTAIN", state)
	}
}

func TestGovernedBridgeForcesUncertainWhenConnectorErrorsAfterStart(t *testing.T) {
	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "github.create_issue",
		Arguments: map[string]any{"repo": "owner/repo", "title": "Ambiguous"}, PrincipalID: "ve-assistant",
	}
	inputHash, err := canonicalize.CanonicalHash(req)
	if err != nil {
		t.Fatal(err)
	}
	admission := approvalceremony.DispatchAdmissionRecord{Admission: contracts.ApprovalDispatchAdmission{
		AdmissionID: "dispatch-admission-c", AdmissionHash: "admission-hash-c", EffectHash: inputHash,
		ConnectorAuthority: contracts.ApprovalConnectorAuthority{ConnectorID: "github", ConnectorAction: req.ToolName},
	}}
	approvals := NewMemoryApprovalStore()
	approvals.Grant(inputHash, ApprovalEvidence{
		ApproverID: "ivan", ApprovalHash: admission.Admission.AdmissionHash, GrantedScope: req.ToolName,
		DispatchAdmission: &admission,
	})
	reservations := &fakeEffectReservationBoundary{}
	adapter, _ := newAdapter(t, BridgeConfig{
		Profile: operateProfile(), Approvals: approvals, Connector: &fakeLifecycleConnector{id: "github", fail: true},
		EffectReservations: reservations, Now: fixedClock(),
	})
	response, err := adapter.Intercept(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if response.Allowed {
		t.Fatalf("ambiguous connector response must not be a clean allow: %+v", response)
	}
	if response.DenyReason == nil || response.DenyReason.Actionable != "reconcile_effect" {
		t.Fatalf("ambiguous effect must direct reconciliation: %+v", response.DenyReason)
	}
	reservations.mu.Lock()
	states := append([]approvalceremony.EffectReservationState(nil), reservations.states...)
	reservations.mu.Unlock()
	if len(states) != 3 || states[2] != approvalceremony.EffectReservationStateUncertain {
		t.Fatalf("ambiguous reservation states = %v, want ADMITTED -> STARTED -> UNCERTAIN", states)
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
