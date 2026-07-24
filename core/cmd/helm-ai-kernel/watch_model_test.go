package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// fakeApprovalClient implements approvalClient for model tests.
type fakeApprovalClient struct {
	items          []contracts.ApprovalCeremony
	listErr        error
	transitionErr  error
	transitionedTo []string
}

func (f *fakeApprovalClient) ListApprovals(context.Context) ([]contracts.ApprovalCeremony, error) {
	return f.items, f.listErr
}

func (f *fakeApprovalClient) TransitionApproval(_ context.Context, approvalID, action, actor, reason string) (contracts.ApprovalCeremony, error) {
	if f.transitionErr != nil {
		return contracts.ApprovalCeremony{}, f.transitionErr
	}
	f.transitionedTo = append(f.transitionedTo, action+":"+approvalID)
	state := contracts.ApprovalCeremonyAllowed
	if action == "deny" {
		state = contracts.ApprovalCeremonyDenied
	}
	return contracts.ApprovalCeremony{ApprovalID: approvalID, State: state}, nil
}

func (f *fakeApprovalClient) CreateApproval(context.Context, createApprovalRequest) (contracts.ApprovalCeremony, error) {
	return contracts.ApprovalCeremony{}, errors.New("not implemented")
}

func pendingCeremony(id string, createdAt time.Time) contracts.ApprovalCeremony {
	return contracts.ApprovalCeremony{
		ApprovalID:  id,
		Subject:     "shell_command",
		Action:      "shell_operate",
		State:       contracts.ApprovalCeremonyPending,
		RequestedBy: "agent.local",
		CreatedAt:   createdAt,
		UpdatedAt:   createdAt,
	}
}

func updateModel(t *testing.T, m *watchModel, msg tea.Msg) (*watchModel, tea.Cmd) {
	t.Helper()
	next, cmd := m.Update(msg)
	model, ok := next.(*watchModel)
	if !ok {
		t.Fatalf("Update returned %T, want *watchModel", next)
	}
	return model, cmd
}

func TestWatchModelFetchFiltersPending(t *testing.T) {
	now := time.Now()
	client := &fakeApprovalClient{}
	m := newWatchModel(client, "operator.cli", time.Second)

	m, cmd := updateModel(t, m, approvalsFetchedMsg{items: []contracts.ApprovalCeremony{
		{ApprovalID: "ap-old", State: contracts.ApprovalCeremonyAllowed, CreatedAt: now},
		pendingCeremony("ap-new", now),
		pendingCeremony("ap-old-pending", now.Add(-time.Hour)),
	}})
	if cmd == nil {
		t.Fatal("successful fetch must schedule the next tick")
	}
	if len(m.pending) != 2 {
		t.Fatalf("pending = %d, want 2 (non-pending filtered out)", len(m.pending))
	}
	if m.pending[0].ApprovalID != "ap-old-pending" {
		t.Fatalf("pending[0] = %s, want oldest first", m.pending[0].ApprovalID)
	}
}

func TestWatchModelFetchErrorFailsClosed(t *testing.T) {
	client := &fakeApprovalClient{}
	m := newWatchModel(client, "operator.cli", time.Second)

	m, _ = updateModel(t, m, approvalsFetchedMsg{items: []contracts.ApprovalCeremony{pendingCeremony("ap-1", time.Now())}})
	if len(m.pending) != 1 {
		t.Fatalf("setup: pending = %d, want 1", len(m.pending))
	}

	m, cmd := updateModel(t, m, approvalsFetchedMsg{err: errors.New("connection refused")})
	if cmd == nil {
		t.Fatal("failed fetch must still schedule the next tick")
	}
	if m.lastErr == nil {
		t.Fatal("lastErr must record the failure")
	}
	if len(m.pending) != 0 {
		t.Fatalf("stale pending items must be cleared, got %d", len(m.pending))
	}

	// Approve key must not fire a transition while the last refresh failed.
	m, cmd = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	if cmd != nil {
		t.Fatal("approve must be disabled after a failed refresh (fail closed)")
	}
	if !strings.Contains(m.status, "unavailable") {
		t.Fatalf("status = %q, want an explanation of the disabled action", m.status)
	}
	if len(client.transitionedTo) != 0 {
		t.Fatalf("no transition may fire, got %v", client.transitionedTo)
	}
}

func TestWatchModelApproveDenyFlow(t *testing.T) {
	client := &fakeApprovalClient{}
	m := newWatchModel(client, "operator.cli", time.Second)
	m, _ = updateModel(t, m, approvalsFetchedMsg{items: []contracts.ApprovalCeremony{
		pendingCeremony("ap-1", time.Now().Add(-time.Minute)),
		pendingCeremony("ap-2", time.Now()),
	}})

	// Navigate to the second item and approve it.
	m, _ = updateModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
	if m.selected != 1 {
		t.Fatalf("selected = %d, want 1", m.selected)
	}
	m, cmd := updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	if !m.busy {
		t.Fatal("busy must be set while a transition is in flight")
	}
	if cmd == nil {
		t.Fatal("approve must produce a transition command")
	}
	msg := cmd()
	transitioned, ok := msg.(approvalTransitionedMsg)
	if !ok {
		t.Fatalf("transition cmd produced %T, want approvalTransitionedMsg", msg)
	}
	if transitioned.err != nil || transitioned.action != "approve" || transitioned.approvalID != "ap-2" {
		t.Fatalf("transition = %+v, want approve ap-2", transitioned)
	}
	if got := client.transitionedTo; len(got) != 1 || got[0] != "approve:ap-2" {
		t.Fatalf("client transitions = %v, want [approve:ap-2]", got)
	}

	m, refresh := updateModel(t, m, transitioned)
	if m.busy {
		t.Fatal("busy must clear after the transition completes")
	}
	if refresh == nil {
		t.Fatal("completed transition must trigger a refresh")
	}
	if !strings.Contains(m.status, "approve ap-2") {
		t.Fatalf("status = %q, want transition confirmation", m.status)
	}

	// Deny the remaining item.
	m, _ = updateModel(t, m, approvalsFetchedMsg{items: []contracts.ApprovalCeremony{pendingCeremony("ap-1", time.Now().Add(-time.Minute))}})
	m, cmd = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	if cmd == nil {
		t.Fatal("deny must produce a transition command")
	}
	if transitioned := cmd().(approvalTransitionedMsg); transitioned.action != "deny" {
		t.Fatalf("action = %s, want deny", transitioned.action)
	}
}

func TestWatchModelTransitionErrorKeepsQueue(t *testing.T) {
	client := &fakeApprovalClient{transitionErr: errors.New("conflict")}
	m := newWatchModel(client, "operator.cli", time.Second)
	m, _ = updateModel(t, m, approvalsFetchedMsg{items: []contracts.ApprovalCeremony{pendingCeremony("ap-1", time.Now())}})

	m, cmd := updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	transitioned := cmd().(approvalTransitionedMsg)
	m, _ = updateModel(t, m, transitioned)
	if !strings.Contains(m.status, "failed") {
		t.Fatalf("status = %q, want the failure surfaced", m.status)
	}
	if m.busy {
		t.Fatal("busy must clear even on transition failure")
	}
}

func TestWatchModelQuitAndGuards(t *testing.T) {
	client := &fakeApprovalClient{}
	m := newWatchModel(client, "operator.cli", time.Second)

	// Empty queue: approve is a no-op with an explanatory status.
	m, cmd := updateModel(t, m, approvalsFetchedMsg{items: nil})
	if cmd == nil {
		t.Fatal("tick must be scheduled")
	}
	m, cmd = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	if cmd != nil {
		t.Fatal("approve with an empty queue must not fire")
	}
	if !strings.Contains(m.status, "no pending approvals") {
		t.Fatalf("status = %q", m.status)
	}

	// q quits.
	_, cmd = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Fatal("q must produce a quit command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("quit cmd produced %T, want tea.QuitMsg", cmd())
	}
}

func TestWatchModelView(t *testing.T) {
	client := &fakeApprovalClient{}
	m := newWatchModel(client, "operator.cli", time.Second)
	m, _ = updateModel(t, m, approvalsFetchedMsg{items: []contracts.ApprovalCeremony{
		pendingCeremony("ap-1", time.Now().Add(-time.Minute)),
	}})
	view := m.View()
	for _, want := range []string{"ap-1", "a approve", "d deny", "q quit", "shell_command"} {
		if !strings.Contains(view, want) {
			t.Fatalf("view missing %q:\n%s", want, view)
		}
	}

	// Error state renders and announces fail-closed.
	m, _ = updateModel(t, m, approvalsFetchedMsg{err: errors.New("boom")})
	view = m.View()
	if !strings.Contains(view, "ERROR") || !strings.Contains(view, "fail-closed") {
		t.Fatalf("error view missing fail-closed notice:\n%s", view)
	}
}

func TestRenderApprovalSnapshot(t *testing.T) {
	var buf bytes.Buffer
	items := []contracts.ApprovalCeremony{
		pendingCeremony("ap-1", time.Now().Add(-time.Minute)),
		{ApprovalID: "ap-done", State: contracts.ApprovalCeremonyDenied},
	}
	renderApprovalSnapshot(&buf, items, time.Now())
	out := buf.String()
	if !strings.Contains(out, "ap-1") {
		t.Fatalf("snapshot missing pending item:\n%s", out)
	}
	if strings.Contains(out, "ap-done") {
		t.Fatalf("snapshot must only show pending items:\n%s", out)
	}

	buf.Reset()
	renderApprovalSnapshot(&buf, nil, time.Now())
	if !strings.Contains(buf.String(), "no pending approvals") {
		t.Fatalf("empty snapshot:\n%s", buf.String())
	}
}
