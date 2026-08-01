package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type watchTransition struct {
	approvalID           string
	action               string
	expectedCeremonyHash string
	reason               string
}

type watchFakeClient struct {
	items         []contracts.ApprovalCeremony
	listErr       error
	listCalls     int
	transitions   []watchTransition
	transitionErr error
}

func (f *watchFakeClient) ListApprovals(context.Context) ([]contracts.ApprovalCeremony, error) {
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]contracts.ApprovalCeremony(nil), f.items...), nil
}

func (f *watchFakeClient) TransitionApproval(_ context.Context, approvalID, action, expectedCeremonyHash, reason string) (contracts.ApprovalCeremony, error) {
	if f.transitionErr != nil {
		return contracts.ApprovalCeremony{}, f.transitionErr
	}
	f.transitions = append(f.transitions, watchTransition{approvalID: approvalID, action: action, expectedCeremonyHash: expectedCeremonyHash, reason: reason})
	state := contracts.ApprovalCeremonyAllowed
	if action == "deny" {
		state = contracts.ApprovalCeremonyDenied
	}
	return contracts.ApprovalCeremony{ApprovalID: approvalID, State: state}, nil
}

func watchTestCeremony(id string, createdAt time.Time) contracts.ApprovalCeremony {
	return contracts.ApprovalCeremony{
		ApprovalID:       id,
		Subject:          "shell_command",
		Action:           "shell_operate",
		State:            contracts.ApprovalCeremonyPending,
		RequestedBy:      "agent.local",
		Approvers:        []string{"alice", "bob"},
		Quorum:           2,
		Reason:           "review destructive command",
		ReceiptID:        "receipt-1",
		BoundaryRecordID: "boundary-1",
		CeremonyHash:     "sha256:ceremony",
		CreatedAt:        createdAt.UTC(),
		UpdatedAt:        createdAt.UTC(),
	}
}

func TestWatchModelRefreshFailureClearsAndDisablesActions(t *testing.T) {
	client := &watchFakeClient{}
	model := newWatchModel(client)
	first, ok := model.beginRefresh()
	if !ok {
		t.Fatal("first refresh was not started")
	}
	model.applyRefresh(first, []contracts.ApprovalCeremony{watchTestCeremony("ap-1", time.Unix(1, 0))}, nil, time.Unix(2, 0))
	if len(model.pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(model.pending))
	}
	second, ok := model.beginRefresh()
	if !ok {
		t.Fatal("second refresh was not started")
	}
	model.applyRefresh(second, nil, errors.New("connection refused"), time.Unix(3, 0))
	if model.lastErr == nil || len(model.pending) != 0 {
		t.Fatalf("failed refresh left state actionable: err=%v pending=%+v", model.lastErr, model.pending)
	}
	if _, err := model.pendingApproval("ap-1"); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("pendingApproval error = %v, want fail-closed guard", err)
	}
}

func TestWatchModelDiscardsStaleRefresh(t *testing.T) {
	model := newWatchModel(&watchFakeClient{})
	model.generation = 2
	model.inFlight = true
	model.pending = []contracts.ApprovalCeremony{watchTestCeremony("current", time.Unix(1, 0))}
	if applied := model.applyRefresh(1, nil, errors.New("stale"), time.Unix(2, 0)); applied {
		t.Fatal("stale response must not apply")
	}
	if len(model.pending) != 1 || model.pending[0].ApprovalID != "current" || !model.inFlight {
		t.Fatalf("stale result mutated state: %+v", model)
	}
	model.applyRefresh(2, nil, errors.New("current"), time.Unix(3, 0))
	if model.lastErr == nil || len(model.pending) != 0 || model.inFlight {
		t.Fatalf("current error did not fail closed: %+v", model)
	}
}

func TestWatchSnapshotIsSortedAndTerminalSafe(t *testing.T) {
	items := []contracts.ApprovalCeremony{
		watchTestCeremony("ap-z", time.Unix(2, 0)),
		watchTestCeremony("ap-b", time.Unix(1, 0)),
		watchTestCeremony("ap-a", time.Unix(1, 0)),
		{ApprovalID: "done", State: contracts.ApprovalCeremonyDenied},
	}
	items[0].Subject = "subject\x1b[2J"
	pending := filterPendingApprovals(items)
	if got := []string{pending[0].ApprovalID, pending[1].ApprovalID, pending[2].ApprovalID}; strings.Join(got, ",") != "ap-a,ap-b,ap-z" {
		t.Fatalf("pending ordering = %v", got)
	}
	row := formatApprovalRow(items[0], time.Now())
	if strings.Contains(row, "\x1b") {
		t.Fatalf("row contains ANSI control: %q", row)
	}
}

func TestWatchDecisionContextShowsEveryCeremonyField(t *testing.T) {
	item := watchTestCeremony("ap-1", time.Unix(1, 0))
	item.BreakGlass = true
	item.AuthMethod = "webauthn"
	item.ChallengeID = "challenge-1"
	item.ChallengeHash = "sha256:challenge"
	item.AssertionHash = "sha256:assertion"
	item.TimelockUntil = time.Unix(4, 0)
	item.ExpiresAt = time.Unix(5, 0)
	context := watchDecisionContext(item, ui.DecisionApprove)
	if context.Action != ui.DecisionApprove || context.Subject != item.Subject || context.Summary == "" {
		t.Fatalf("decision context = %+v", context)
	}
	wantKeys := []string{
		"Approval ID", "Requested action", "Current state", "Requested by", "Approvers", "Quorum",
		"Created at", "Updated at", "Timelock until", "Expires at", "Break glass", "Authentication method",
		"Challenge ID", "Challenge hash", "Assertion hash", "Reason", "Receipt ID", "Boundary record ID", "Ceremony hash",
	}
	got := make(map[string]bool, len(context.Details))
	for _, detail := range context.Details {
		got[detail.Key] = true
	}
	for _, key := range wantKeys {
		if !got[key] {
			t.Errorf("DecisionContext is missing %q", key)
		}
	}
}
