package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// watchModel is deliberately presentation-agnostic. It owns only the
// server-derived snapshot and the fail-closed action guard; the command owns
// prompting and delegates every state change to ui.ConfirmDecision.
type watchModel struct {
	client approvalClient

	pending     []contracts.ApprovalCeremony
	lastErr     error
	busy        bool
	refreshedAt time.Time

	generation int
	inFlight   bool
}

func newWatchModel(client approvalClient, _ ...time.Duration) *watchModel {
	return &watchModel{client: client}
}

// beginRefresh starts a generation only when no other refresh is active.
// This keeps a stale response from restoring actionable state after a newer
// failed refresh.
func (m *watchModel) beginRefresh() (int, bool) {
	if m == nil || m.inFlight {
		return 0, false
	}
	m.generation++
	m.inFlight = true
	return m.generation, true
}

// applyRefresh consumes only the current generation. A current refresh error
// clears all pending state so no stale approval remains actionable.
func (m *watchModel) applyRefresh(generation int, items []contracts.ApprovalCeremony, err error, refreshedAt time.Time) bool {
	if m == nil || generation != m.generation {
		return false
	}
	m.inFlight = false
	m.refreshedAt = refreshedAt.UTC()
	if err != nil {
		m.lastErr = err
		m.pending = nil
		return true
	}
	m.lastErr = nil
	m.pending = filterPendingApprovals(items)
	return true
}

func (m *watchModel) refresh(ctx context.Context, refreshedAt time.Time) error {
	if m == nil || m.client == nil {
		return errors.New("approval client is required")
	}
	generation, ok := m.beginRefresh()
	if !ok {
		return errors.New("approval refresh is already in flight")
	}
	items, err := m.client.ListApprovals(ctx)
	m.applyRefresh(generation, items, err, refreshedAt)
	return err
}

// pendingApproval returns a server-derived approval only when the latest
// refresh is known-good and no transition is active. It is the single action
// guard used immediately before ui.ConfirmDecision and again inside its
// callback.
func (m *watchModel) pendingApproval(approvalID string) (contracts.ApprovalCeremony, error) {
	if m == nil {
		return contracts.ApprovalCeremony{}, errors.New("watch state is unavailable")
	}
	if m.busy {
		return contracts.ApprovalCeremony{}, errors.New("approval action is already in flight")
	}
	if m.inFlight {
		return contracts.ApprovalCeremony{}, errors.New("approval actions are disabled while refresh is in flight")
	}
	if m.lastErr != nil {
		return contracts.ApprovalCeremony{}, errors.New("approval actions are disabled because the latest refresh failed")
	}
	for _, item := range m.pending {
		if item.ApprovalID == approvalID {
			if reason := watchTransitionBlockReason(item); reason != "" {
				return contracts.ApprovalCeremony{}, fmt.Errorf("pending approval %q is read-only in watch: %s", terminalSafe(approvalID), reason)
			}
			return item, nil
		}
	}
	return contracts.ApprovalCeremony{}, fmt.Errorf("pending approval %q is not available", terminalSafe(approvalID))
}

// watchTransitionBlockReason identifies ceremony evidence that a typed terminal
// confirmation and shared admin key cannot cryptographically satisfy. Watch
// keeps those records visible, but must not turn its review UI into a bypass of
// the required assertion flow.
func watchTransitionBlockReason(item contracts.ApprovalCeremony) string {
	requirements := make([]string, 0, 4)
	if strings.TrimSpace(item.AuthMethod) != "" {
		requirements = append(requirements, "auth_method")
	}
	if strings.TrimSpace(item.ChallengeID) != "" {
		requirements = append(requirements, "challenge_id")
	}
	if strings.TrimSpace(item.ChallengeHash) != "" {
		requirements = append(requirements, "challenge_hash")
	}
	if strings.TrimSpace(item.AssertionHash) != "" {
		requirements = append(requirements, "assertion_hash")
	}
	if len(requirements) == 0 {
		return ""
	}
	return "it declares " + strings.Join(requirements, ", ") + "; use a verified approval flow that can satisfy those requirements"
}

// watchActionBlockReason keeps break-glass approvals visible and denyable,
// while refusing a terminal APPROVE path that cannot supply their mandatory
// receipt evidence.
func watchActionBlockReason(item contracts.ApprovalCeremony, action ui.DecisionAction) string {
	if item.BreakGlass && action == ui.DecisionApprove {
		return "break-glass approvals cannot be approved from watch; use the verified break-glass approval flow (DENY remains available)"
	}
	return ""
}

// filterPendingApprovals keeps only pending ceremonies. It sorts by creation
// timestamp and then ID so text and JSON snapshots are deterministic even
// when server ordering is not.
func filterPendingApprovals(items []contracts.ApprovalCeremony) []contracts.ApprovalCeremony {
	pending := make([]contracts.ApprovalCeremony, 0, len(items))
	for _, item := range items {
		if item.State == contracts.ApprovalCeremonyPending {
			pending = append(pending, item)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		if pending[i].CreatedAt.Equal(pending[j].CreatedAt) {
			return pending[i].ApprovalID < pending[j].ApprovalID
		}
		return pending[i].CreatedAt.Before(pending[j].CreatedAt)
	})
	return pending
}

// formatApprovalRow is intentionally plain: it is shared by terminal and
// pipe snapshots and never emits ANSI or cursor control sequences.
func formatApprovalRow(item contracts.ApprovalCeremony, _ time.Time) string {
	return fmt.Sprintf(
		"%s | %s:%s | requested by %s | created %s",
		terminalSafe(item.ApprovalID),
		terminalSafe(item.Subject),
		terminalSafe(item.Action),
		terminalSafe(item.RequestedBy),
		watchTime(item.CreatedAt),
	)
}

// renderApprovalSnapshot prints the stable, non-interactive view. It is safe
// for pipes and JSON-adjacent operator automation because it has no prompts,
// ANSI, relative timestamps, or mutable terminal state.
func renderApprovalSnapshot(w io.Writer, items []contracts.ApprovalCeremony, _ ...time.Time) {
	pending := filterPendingApprovals(items)
	fmt.Fprintln(w, "HELM WATCH snapshot")
	fmt.Fprintf(w, "pending: %d\n", len(pending))
	for _, item := range pending {
		fmt.Fprintf(w, "  %s\n", formatApprovalRow(item, time.Time{}))
	}
}

// watchDecisionContext includes every approval-ceremony field before a human
// can transition it. Keep these ordered rather than using a map: review order
// is part of the accessible terminal contract.
func watchDecisionContext(item contracts.ApprovalCeremony, action ui.DecisionAction) ui.DecisionContext {
	summary := fmt.Sprintf(
		"Record %s requests %s on %s.",
		terminalSafe(item.ApprovalID),
		terminalSafe(item.Action),
		terminalSafe(item.Subject),
	)
	return ui.DecisionContext{
		Action:  action,
		Subject: terminalSafe(item.Subject),
		Summary: summary,
		Details: []ui.KeyValue{
			{Key: "Approval ID", Value: terminalSafe(item.ApprovalID)},
			{Key: "Requested action", Value: terminalSafe(item.Action)},
			{Key: "Current state", Value: terminalSafe(string(item.State))},
			{Key: "Requested by", Value: terminalSafe(item.RequestedBy)},
			{Key: "Approvers", Value: watchApprovers(item.Approvers)},
			{Key: "Quorum", Value: fmt.Sprintf("%d", item.Quorum)},
			{Key: "Created at", Value: watchTime(item.CreatedAt)},
			{Key: "Updated at", Value: watchTime(item.UpdatedAt)},
			{Key: "Timelock until", Value: watchTime(item.TimelockUntil)},
			{Key: "Expires at", Value: watchTime(item.ExpiresAt)},
			{Key: "Break glass", Value: fmt.Sprintf("%t", item.BreakGlass)},
			{Key: "Authentication method", Value: terminalSafe(item.AuthMethod)},
			{Key: "Challenge ID", Value: terminalSafe(item.ChallengeID)},
			{Key: "Challenge hash", Value: terminalSafe(item.ChallengeHash)},
			{Key: "Assertion hash", Value: terminalSafe(item.AssertionHash)},
			{Key: "Reason", Value: terminalSafe(item.Reason)},
			{Key: "Receipt ID", Value: terminalSafe(item.ReceiptID)},
			{Key: "Boundary record ID", Value: terminalSafe(item.BoundaryRecordID)},
			{Key: "Ceremony hash", Value: terminalSafe(item.CeremonyHash)},
		},
	}
}

func watchApprovers(approvers []string) string {
	if len(approvers) == 0 {
		return ""
	}
	values := make([]string, len(approvers))
	for i, approver := range approvers {
		values[i] = terminalSafe(approver)
	}
	return strings.Join(values, ", ")
}

func watchTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

// terminalSafe strips control and Unicode format characters from all
// server-controlled values before they enter a terminal view or an error.
func terminalSafe(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return '\uFFFD'
		}
		return r
	}, value)
}
