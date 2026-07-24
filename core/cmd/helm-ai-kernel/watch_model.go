// watch_model.go — bubbletea model for `helm-ai-kernel watch`.
//
// Attribution: the keyboard-first approval UX (live pending list with
// approve/deny hotkeys) is adapted from Rowboat (Apache-2.0),
// apps/cli/src/tui/ui.tsx. This is an original Go implementation against the
// HELM approval API; no Rowboat code is copied verbatim.
//
// Fail-closed invariants:
//   - Pending items always derive from server state; the model never invents
//     or retains stale actionable items. A failed refresh clears the list.
//   - Approve/deny are disabled whenever the last refresh failed or a
//     transition is in flight.
package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type approvalsFetchedMsg struct {
	items []contracts.ApprovalCeremony
	err   error
}

type approvalTransitionedMsg struct {
	approvalID string
	action     string
	err        error
}

type watchTickMsg time.Time

// watchModel renders the live approval queue and wires approve/deny hotkeys
// to the kernel approval API.
type watchModel struct {
	client   approvalClient
	actor    string
	interval time.Duration

	pending     []contracts.ApprovalCeremony
	selected    int
	lastErr     error
	busy        bool
	refreshedAt time.Time
	status      string
	width       int
}

func newWatchModel(client approvalClient, actor string, interval time.Duration) *watchModel {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &watchModel{client: client, actor: actor, interval: interval}
}

func (m *watchModel) Init() tea.Cmd {
	return m.fetchCmd()
}

func (m *watchModel) fetchCmd() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		items, err := m.client.ListApprovals(ctx)
		return approvalsFetchedMsg{items: items, err: err}
	}
}

func (m *watchModel) tickCmd() tea.Cmd {
	return tea.Tick(m.interval, func(t time.Time) tea.Msg { return watchTickMsg(t) })
}

func (m *watchModel) transitionCmd(approvalID, action string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := m.client.TransitionApproval(ctx, approvalID, action, m.actor, "operator decision via helm-ai-kernel watch")
		return approvalTransitionedMsg{approvalID: approvalID, action: action, err: err}
	}
}

// actGuard explains why an approve/deny action is currently unavailable, or
// returns "" when the selected item can be transitioned. Fail closed: any
// uncertainty disables the action.
func (m *watchModel) actGuard() string {
	if m.busy {
		return "an approval transition is already in flight"
	}
	if m.lastErr != nil {
		return "approval actions unavailable: last refresh failed"
	}
	if len(m.pending) == 0 {
		return "no pending approvals"
	}
	if m.selected < 0 || m.selected >= len(m.pending) {
		return "no approval selected"
	}
	return ""
}

func (m *watchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch typed := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = typed.Width
		return m, nil
	case watchTickMsg:
		return m, m.fetchCmd()
	case approvalsFetchedMsg:
		m.refreshedAt = time.Now()
		if typed.err != nil {
			// Fail closed: never present stale items as actionable.
			m.lastErr = typed.err
			m.pending = nil
			m.selected = 0
			m.status = ""
			return m, m.tickCmd()
		}
		m.lastErr = nil
		m.pending = filterPendingApprovals(typed.items)
		if m.selected >= len(m.pending) {
			m.selected = len(m.pending) - 1
		}
		if m.selected < 0 {
			m.selected = 0
		}
		return m, m.tickCmd()
	case approvalTransitionedMsg:
		m.busy = false
		if typed.err != nil {
			m.status = fmt.Sprintf("%s %s failed: %v", typed.action, typed.approvalID, typed.err)
		} else {
			m.status = fmt.Sprintf("%s %s recorded", typed.action, typed.approvalID)
		}
		return m, m.fetchCmd()
	case tea.KeyMsg:
		switch typed.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "up", "k":
			if m.selected > 0 {
				m.selected--
			}
			return m, nil
		case "down", "j":
			if m.selected < len(m.pending)-1 {
				m.selected++
			}
			return m, nil
		case "r":
			return m, m.fetchCmd()
		case "a", "d":
			action := "approve"
			if typed.String() == "d" {
				action = "deny"
			}
			if guard := m.actGuard(); guard != "" {
				m.status = guard
				return m, nil
			}
			m.busy = true
			m.status = fmt.Sprintf("%s %s in flight…", action, m.pending[m.selected].ApprovalID)
			return m, m.transitionCmd(m.pending[m.selected].ApprovalID, action)
		}
	}
	return m, nil
}

func (m *watchModel) View() string {
	var b strings.Builder
	b.WriteString("HELM WATCH — pending approvals\n")
	if !m.refreshedAt.IsZero() {
		fmt.Fprintf(&b, "refreshed %s · every %s · server-derived state\n", m.refreshedAt.Format("15:04:05"), m.interval)
	}
	if m.lastErr != nil {
		fmt.Fprintf(&b, "ERROR: %v (actions disabled, fail-closed)\n", m.lastErr)
	}
	b.WriteString("\n")
	if len(m.pending) == 0 && m.lastErr == nil {
		b.WriteString("  no pending approvals\n")
	}
	for i, item := range m.pending {
		cursor := "  "
		if i == m.selected {
			cursor = "> "
		}
		fmt.Fprintf(&b, "%s%s\n", cursor, formatApprovalRow(item, time.Now()))
	}
	b.WriteString("\n")
	if m.status != "" {
		fmt.Fprintf(&b, "%s\n", m.status)
	}
	b.WriteString("↑/↓ select · a approve · d deny · r refresh · q quit\n")
	return b.String()
}

// filterPendingApprovals keeps only pending ceremonies, sorted oldest-first so
// the operator drains the queue in request order.
func filterPendingApprovals(items []contracts.ApprovalCeremony) []contracts.ApprovalCeremony {
	var pending []contracts.ApprovalCeremony
	for _, item := range items {
		if item.State == contracts.ApprovalCeremonyPending {
			pending = append(pending, item)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].CreatedAt.Before(pending[j].CreatedAt)
	})
	return pending
}

// formatApprovalRow renders one approval ceremony as a compact line.
func formatApprovalRow(item contracts.ApprovalCeremony, now time.Time) string {
	age := "unknown"
	if !item.CreatedAt.IsZero() {
		age = now.Sub(item.CreatedAt).Round(time.Second).String()
	}
	flags := make([]string, 0, 2)
	if item.BreakGlass {
		flags = append(flags, "break-glass")
	}
	if !item.TimelockUntil.IsZero() && now.Before(item.TimelockUntil) {
		flags = append(flags, "timelocked")
	}
	suffix := ""
	if len(flags) > 0 {
		suffix = " [" + strings.Join(flags, ",") + "]"
	}
	return fmt.Sprintf("%s  %s:%s  by %s  age %s%s",
		item.ApprovalID, item.Subject, item.Action, item.RequestedBy, age, suffix)
}

// renderApprovalSnapshot prints a non-interactive snapshot of the pending
// queue (used by --once and non-TTY output).
func renderApprovalSnapshot(w io.Writer, items []contracts.ApprovalCeremony, refreshedAt time.Time) {
	pending := filterPendingApprovals(items)
	fmt.Fprintf(w, "HELM WATCH snapshot — %s\n", refreshedAt.Format(time.RFC3339))
	if len(pending) == 0 {
		fmt.Fprintln(w, "  no pending approvals")
		return
	}
	for _, item := range pending {
		fmt.Fprintf(w, "  %s\n", formatApprovalRow(item, refreshedAt))
	}
}
