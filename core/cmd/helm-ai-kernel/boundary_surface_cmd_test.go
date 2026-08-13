package main

import (
	"bytes"
	"testing"
	"time"

	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestLocalApprovalTransitionRetainsExplicitActor(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	registry := boundarypkg.NewSurfaceRegistry(func() time.Time { return now })
	approval, err := registry.PutApproval(contracts.ApprovalCeremony{
		ApprovalID:    "approval-local-actor",
		Subject:       "mcp:local",
		Action:        "mcp.approve",
		State:         contracts.ApprovalCeremonyPending,
		RequestedBy:   "agent:requester",
		Quorum:        1,
		TimelockUntil: now.Add(-time.Minute),
		ExpiresAt:     now.Add(time.Hour),
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runApprovalsTransition([]string{
		"--approval-id", approval.ApprovalID,
		"--actor", "user:local-operator",
		"--receipt-id", "receipt-local-actor",
		"--reason", "local direct approval",
	}, registry, contracts.ApprovalCeremonyAllowed, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("local transition code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	var updated contracts.ApprovalCeremony
	for _, item := range registry.ListApprovals() {
		if item.ApprovalID == approval.ApprovalID {
			updated = item
			break
		}
	}
	if updated.ApprovalID == "" {
		t.Fatal("updated approval not found")
	}
	if updated.State != contracts.ApprovalCeremonyAllowed || len(updated.Approvers) != 1 || updated.Approvers[0] != "user:local-operator" {
		t.Fatalf("local actor was not retained: %+v", updated)
	}
}

// TestApprovalTransitionRefusesUnattributedAuthority pins the reason the actor
// and receipt flags carry no defaults. They used to default to
// "user:local-admin" and "receipt-local-approval", so `approvals approve` with
// no arguments at all approved whatever bootstrap ceremony a fresh data
// directory contained, and wrote a principal who had never seen it into the
// permanent record.
func TestApprovalTransitionRefusesUnattributedAuthority(t *testing.T) {
	pending := func(t *testing.T) *boundarypkg.SurfaceRegistry {
		t.Helper()
		now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
		registry := boundarypkg.NewSurfaceRegistry(func() time.Time { return now })
		if _, err := registry.PutApproval(contracts.ApprovalCeremony{
			ApprovalID:    "approval-bootstrap",
			Subject:       "mcp:local",
			Action:        "mcp.approve",
			State:         contracts.ApprovalCeremonyPending,
			RequestedBy:   "agent:requester",
			Quorum:        1,
			TimelockUntil: now.Add(-time.Minute),
			ExpiresAt:     now.Add(time.Hour),
			CreatedAt:     now,
			UpdatedAt:     now,
		}); err != nil {
			t.Fatal(err)
		}
		return registry
	}

	for name, args := range map[string][]string{
		"no arguments at all": {},
		"no actor":            {"--approval-id", "approval-bootstrap", "--receipt-id", "receipt-x"},
		"no receipt":          {"--approval-id", "approval-bootstrap", "--actor", "user:someone"},
		"no approval id":      {"--actor", "user:someone", "--receipt-id", "receipt-x"},
		"blank actor":         {"--approval-id", "approval-bootstrap", "--actor", "   ", "--receipt-id", "receipt-x"},
	} {
		t.Run(name, func(t *testing.T) {
			registry := pending(t)
			var stdout, stderr bytes.Buffer
			code := runApprovalsTransition(args, registry, contracts.ApprovalCeremonyAllowed, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("code=%d, want 2; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			for _, item := range registry.ListApprovals() {
				if item.ApprovalID == "approval-bootstrap" && item.State != contracts.ApprovalCeremonyPending {
					t.Fatalf("refused transition still changed state to %s", item.State)
				}
			}
		})
	}
}

// TestApprovalTransitionHonoursReviewedCeremonyHash proves the CLI can now pin
// the snapshot it reviewed, the way the HTTP route already required.
func TestApprovalTransitionHonoursReviewedCeremonyHash(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	registry := boundarypkg.NewSurfaceRegistry(func() time.Time { return now })
	approval, err := registry.PutApproval(contracts.ApprovalCeremony{
		ApprovalID:    "approval-hash",
		Subject:       "mcp:local",
		Action:        "mcp.approve",
		State:         contracts.ApprovalCeremonyPending,
		RequestedBy:   "agent:requester",
		Quorum:        1,
		TimelockUntil: now.Add(-time.Minute),
		ExpiresAt:     now.Add(time.Hour),
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatal(err)
	}

	base := []string{"--approval-id", approval.ApprovalID, "--actor", "user:reviewer", "--receipt-id", "receipt-hash"}

	var stdout, stderr bytes.Buffer
	if code := runApprovalsTransition(append(append([]string{}, base...), "--expected-ceremony-hash", "sha256:not-the-one"), registry, contracts.ApprovalCeremonyAllowed, &stdout, &stderr); code == 0 {
		t.Fatalf("a stale reviewed hash was accepted: stdout=%q", stdout.String())
	}
	for _, item := range registry.ListApprovals() {
		if item.ApprovalID == approval.ApprovalID && item.State != contracts.ApprovalCeremonyPending {
			t.Fatalf("stale-hash transition still changed state to %s", item.State)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := runApprovalsTransition(append(append([]string{}, base...), "--expected-ceremony-hash", approval.CeremonyHash), registry, contracts.ApprovalCeremonyAllowed, &stdout, &stderr); code != 0 {
		t.Fatalf("the reviewed hash was rejected: code=%d stderr=%q", code, stderr.String())
	}
}
