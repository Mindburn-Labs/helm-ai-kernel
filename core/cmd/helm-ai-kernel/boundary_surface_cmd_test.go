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
		ApprovalID:  "approval-local-actor",
		Subject:     "mcp:local",
		Action:      "mcp.approve",
		State:       contracts.ApprovalCeremonyPending,
		RequestedBy: "agent:requester",
		Quorum:      1,
		CreatedAt:   now,
		UpdatedAt:   now,
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
