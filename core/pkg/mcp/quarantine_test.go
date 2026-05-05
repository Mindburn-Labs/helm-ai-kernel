package mcp

import (
	"context"
	"testing"
	"time"
)

func TestQuarantineRegistryDiscoversIntoQuarantine(t *testing.T) {
	registry := NewQuarantineRegistry()
	record, err := registry.Discover(context.Background(), DiscoverServerRequest{
		ServerID:  "srv-1",
		Name:      "local tools",
		Transport: "stdio",
		ToolNames: []string{"write_file", "read_file"},
		Risk:      ServerRiskHigh,
	})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if record.State != QuarantineQuarantined {
		t.Fatalf("new server state = %s, want %s", record.State, QuarantineQuarantined)
	}
	if err := registry.RequireApproved(context.Background(), "srv-1", time.Now().UTC()); err == nil {
		t.Fatal("quarantined server should not be approved")
	}
}

func TestQuarantineRegistryApprovalRequiresReceipt(t *testing.T) {
	registry := NewQuarantineRegistry()
	if _, err := registry.Discover(context.Background(), DiscoverServerRequest{ServerID: "srv-1"}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	_, err := registry.Approve(context.Background(), ApprovalDecision{
		ServerID:   "srv-1",
		ApproverID: "user:alice",
	})
	if err == nil {
		t.Fatal("approval without receipt should fail")
	}
}

func TestQuarantineRegistryApprovedServerPassesUntilExpiry(t *testing.T) {
	now := time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC)
	registry := NewQuarantineRegistry()
	if _, err := registry.Discover(context.Background(), DiscoverServerRequest{ServerID: "srv-1", DiscoveredAt: now}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	approved, err := registry.Approve(context.Background(), ApprovalDecision{
		ServerID:          "srv-1",
		ApproverID:        "user:alice",
		ApprovalReceiptID: "approval-r1",
		ApprovedAt:        now,
		ExpiresAt:         now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if approved.State != QuarantineApproved {
		t.Fatalf("state = %s, want approved", approved.State)
	}
	if err := registry.RequireApproved(context.Background(), "srv-1", now.Add(time.Minute)); err != nil {
		t.Fatalf("approved server denied: %v", err)
	}
	if err := registry.RequireApproved(context.Background(), "srv-1", now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired approval should fail closed")
	}
	expired, ok := registry.Get(context.Background(), "srv-1")
	if !ok {
		t.Fatal("record missing after expiry")
	}
	if expired.State != QuarantineExpired {
		t.Fatalf("state after expiry = %s, want expired", expired.State)
	}
}

func TestQuarantineRegistryRevokedServerDenied(t *testing.T) {
	registry := NewQuarantineRegistry()
	if _, err := registry.Discover(context.Background(), DiscoverServerRequest{ServerID: "srv-1"}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if _, err := registry.Approve(context.Background(), ApprovalDecision{
		ServerID:          "srv-1",
		ApproverID:        "user:alice",
		ApprovalReceiptID: "approval-r1",
	}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := registry.Revoke(context.Background(), "srv-1", "tool drift", time.Now().UTC()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := registry.RequireApproved(context.Background(), "srv-1", time.Now().UTC()); err == nil {
		t.Fatal("revoked server should fail closed")
	}
}
