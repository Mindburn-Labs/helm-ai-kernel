package mcp

import (
	"context"
	"errors"
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

func TestQuarantineRegistryApprovalFailsClosedWithoutCredentialVerifier(t *testing.T) {
	registry := NewQuarantineRegistry()
	if _, err := registry.Discover(context.Background(), DiscoverServerRequest{ServerID: "srv-1"}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	_, err := registry.Approve(context.Background(), ApprovalDecision{
		ServerID:          "srv-1",
		ApproverID:        "user:alice",
		ApprovalReceiptID: "approval-r1",
		Reason:            "reviewed",
		ToolNames:         []string{"read_file"},
	})
	if !errors.Is(err, ErrApprovalVerificationUnavailable) {
		t.Fatalf("approve error = %v, want ErrApprovalVerificationUnavailable", err)
	}
}

func TestFailClosedUnverifiedApprovalRemovesOpaquePersistedMetadata(t *testing.T) {
	now := time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC)
	record := FailClosedUnverifiedApproval(ServerQuarantineRecord{
		ServerID:            "srv-opaque",
		State:               QuarantineApproved,
		ApprovedToolNames:   []string{"read_file"},
		ApprovedEffects:     []string{"read"},
		ApprovedAt:          now,
		ApprovedBy:          "user:opaque",
		ApprovalReceiptID:   "opaque-receipt",
		ApprovalReceiptPath: "/tmp/opaque-receipt.json",
		ExpiresAt:           now.Add(time.Hour),
		Reason:              "caller supplied",
	})
	if record.State != QuarantineQuarantined {
		t.Fatalf("state = %s, want %s", record.State, QuarantineQuarantined)
	}
	if record.ApprovedBy != "" || record.ApprovalReceiptID != "" || record.ApprovalReceiptPath != "" {
		t.Fatalf("opaque approval metadata survived: %+v", record)
	}
	if len(record.ApprovedToolNames) != 0 || len(record.ApprovedEffects) != 0 || !record.ApprovedAt.IsZero() || !record.ExpiresAt.IsZero() {
		t.Fatalf("opaque approval scope survived: %+v", record)
	}
	if record.Reason != ErrApprovalVerificationUnavailable.Error() {
		t.Fatalf("reason = %q", record.Reason)
	}
}

func TestQuarantineRegistryApprovedRecordPassesUntilExpiry(t *testing.T) {
	now := time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC)
	registry := NewQuarantineRegistry()
	if _, err := registry.Discover(context.Background(), DiscoverServerRequest{ServerID: "srv-1", DiscoveredAt: now}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	seedVerifiedApprovalFixture(t, registry, ApprovalDecision{
		ServerID:          "srv-1",
		ApproverID:        "verified:fixture",
		ApprovalReceiptID: "approval-r1",
		ApprovedAt:        now,
		ExpiresAt:         now.Add(time.Hour),
		Reason:            "fixture approval",
		ToolNames:         []string{"read_file"},
		Effects:           []string{"read"},
	})
	if err := registry.RequireApproved(context.Background(), "srv-1", now.Add(time.Minute)); err != nil {
		t.Fatalf("approved server denied: %v", err)
	}
	if err := registry.RequireApprovedTool(context.Background(), "srv-1", "read_file", "read", now.Add(time.Minute)); err != nil {
		t.Fatalf("approved tool denied: %v", err)
	}
	if err := registry.RequireApprovedTool(context.Background(), "srv-1", "write_file", "read", now.Add(time.Minute)); err == nil {
		t.Fatal("unapproved tool should fail closed")
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
	seedVerifiedApprovalFixture(t, registry, ApprovalDecision{
		ServerID:          "srv-1",
		ApproverID:        "verified:fixture",
		ApprovalReceiptID: "approval-r1",
		Reason:            "fixture approval",
		ToolNames:         []string{"read_file"},
	})
	if _, err := registry.Revoke(context.Background(), "srv-1", "tool drift", time.Now().UTC()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := registry.RequireApproved(context.Background(), "srv-1", time.Now().UTC()); err == nil {
		t.Fatal("revoked server should fail closed")
	}
}

func TestQuarantineRegistryLifecycleEdges(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 3, 9, 0, 0, 0, time.UTC)
	registry := NewQuarantineRegistry()

	if _, err := registry.Discover(ctx, DiscoverServerRequest{}); err == nil {
		t.Fatal("discover without server id should fail")
	}
	discovered, err := registry.Discover(ctx, DiscoverServerRequest{
		ServerID:  "srv-b",
		ToolNames: []string{"write", "read"},
	})
	if err != nil {
		t.Fatalf("discover defaulted server: %v", err)
	}
	if discovered.Risk != ServerRiskUnknown {
		t.Fatalf("default risk = %s, want unknown", discovered.Risk)
	}
	if discovered.DiscoveredAt.IsZero() {
		t.Fatal("discover without timestamp should set DiscoveredAt")
	}
	if got := discovered.ToolNames; len(got) != 2 || got[0] != "read" || got[1] != "write" {
		t.Fatalf("tool names were not sorted: %#v", got)
	}

	updated, err := registry.Discover(ctx, DiscoverServerRequest{
		ServerID:  "srv-b",
		ToolNames: []string{"execute"},
		Risk:      ServerRiskMedium,
		Reason:    "new tool observed",
	})
	if err != nil {
		t.Fatalf("rediscover quarantined server: %v", err)
	}
	if updated.State != QuarantineQuarantined || updated.Risk != ServerRiskMedium || updated.Reason != "new tool observed" {
		t.Fatalf("rediscover updated record = %+v", updated)
	}
	if len(updated.ToolNames) != 1 || updated.ToolNames[0] != "execute" {
		t.Fatalf("rediscover tools = %#v", updated.ToolNames)
	}

	if _, err := registry.Discover(ctx, DiscoverServerRequest{ServerID: "srv-a", DiscoveredAt: now}); err != nil {
		t.Fatalf("discover srv-a: %v", err)
	}
	listed := registry.List(ctx)
	if len(listed) != 2 || listed[0].ServerID != "srv-a" || listed[1].ServerID != "srv-b" {
		t.Fatalf("list ordering = %#v", listed)
	}

	if _, err := registry.Approve(ctx, ApprovalDecision{}); err == nil {
		t.Fatal("approve without server id should fail")
	}
	if _, err := registry.Approve(ctx, ApprovalDecision{ServerID: "missing", ApproverID: "user", ApprovalReceiptID: "receipt"}); err == nil {
		t.Fatal("approve missing server should fail")
	}
	if _, err := registry.Approve(ctx, ApprovalDecision{ServerID: "srv-a", ApprovalReceiptID: "receipt"}); err == nil {
		t.Fatal("approve without approver should fail")
	}
	if _, err := registry.Approve(ctx, ApprovalDecision{
		ServerID:          "srv-a",
		ApproverID:        "user:alice",
		ApprovalReceiptID: "receipt-a",
		ApprovedAt:        now,
		Reason:            "reviewed",
		ToolNames:         []string{"read"},
	}); !errors.Is(err, ErrApprovalVerificationUnavailable) {
		t.Fatalf("approve srv-a error = %v, want ErrApprovalVerificationUnavailable", err)
	}
	seedVerifiedApprovalFixture(t, registry, ApprovalDecision{
		ServerID:          "srv-a",
		ApproverID:        "verified:fixture",
		ApprovalReceiptID: "receipt-a",
		ApprovedAt:        now,
		Reason:            "reviewed",
		ToolNames:         []string{"read"},
		Effects:           []string{"read"},
	})
	rediscoveredApproved, err := registry.Discover(ctx, DiscoverServerRequest{
		ServerID: "srv-a",
		Risk:     ServerRiskCritical,
		Reason:   "should not overwrite approval",
	})
	if err != nil {
		t.Fatalf("rediscover approved server: %v", err)
	}
	if rediscoveredApproved.State != QuarantineApproved || rediscoveredApproved.Risk == ServerRiskCritical {
		t.Fatalf("approved rediscovery should return existing approval, got %+v", rediscoveredApproved)
	}
	if err := registry.RequireApproved(ctx, "srv-a", time.Time{}); err != nil {
		t.Fatalf("approved server without expiry should pass with default time: %v", err)
	}
	if err := registry.RequireApproved(ctx, "missing", now); err == nil {
		t.Fatal("unknown server should fail approval check")
	}

	if _, err := registry.Revoke(ctx, "", "missing id", now); err == nil {
		t.Fatal("revoke without server id should fail")
	}
	if _, err := registry.Revoke(ctx, "missing", "unknown", now); err == nil {
		t.Fatal("revoke missing server should fail")
	}
	revoked, err := registry.Revoke(ctx, "srv-b", "manual block", time.Time{})
	if err != nil {
		t.Fatalf("revoke srv-b: %v", err)
	}
	if revoked.State != QuarantineRevoked || revoked.RevokedAt.IsZero() || revoked.Reason != "manual block" {
		t.Fatalf("revoked record = %+v", revoked)
	}
	if _, err := registry.Approve(ctx, ApprovalDecision{
		ServerID:          "srv-b",
		ApproverID:        "user:alice",
		ApprovalReceiptID: "receipt-b",
		Reason:            "reviewed",
		ToolNames:         []string{"read"},
	}); err == nil {
		t.Fatal("revoked server should not be approvable")
	}
}
