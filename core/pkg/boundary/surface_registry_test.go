package boundary

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	_ "modernc.org/sqlite"
)

func TestSurfaceRegistrySeedsBoundaryRecordsAndCheckpoint(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })

	status := registry.Status("test", true, true, 1)
	if status.Status != "ready" || status.LastCheckpointHash == "" {
		t.Fatalf("unexpected status: %+v", status)
	}
	if len(registry.Capabilities()) < 6 {
		t.Fatal("expected SOTA boundary capability summaries")
	}
	if got := registry.ListRecords(contracts.BoundarySearchRequest{Limit: 10}); len(got) == 0 {
		t.Fatal("expected seeded boundary record")
	}
}

func TestSurfaceRegistryVerifyRecordDetectsTamper(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })

	record, err := registry.PutRecord(contracts.ExecutionBoundaryRecord{
		RecordID:    "rec-1",
		Verdict:     contracts.VerdictAllow,
		PolicyEpoch: "epoch-1",
		ToolName:    "tool",
		CreatedAt:   now,
	})
	if err != nil {
		t.Fatal(err)
	}
	verification := registry.VerifyRecord(record.RecordID)
	if !verification.Verified {
		t.Fatalf("expected record to verify: %+v", verification)
	}

	record.RecordHash = "sha256:tampered"
	registry.records[record.RecordID] = record
	verification = registry.VerifyRecord(record.RecordID)
	if verification.Verified {
		t.Fatal("expected tampered record to fail verification")
	}
}

func TestApprovalTransitionSealsCeremony(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })

	approval, err := registry.TransitionApproval("approval-bootstrap", contracts.ApprovalCeremonyAllowed, "user:alice", "rcpt-1", "reviewed")
	if err != nil {
		t.Fatal(err)
	}
	if approval.State != contracts.ApprovalCeremonyAllowed || approval.CeremonyHash == "" {
		t.Fatalf("unexpected approval: %+v", approval)
	}
}

func TestApprovalTransitionEnforcesQuorumAndTimelock(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })
	approval, err := registry.PutApproval(contracts.ApprovalCeremony{
		ApprovalID:    "approval-quorum",
		Subject:       "mcp:srv",
		Action:        "mcp.approve",
		State:         contracts.ApprovalCeremonyPending,
		RequestedBy:   "agent:test",
		Quorum:        2,
		TimelockUntil: now.Add(time.Minute),
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatal(err)
	}
	approval, err = registry.TransitionApproval(approval.ApprovalID, contracts.ApprovalCeremonyAllowed, "user:alice", "rcpt-1", "reviewed")
	if err != nil {
		t.Fatal(err)
	}
	if approval.State != contracts.ApprovalCeremonyPending {
		t.Fatalf("timelocked approval should remain pending: %+v", approval)
	}

	later := now.Add(2 * time.Minute)
	registry.now = func() time.Time { return later }
	approval, err = registry.TransitionApproval(approval.ApprovalID, contracts.ApprovalCeremonyAllowed, "user:alice", "rcpt-1", "reviewed")
	if err != nil {
		t.Fatal(err)
	}
	if approval.State != contracts.ApprovalCeremonyPending || len(approval.Approvers) != 1 {
		t.Fatalf("approval should remain pending until quorum: %+v", approval)
	}
	approval, err = registry.TransitionApproval(approval.ApprovalID, contracts.ApprovalCeremonyAllowed, "user:bob", "rcpt-2", "reviewed")
	if err != nil {
		t.Fatal(err)
	}
	if approval.State != contracts.ApprovalCeremonyAllowed {
		t.Fatalf("approval should activate after quorum: %+v", approval)
	}
}

func TestApprovalChallengeAssertionBindsPasskeyEvidence(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })
	challenge, err := registry.CreateApprovalChallenge("approval-bootstrap", "passkey", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := registry.AssertApprovalChallenge(contracts.ApprovalWebAuthnAssertion{
		ChallengeID: challenge.ChallengeID,
		Actor:       "user:alice",
		Assertion:   "signed-client-data",
		ReceiptID:   "rcpt-passkey",
		Reason:      "passkey assertion",
	})
	if err != nil {
		t.Fatal(err)
	}
	if approval.State != contracts.ApprovalCeremonyAllowed || approval.AuthMethod != "passkey" {
		t.Fatalf("passkey approval not bound: %+v", approval)
	}
	if approval.ChallengeHash == "" || approval.AssertionHash == "" {
		t.Fatalf("challenge/assertion hashes missing: %+v", approval)
	}
}

func TestFileBackedSurfaceRegistryPersistsRecords(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "surfaces.json")
	registry, err := NewFileBackedSurfaceRegistry(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	record, err := registry.PutRecord(contracts.ExecutionBoundaryRecord{
		RecordID:    "rec-durable",
		Verdict:     contracts.VerdictDeny,
		ReasonCode:  contracts.ReasonPolicyViolation,
		PolicyEpoch: "epoch-1",
		ToolName:    "tool.delete",
		CreatedAt:   now,
	})
	if err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewFileBackedSurfaceRegistry(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.GetRecord(record.RecordID)
	if !ok {
		t.Fatal("expected durable boundary record after reload")
	}
	if got.RecordHash != record.RecordHash {
		t.Fatalf("record hash changed after reload: %s != %s", got.RecordHash, record.RecordHash)
	}
}

func TestSQLSurfaceRegistryPersistsRecords(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "surfaces.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	registry, err := NewSQLSurfaceRegistry(context.Background(), db, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	record, err := registry.PutRecord(contracts.ExecutionBoundaryRecord{
		RecordID:    "rec-sql",
		Verdict:     contracts.VerdictDeny,
		ReasonCode:  contracts.ReasonPDPError,
		PolicyEpoch: "epoch-1",
		ToolName:    "tool.exec",
		CreatedAt:   now,
	})
	if err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewSQLSurfaceRegistry(context.Background(), db, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.GetRecord(record.RecordID)
	if !ok {
		t.Fatal("expected SQL-backed boundary record after reload")
	}
	if got.RecordHash != record.RecordHash {
		t.Fatalf("record hash changed after SQL reload: %s != %s", got.RecordHash, record.RecordHash)
	}
	var eventCount int
	if err := db.QueryRow(`SELECT count(*) FROM boundary_surface_events WHERE event_kind = 'record' AND object_id = ?`, record.RecordID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount == 0 {
		t.Fatal("expected append-only boundary event for record")
	}
	var indexedHash string
	if err := db.QueryRow(`SELECT record_hash FROM boundary_records_index WHERE record_id = ?`, record.RecordID).Scan(&indexedHash); err != nil {
		t.Fatal(err)
	}
	if indexedHash != record.RecordHash {
		t.Fatalf("record index hash = %s want %s", indexedHash, record.RecordHash)
	}
	verify := reloaded.VerifyCheckpoint(reloaded.ListCheckpoints()[0].CheckpointID)
	if verify["verified"] != true {
		t.Fatalf("checkpoint verification failed: %+v", verify)
	}
}
