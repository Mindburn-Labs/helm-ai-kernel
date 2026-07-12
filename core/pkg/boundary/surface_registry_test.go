package boundary

import (
	"context"
	"database/sql"
	"errors"
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

func TestApprovalTransitionFailsClosedWithoutVerifier(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })

	if _, err := registry.TransitionApproval("approval-bootstrap", contracts.ApprovalCeremonyAllowed, "user:alice", "rcpt-1", "reviewed"); !errors.Is(err, ErrApprovalVerificationUnavailable) {
		t.Fatalf("approval error = %v, want %v", err, ErrApprovalVerificationUnavailable)
	}
	approval := registry.approvals["approval-bootstrap"]
	if approval.State != contracts.ApprovalCeremonyPending {
		t.Fatalf("approval state = %q, want pending", approval.State)
	}
	if len(approval.Approvers) != 0 || approval.ReceiptID != "" {
		t.Fatalf("approval persisted unverified evidence: %+v", approval)
	}
}

func TestPutApprovalFailsClosedWhenAllowedWithoutVerifier(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })

	forged := contracts.ApprovalCeremony{
		ApprovalID:    "approval-forged",
		Subject:       "mcp:billing",
		Action:        "mcp.approve",
		State:         contracts.ApprovalCeremonyAllowed,
		RequestedBy:   "agent:untrusted",
		AuthMethod:    "passkey",
		AssertionHash: "sha256:opaque-assertion",
		ReceiptID:     "rcpt-forged",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if _, err := registry.PutApproval(forged); !errors.Is(err, ErrApprovalVerificationUnavailable) {
		t.Fatalf("put approval error = %v, want %v", err, ErrApprovalVerificationUnavailable)
	}
	if _, ok := registry.approvals[forged.ApprovalID]; ok {
		t.Fatalf("forged allowed approval persisted: %+v", registry.approvals[forged.ApprovalID])
	}

	bootstrap := registry.approvals["approval-bootstrap"]
	bootstrap.State = contracts.ApprovalCeremonyAllowed
	bootstrap.AuthMethod = "passkey"
	bootstrap.AssertionHash = "sha256:opaque-assertion"
	bootstrap.ReceiptID = "rcpt-forged"
	if _, err := registry.PutApproval(bootstrap); !errors.Is(err, ErrApprovalVerificationUnavailable) {
		t.Fatalf("replacement approval error = %v, want %v", err, ErrApprovalVerificationUnavailable)
	}
	persisted := registry.approvals["approval-bootstrap"]
	if persisted.State != contracts.ApprovalCeremonyPending || persisted.AuthMethod != "" || persisted.AssertionHash != "" || persisted.ReceiptID != "" {
		t.Fatalf("bootstrap approval mutated by forged write: %+v", persisted)
	}
}

func TestApprovalTransitionAllowsDenialWithoutVerifier(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })
	approval, err := registry.TransitionApproval("approval-bootstrap", contracts.ApprovalCeremonyDenied, "user:alice", "rcpt-1", "reviewed")
	if err != nil {
		t.Fatal(err)
	}
	if approval.State != contracts.ApprovalCeremonyDenied || len(approval.Approvers) != 1 || approval.ReceiptID != "rcpt-1" {
		t.Fatalf("denied approval = %+v", approval)
	}
}

func TestApprovalChallengeAssertionFailsClosedWithoutVerifier(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })
	challenge, err := registry.CreateApprovalChallenge("approval-bootstrap", "passkey", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	assertUnavailable := func(t *testing.T, assertion contracts.ApprovalWebAuthnAssertion) {
		t.Helper()
		if _, err := registry.AssertApprovalChallenge(assertion); !errors.Is(err, ErrApprovalVerificationUnavailable) {
			t.Fatalf("assertion error = %v, want %v", err, ErrApprovalVerificationUnavailable)
		}
		approval := registry.approvals["approval-bootstrap"]
		if approval.State != contracts.ApprovalCeremonyPending {
			t.Fatalf("approval state = %q, want pending", approval.State)
		}
		if approval.AuthMethod != "" || approval.ChallengeID != "" || approval.ChallengeHash != "" || approval.AssertionHash != "" {
			t.Fatalf("approval claimed unverified passkey evidence: %+v", approval)
		}
		persisted := registry.challenges[challenge.ChallengeID]
		if persisted.Verified || persisted.AssertionHash != "" {
			t.Fatalf("challenge claimed verification: %+v", persisted)
		}
	}

	assertion := contracts.ApprovalWebAuthnAssertion{
		ChallengeID: challenge.ChallengeID,
		Actor:       "user:alice",
		Assertion:   "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0.valid-looking-opaque-signature",
		ReceiptID:   "rcpt-passkey",
		Reason:      "passkey assertion",
	}
	t.Run("valid-looking opaque assertion", func(t *testing.T) {
		assertUnavailable(t, assertion)
	})
	t.Run("repeated request", func(t *testing.T) {
		assertUnavailable(t, assertion)
	})

	now = now.Add(2 * time.Minute)
	t.Run("expired challenge", func(t *testing.T) {
		assertUnavailable(t, assertion)
	})
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
