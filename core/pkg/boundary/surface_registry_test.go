package boundary

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
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

func TestApprovalTransitionPreservesImmutableBinding(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })
	pending, err := registry.PutApproval(contracts.ApprovalCeremony{
		ApprovalID:  "approval-command-bound",
		Subject:     "shell_command",
		Action:      "shell_operate",
		State:       contracts.ApprovalCeremonyPending,
		RequestedBy: "agent.local",
		BindingHash: "sha256:command-binding",
		Reason:      "request details",
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := registry.TransitionApproval(
		pending.ApprovalID,
		contracts.ApprovalCeremonyAllowed,
		"operator.cli",
		"",
		"approver-controlled reason",
	)
	if err != nil {
		t.Fatal(err)
	}
	if approved.BindingHash != pending.BindingHash {
		t.Fatalf("binding changed across transition: got %q want %q", approved.BindingHash, pending.BindingHash)
	}
	if approved.Reason != "approver-controlled reason" {
		t.Fatalf("reason = %q, want mutable audit note", approved.Reason)
	}
}

func TestApprovedApprovalCanOnlyBeRevokedOnce(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })
	if _, err := registry.TransitionApproval("approval-bootstrap", contracts.ApprovalCeremonyAllowed, "user:alice", "rcpt-1", "reviewed"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.TransitionApproval("approval-bootstrap", contracts.ApprovalCeremonyRevoked, "workstation.shellgate", "", "consumed"); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if _, err := registry.TransitionApproval("approval-bootstrap", contracts.ApprovalCeremonyRevoked, "workstation.shellgate", "", "consumed"); err == nil {
		t.Fatal("second revoke must fail atomically")
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

	// F-08: this test used to assert that two TransitionApproval calls naming
	// "user:alice" and "user:bob" satisfied the 2-of-2 quorum. Both calls carry
	// the same single credential and the name is just a string in the request,
	// so that encoded a dual-control bypass as expected behaviour. A multi-party
	// quorum must not be reachable from asserted actor names.
	later := now.Add(2 * time.Minute)
	registry.now = func() time.Time { return later }
	approval, err = registry.TransitionApproval(approval.ApprovalID, contracts.ApprovalCeremonyAllowed, "user:alice", "rcpt-1", "reviewed")
	if err != nil {
		t.Fatal(err)
	}
	if approval.State != contracts.ApprovalCeremonyPending {
		t.Fatalf("approval should remain pending past the timelock without a real quorum: %+v", approval)
	}
	approval, err = registry.TransitionApproval(approval.ApprovalID, contracts.ApprovalCeremonyAllowed, "user:bob", "rcpt-2", "reviewed")
	if err != nil {
		t.Fatal(err)
	}
	if approval.State == contracts.ApprovalCeremonyAllowed {
		t.Fatalf("a 2-of-2 quorum was satisfied by one caller asserting two names: %+v", approval)
	}
	if !strings.Contains(approval.Reason, "verified approver credentials") {
		t.Fatalf("refusal should name the missing requirement, got: %q", approval.Reason)
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

func TestApprovalChallengeAssertionCannotOverwriteConcurrentRevocation(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ {
		registry := NewSurfaceRegistry(func() time.Time { return now })
		approvalID := fmt.Sprintf("approval-concurrent-%d", i)
		if _, err := registry.PutApproval(contracts.ApprovalCeremony{
			ApprovalID:  approvalID,
			Subject:     "shell_command",
			Action:      "shell_operate",
			State:       contracts.ApprovalCeremonyPending,
			RequestedBy: "agent.local",
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			t.Fatal(err)
		}
		challenge, err := registry.CreateApprovalChallenge(approvalID, "passkey", time.Minute)
		if err != nil {
			t.Fatal(err)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var revokeErr error
		go func() {
			defer wg.Done()
			<-start
			_, _ = registry.AssertApprovalChallenge(contracts.ApprovalWebAuthnAssertion{
				ChallengeID: challenge.ChallengeID,
				Actor:       "user:alice",
				Assertion:   "signed-client-data",
			})
		}()
		go func() {
			defer wg.Done()
			<-start
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				items := registry.ListApprovals()
				for _, item := range items {
					if item.ApprovalID == approvalID && item.State == contracts.ApprovalCeremonyAllowed {
						_, revokeErr = registry.TransitionApproval(approvalID, contracts.ApprovalCeremonyRevoked, "workstation.shellgate", "", "consumed")
						return
					}
				}
			}
		}()
		close(start)
		wg.Wait()

		if revokeErr == nil {
			var final contracts.ApprovalCeremony
			for _, item := range registry.ListApprovals() {
				if item.ApprovalID == approvalID {
					final = item
				}
			}
			if final.State != contracts.ApprovalCeremonyRevoked {
				t.Fatalf("iteration %d: successful revoke was overwritten: %+v", i, final)
			}
		}
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
