package boundary

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
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

func TestApprovalTransitionIfCurrentRejectsStaleAndConcurrentSnapshots(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })
	approval, err := registry.PutApproval(contracts.ApprovalCeremony{
		ApprovalID:  "approval-cas",
		Subject:     "mcp:cas",
		Action:      "mcp.approve",
		State:       contracts.ApprovalCeremonyPending,
		RequestedBy: "agent:test",
		Quorum:      1,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.TransitionApprovalIfCurrent(approval.ApprovalID, contracts.ApprovalCeremonyAllowed, "user:alice", "receipt", "reviewed", "sha256:stale"); !errors.Is(err, ErrApprovalTransitionConflict) {
		t.Fatalf("stale transition error = %v, want conflict", err)
	}
	for _, item := range registry.ListApprovals() {
		if item.ApprovalID == approval.ApprovalID && (item.State != contracts.ApprovalCeremonyPending || item.CeremonyHash != approval.CeremonyHash) {
			t.Fatalf("stale transition mutated approval: %+v", item)
		}
	}

	type result struct {
		state    contracts.ApprovalCeremonyState
		approval contracts.ApprovalCeremony
		err      error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for _, state := range []contracts.ApprovalCeremonyState{contracts.ApprovalCeremonyAllowed, contracts.ApprovalCeremonyDenied} {
		go func(state contracts.ApprovalCeremonyState) {
			<-start
			transitioned, err := registry.TransitionApprovalIfCurrent(approval.ApprovalID, state, "user:alice", "receipt", "reviewed", approval.CeremonyHash)
			results <- result{state: state, approval: transitioned, err: err}
		}(state)
	}
	close(start)

	winners, conflicts := 0, 0
	var winner result
	for range 2 {
		result := <-results
		switch {
		case result.err == nil:
			winners++
			winner = result
		case errors.Is(result.err, ErrApprovalTransitionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent transition error = %v", result.err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("concurrent transition winners=%d conflicts=%d", winners, conflicts)
	}
	for _, item := range registry.ListApprovals() {
		if item.ApprovalID == approval.ApprovalID && item.State != winner.approval.State {
			t.Fatalf("winning transition %s was overwritten by %s", winner.state, item.State)
		}
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
