package boundary

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/lib/pq"
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

func TestApprovalTransitionFailsClosedWithoutWindow(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })

	if _, err := registry.TransitionApproval("approval-bootstrap", contracts.ApprovalCeremonyAllowed, "user:alice", "rcpt-1", "reviewed"); err == nil || !strings.Contains(err.Error(), "timelock_until and expires_at") {
		t.Fatalf("zero-value approval transition error = %v", err)
	}
	if approval := registry.approvals["approval-bootstrap"]; approval.State != contracts.ApprovalCeremonyPending {
		t.Fatalf("zero-value approval became authoritative: %+v", approval)
	}
}

func TestApprovalTransitionIfCurrentRejectsStaleAndConcurrentSnapshots(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })
	approval, err := registry.PutApproval(contracts.ApprovalCeremony{
		ApprovalID:    "approval-cas",
		Subject:       "mcp:cas",
		Action:        "mcp.approve",
		State:         contracts.ApprovalCeremonyPending,
		RequestedBy:   "agent:test",
		Quorum:        1,
		TimelockUntil: now.Add(-time.Minute),
		ExpiresAt:     now.Add(time.Hour),
		CreatedAt:     now,
		UpdatedAt:     now,
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
		ExpiresAt:     now.Add(10 * time.Minute),
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

// approvalAssertionVerifierFunc adapts a function to ApprovalAssertionVerifier
// for tests.
type approvalAssertionVerifierFunc func(challenge contracts.ApprovalWebAuthnChallenge, assertion contracts.ApprovalWebAuthnAssertion) error

func (f approvalAssertionVerifierFunc) VerifyApprovalAssertion(challenge contracts.ApprovalWebAuthnChallenge, assertion contracts.ApprovalWebAuthnAssertion) error {
	return f(challenge, assertion)
}

func TestApprovalChallengeAssertionFailsClosedWithoutVerifier(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })
	challenge, err := registry.CreateApprovalChallenge("approval-bootstrap", "passkey", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	assertion := contracts.ApprovalWebAuthnAssertion{
		ChallengeID: challenge.ChallengeID,
		Actor:       "user:alice",
		Assertion:   "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0.valid-looking-opaque-signature",
		ReceiptID:   "rcpt-passkey",
		Reason:      "passkey assertion",
	}
	for _, name := range []string{"first attempt", "repeated request"} {
		t.Run(name, func(t *testing.T) {
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
		})
	}
}

func TestApprovalChallengeAssertionRejectedByVerifierDoesNotTransition(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })
	registry.SetApprovalAssertionVerifier(approvalAssertionVerifierFunc(func(contracts.ApprovalWebAuthnChallenge, contracts.ApprovalWebAuthnAssertion) error {
		return errors.New("signature does not match registered credential")
	}))
	challenge, err := registry.CreateApprovalChallenge("approval-bootstrap", "passkey", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.AssertApprovalChallenge(contracts.ApprovalWebAuthnAssertion{
		ChallengeID: challenge.ChallengeID,
		Actor:       "user:alice",
		Assertion:   "garbage-signature",
	})
	if err == nil || errors.Is(err, ErrApprovalVerificationUnavailable) || !strings.Contains(err.Error(), "approval assertion rejected") {
		t.Fatalf("rejected assertion error = %v, want rejection distinct from unavailability", err)
	}
	if approval := registry.approvals["approval-bootstrap"]; approval.State != contracts.ApprovalCeremonyPending {
		t.Fatalf("rejected assertion transitioned approval: %+v", approval)
	}
	if persisted := registry.challenges[challenge.ChallengeID]; persisted.Verified || persisted.AssertionHash != "" {
		t.Fatalf("rejected assertion marked challenge verified: %+v", persisted)
	}
}

func TestApprovalChallengeAssertionVerifierUnavailableForCredentialFailsClosed(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })
	registry.SetApprovalAssertionVerifier(approvalAssertionVerifierFunc(func(challenge contracts.ApprovalWebAuthnChallenge, _ contracts.ApprovalWebAuthnAssertion) error {
		return fmt.Errorf("no verifier registered for method %q: %w", challenge.Method, ErrApprovalVerificationUnavailable)
	}))
	challenge, err := registry.CreateApprovalChallenge("approval-bootstrap", "hardware-token", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.AssertApprovalChallenge(contracts.ApprovalWebAuthnAssertion{
		ChallengeID: challenge.ChallengeID,
		Actor:       "user:alice",
		Assertion:   "assertion-for-unsupported-method",
	}); !errors.Is(err, ErrApprovalVerificationUnavailable) {
		t.Fatalf("assertion error = %v, want %v", err, ErrApprovalVerificationUnavailable)
	}
	if approval := registry.approvals["approval-bootstrap"]; approval.State != contracts.ApprovalCeremonyPending {
		t.Fatalf("unavailable verifier transitioned approval: %+v", approval)
	}
}

func TestApprovalChallengeAssertionBindsPasskeyEvidenceWithVerifier(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry := NewSurfaceRegistry(func() time.Time { return now })
	const approvalID = "approval-passkey"
	if _, err := registry.PutApproval(contracts.ApprovalCeremony{
		ApprovalID:    approvalID,
		Subject:       "mcp:passkey",
		Action:        "mcp.approve",
		State:         contracts.ApprovalCeremonyPending,
		RequestedBy:   "agent:test",
		TimelockUntil: now.Add(-time.Minute),
		ExpiresAt:     now.Add(time.Hour),
		CreatedAt:     now,
		UpdatedAt:     now,
	}); err != nil {
		t.Fatal(err)
	}
	var verified int
	registry.SetApprovalAssertionVerifier(approvalAssertionVerifierFunc(func(challenge contracts.ApprovalWebAuthnChallenge, assertion contracts.ApprovalWebAuthnAssertion) error {
		verified++
		if challenge.ApprovalID != approvalID || assertion.Assertion != "signed-client-data" {
			return errors.New("unexpected verification input")
		}
		return nil
	}))
	challenge, err := registry.CreateApprovalChallenge(approvalID, "passkey", time.Minute)
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
	if verified != 1 {
		t.Fatalf("verifier consulted %d times, want 1", verified)
	}
	if approval.State != contracts.ApprovalCeremonyAllowed || approval.AuthMethod != "passkey" {
		t.Fatalf("passkey approval not bound: %+v", approval)
	}
	if approval.ChallengeHash == "" || approval.AssertionHash == "" {
		t.Fatalf("challenge/assertion hashes missing: %+v", approval)
	}
	if persisted := registry.challenges[challenge.ChallengeID]; !persisted.Verified || persisted.AssertionHash != approval.AssertionHash {
		t.Fatalf("verified challenge not recorded: %+v", persisted)
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

func TestFileBackedSurfaceRegistryPersistsExplicitReceiptRefs(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "surfaces.json")
	registry, err := NewFileBackedSurfaceRegistry(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.PutVerificationScope(contracts.VerificationScope{VerificationScopeID: "scope-refs", ReceiptRefs: []string{"rcpt-scope"}, SubjectHash: "sha256:subject", ChecksPerformed: []string{"hash"}, VerifierHash: "sha256:verifier", PolicyHash: "sha256:policy"}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.PutPlanTransaction(contracts.PlanTransaction{PlanTransactionID: "tx-refs", ReceiptRefs: []string{"rcpt-tx"}, PlanHash: "sha256:plan", ReadSet: []string{"artifact:read"}, WriteSet: []string{"artifact:write"}, AssumptionSet: []string{"assumption"}, VerificationObligations: []string{"verify"}, ConflictPolicy: "deny"}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.PutGroundedAction(contracts.GroundedActionRef{GroundedActionID: "action-refs", ReceiptRefs: []string{"rcpt-action"}, ScreenshotHash: "sha256:screenshot", DOMOrAXSnapshotHash: "sha256:dom", TargetRef: "button#save", BBoxOrElementID: "button#save", ActionType: "click", Precondition: "form dirty", Postcondition: "saved", PostconditionRef: "proof:save", ProofGraphNodeRef: "proofgraph:save", VerificationScopeRef: "scope-refs", PolicyHash: "sha256:policy"}); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewFileBackedSurfaceRegistry(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := reloaded.GetVerificationScope("scope-refs"); !ok || len(got.ReceiptRefs) != 1 || got.ReceiptRefs[0] != "rcpt-scope" {
		t.Fatalf("persisted scope refs = %+v, found=%v", got.ReceiptRefs, ok)
	}
	if got, ok := reloaded.GetPlanTransaction("tx-refs"); !ok || len(got.ReceiptRefs) != 1 || got.ReceiptRefs[0] != "rcpt-tx" {
		t.Fatalf("persisted transaction refs = %+v, found=%v", got.ReceiptRefs, ok)
	}
	if got, ok := reloaded.GetGroundedAction("action-refs"); !ok || len(got.ReceiptRefs) != 1 || got.ReceiptRefs[0] != "rcpt-action" {
		t.Fatalf("persisted action refs = %+v, found=%v", got.ReceiptRefs, ok)
	}
}

func TestSQLSurfaceRegistryPersistsRecords(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "surfaces.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	registry, err := NewSQLSurfaceRegistry(context.Background(), db, "sqlite", func() time.Time { return now })
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

	reloaded, err := NewSQLSurfaceRegistry(context.Background(), db, "sqlite", func() time.Time { return now })
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

func TestSQLSurfaceRegistryPersistsRecordsOnPostgres(t *testing.T) {
	postgresURL := strings.TrimSpace(os.Getenv("HELM_TEST_POSTGRES_URL"))
	if postgresURL == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the Postgres boundary registry proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	schema := fmt.Sprintf("helm_boundary_%d", time.Now().UnixNano())
	adminDB, err := sql.Open("postgres", postgresURL)
	if err != nil {
		t.Fatal(err)
	}
	defer adminDB.Close()
	if _, err := adminDB.ExecContext(ctx, `CREATE SCHEMA `+pq.QuoteIdentifier(schema)); err != nil {
		t.Fatalf("create boundary test schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = adminDB.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+pq.QuoteIdentifier(schema)+` CASCADE`)
	}()

	parsed, err := url.Parse(postgresURL)
	if err != nil || parsed.Scheme == "" {
		t.Fatalf("HELM_TEST_POSTGRES_URL must be a URL-style Postgres DSN: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := sql.Open("postgres", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	registry, err := NewSQLSurfaceRegistry(ctx, db, "postgres", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	record, err := registry.PutRecord(contracts.ExecutionBoundaryRecord{
		RecordID:    "rec-postgres",
		Verdict:     contracts.VerdictDeny,
		ReasonCode:  contracts.ReasonPDPError,
		PolicyEpoch: "epoch-1",
		ToolName:    "tool.exec",
		CreatedAt:   now,
	})
	if err != nil {
		t.Fatal(err)
	}
	var sequence int64
	if err := db.QueryRowContext(ctx, `SELECT sequence FROM boundary_surface_events WHERE object_id = $1`, record.RecordID).Scan(&sequence); err != nil {
		t.Fatal(err)
	}
	if sequence <= 0 {
		t.Fatalf("Postgres identity sequence = %d, want positive", sequence)
	}
	reloaded, err := NewSQLSurfaceRegistry(ctx, db, "postgres", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := reloaded.GetRecord(record.RecordID); !ok || got.RecordHash != record.RecordHash {
		t.Fatalf("Postgres reload = (%+v, %v), want record hash %s", got, ok, record.RecordHash)
	}
}
