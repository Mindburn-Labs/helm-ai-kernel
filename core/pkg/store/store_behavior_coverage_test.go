package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"

	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

func TestAuditStoreNewIsEmpty(t *testing.T) {
	s := NewAuditStore()
	if s.Size() != 0 || s.GetSequence() != 0 || s.GetChainHead() != "genesis" {
		t.Fatal("new audit store should be empty with genesis head")
	}
}

func TestAuditStoreAppendMultipleTypes(t *testing.T) {
	s := NewAuditStore()
	types := []EntryType{EntryTypeViolation, EntryTypeEvidence, EntryTypeSecurityEvent}
	for _, et := range types {
		if _, err := s.Append(et, "subj", "act", nil, nil); err != nil {
			t.Fatalf("append %s: %v", et, err)
		}
	}
	if s.Size() != 3 {
		t.Fatalf("expected 3, got %d", s.Size())
	}
}

func TestAuditStoreGetByHashNotFound(t *testing.T) {
	s := NewAuditStore()
	_, err := s.GetByHash("sha256:nonexistent")
	if !errors.Is(err, ErrEntryNotFound) {
		t.Fatal("expected ErrEntryNotFound for missing hash")
	}
}

func TestAuditStorePayloadHashComputed(t *testing.T) {
	s := NewAuditStore()
	e, _ := s.Append(EntryTypeAudit, "s", "a", map[string]string{"k": "v"}, nil)
	if e.PayloadHash == "" || e.PayloadHash[:7] != "sha256:" {
		t.Fatalf("expected sha256 payload hash, got %q", e.PayloadHash)
	}
}

func TestAuditStoreMetadataPreserved(t *testing.T) {
	s := NewAuditStore()
	meta := map[string]string{"env": "test", "region": "us-east-1"}
	e, _ := s.Append(EntryTypeAudit, "s", "a", nil, meta)
	if e.Metadata["env"] != "test" || e.Metadata["region"] != "us-east-1" {
		t.Fatal("metadata not preserved")
	}
}

func TestAuditStoreQueryMaxResults(t *testing.T) {
	s := NewAuditStore()
	for i := 0; i < 10; i++ {
		s.Append(EntryTypeAudit, "s", "a", nil, nil)
	}
	results := s.Query(QueryFilter{MaxResults: 3})
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
}

func TestAuditStoreVerifyChainEmpty(t *testing.T) {
	s := NewAuditStore()
	if err := s.VerifyChain(); err != nil {
		t.Fatalf("empty chain should verify: %v", err)
	}
}

func TestAuditStoreExportBundleNoMatch(t *testing.T) {
	s := NewAuditStore()
	s.Append(EntryTypeAudit, "s", "a", nil, nil)
	_, err := s.ExportBundle(QueryFilter{Subject: "no-match"})
	if err == nil {
		t.Fatal("expected error for empty bundle")
	}
}

func TestVerifyBundleEmpty(t *testing.T) {
	err := VerifyBundle(&AuditEvidenceBundle{Entries: []*AuditEntry{}})
	if err == nil {
		t.Fatal("expected error for empty bundle")
	}
}

func TestAuditStoreMultipleHandlers(t *testing.T) {
	s := NewAuditStore()
	count := 0
	s.AddHandler(func(_ *AuditEntry) { count++ })
	s.AddHandler(func(_ *AuditEntry) { count++ })
	s.Append(EntryTypeAudit, "s", "a", nil, nil)
	if count != 2 {
		t.Fatalf("expected 2 handler calls, got %d", count)
	}
}

// --- SQLite Receipt Store tests ---

func newTestSQLiteStore(t *testing.T) (*SQLiteReceiptStore, func()) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteReceiptStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return store, func() { _ = db.Close() }
}

func TestSQLiteReceiptStoreAndGet(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	r := &contracts.Receipt{ReceiptID: "r1", DecisionID: "d1", EffectID: "e1", Status: "OK", Timestamp: time.Now()}
	if err := store.Store(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(context.Background(), "d1")
	if err != nil || got.ReceiptID != "r1" {
		t.Fatalf("expected r1, got err=%v, receipt=%+v", err, got)
	}
}

func TestSQLiteReceiptV5RoundTripKeepsSignedGovernanceFields(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()

	signer, err := helmcrypto.NewEd25519Signer("sqlite-receipt-v5")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	receipt := &contracts.Receipt{
		ReceiptID:        "r-v5",
		DecisionID:       "d-v5",
		EffectID:         "e-v5",
		Status:           "OK",
		OutputHash:       "output-hash",
		DecisionHash:     "decision-hash",
		PrevHash:         "previous-hash",
		LamportClock:     7,
		ArgsHash:         "args-hash",
		SignatureVersion: contracts.ReceiptSignatureV5,
		Verdict:          "DENY",
		ReasonCode:       "POLICY_VIOLATION",
		PolicyHash:       "policy-content-hash",
		SessionID:        "session-v5",
		Timestamp:        time.Unix(1700000000, 0).UTC(),
	}
	if err := signer.SignReceipt(receipt); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	if err := store.Store(context.Background(), receipt); err != nil {
		t.Fatalf("store receipt: %v", err)
	}

	got, err := store.GetByReceiptID(context.Background(), receipt.ReceiptID)
	if err != nil {
		t.Fatalf("load receipt: %v", err)
	}
	if got.SignatureVersion != contracts.ReceiptSignatureV5 || got.DecisionHash != "decision-hash" || got.Verdict != "DENY" || got.ReasonCode != "POLICY_VIOLATION" || got.PolicyHash != "policy-content-hash" || got.SessionID != "session-v5" {
		t.Fatalf("V5 governance fields did not round-trip: %+v", got)
	}
	if ok, err := signer.VerifyReceipt(got); err != nil || !ok {
		t.Fatalf("reloaded V5 receipt did not verify: ok=%v err=%v", ok, err)
	}
}

func TestSQLiteReceiptAppendCausalPreservesCanonicalEnvelopeAcrossReload(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()
	const sessionID = "signed-session"

	var first *contracts.Receipt
	if err := store.AppendCausal(ctx, sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		first = storeCoverageReceipt("r-chain-first", "d-chain-first", sessionID, lamport, time.Unix(1700000000, 0).UTC())
		first.PrevHash = prevHash
		return first, nil
	}); err != nil {
		t.Fatalf("append first receipt: %v", err)
	}
	firstHash, err := contracts.ReceiptChainHash(first)
	if err != nil {
		t.Fatalf("hash first receipt at issuance: %v", err)
	}
	reloaded, err := store.GetByReceiptID(ctx, first.ReceiptID)
	if err != nil {
		t.Fatalf("reload first receipt: %v", err)
	}
	reloadedHash, err := contracts.ReceiptChainHash(reloaded)
	if err != nil {
		t.Fatalf("hash reloaded receipt: %v", err)
	}
	if reloadedHash != firstHash {
		t.Fatalf("reloaded hash = %q, want persisted chain hash %q", reloadedHash, firstHash)
	}
	if reloaded.EmergencyActivationID != first.EmergencyActivationID || reloaded.SafeDepState != first.SafeDepState {
		t.Fatalf("reloaded receipt lost hash-bound safe-deprecation fields: %+v", reloaded)
	}

	var second *contracts.Receipt
	if err := store.AppendCausal(ctx, sessionID, func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		if previous == nil || previous.ReceiptID != first.ReceiptID {
			t.Fatalf("builder previous = %+v, want first receipt", previous)
		}
		if prevHash != firstHash {
			t.Fatalf("durable prev_hash = %q, want issued chain hash %q", prevHash, firstHash)
		}
		second = storeCoverageReceipt("r-chain-second", "d-chain-second", sessionID, lamport, time.Unix(1700000001, 0).UTC())
		second.PrevHash = prevHash
		return second, nil
	}); err != nil {
		t.Fatalf("append second receipt: %v", err)
	}
	if second == nil || second.PrevHash != firstHash {
		t.Fatalf("second receipt prev_hash = %+v, want %q", second, firstHash)
	}
}

func TestSQLiteReceiptEnvelopeCompatibilityBackfillAndProofBoundary(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()
	const legacySessionID = "legacy-envelope-session"

	projectionOnly := &contracts.Receipt{
		ReceiptID:             "r-legacy-projection-only",
		DecisionID:            "d-legacy-projection-only",
		EffectID:              "effect",
		Status:                "OK",
		BlobHash:              "blob",
		OutputHash:            "output",
		Timestamp:             time.Unix(1700000100, 0).UTC(),
		ExecutorID:            legacySessionID,
		Signature:             "legacy-signature",
		PrevHash:              "prior-hash",
		LamportClock:          7,
		ArgsHash:              "args",
		EmergencyActivationID: "activation-lost-by-old-projection",
		SafeDepState:          string(contracts.SafeDepDegradedNarrowing),
	}
	projectionOnlyHash, err := contracts.ReceiptChainHash(projectionOnly)
	if err != nil {
		t.Fatalf("hash projection-only historical receipt: %v", err)
	}
	insertLegacySQLiteReceiptProjection(t, store, projectionOnly, legacySessionID, projectionOnlyHash)

	matchingProjection := &contracts.Receipt{
		ReceiptID:    "r-legacy-hash-equal",
		DecisionID:   "d-legacy-hash-equal",
		EffectID:     "effect",
		Status:       "OK",
		BlobHash:     "blob",
		OutputHash:   "output",
		Timestamp:    time.Unix(1700000200, 0).UTC(),
		ExecutorID:   "legacy-hash-equal-session",
		Signature:    "legacy-signature",
		PrevHash:     "prior-hash",
		LamportClock: 1,
		ArgsHash:     "args",
	}
	matchingProjectionHash, err := contracts.ReceiptChainHash(matchingProjection)
	if err != nil {
		t.Fatalf("hash matching historical projection: %v", err)
	}
	insertLegacySQLiteReceiptProjection(t, store, matchingProjection, matchingProjection.ExecutorID, matchingProjectionHash)

	if err := store.migrate(); err != nil {
		t.Fatalf("backfill receipt envelopes: %v", err)
	}

	operational, err := store.GetByReceiptID(ctx, projectionOnly.ReceiptID)
	if err != nil {
		t.Fatalf("read projection-only receipt for operations: %v", err)
	}
	if operational.ReceiptID != projectionOnly.ReceiptID || operational.EmergencyActivationID != "" || operational.SafeDepState != "" {
		t.Fatalf("legacy operational projection was not returned faithfully: %+v", operational)
	}
	if _, err := store.GetCanonicalReceiptByID(ctx, projectionOnly.ReceiptID); err == nil || !strings.Contains(err.Error(), "cannot be used as verified evidence") {
		t.Fatalf("projection-only receipt unexpectedly crossed proof boundary: %v", err)
	}

	var incompleteEnvelope sql.NullString
	if err := store.db.QueryRowContext(ctx, `SELECT receipt_envelope FROM receipts WHERE receipt_id = ?`, projectionOnly.ReceiptID).Scan(&incompleteEnvelope); err != nil {
		t.Fatalf("read projection-only envelope column: %v", err)
	}
	if incompleteEnvelope.Valid && strings.TrimSpace(incompleteEnvelope.String) != "" && incompleteEnvelope.String != "null" {
		t.Fatalf("hash-mismatched projection was backfilled as canonical: %q", incompleteEnvelope.String)
	}

	backfilled, err := store.GetCanonicalReceiptByID(ctx, matchingProjection.ReceiptID)
	if err != nil {
		t.Fatalf("read hash-equal backfilled receipt as canonical: %v", err)
	}
	backfilledHash, err := contracts.ReceiptChainHash(backfilled)
	if err != nil || backfilledHash != matchingProjectionHash {
		t.Fatalf("backfilled canonical hash = %q err=%v, want %q", backfilledHash, err, matchingProjectionHash)
	}
	var recoveredEnvelope sql.NullString
	if err := store.db.QueryRowContext(ctx, `SELECT receipt_envelope FROM receipts WHERE receipt_id = ?`, matchingProjection.ReceiptID).Scan(&recoveredEnvelope); err != nil {
		t.Fatalf("read hash-equal envelope column: %v", err)
	}
	if !recoveredEnvelope.Valid || strings.TrimSpace(recoveredEnvelope.String) == "" || recoveredEnvelope.String == "null" {
		t.Fatal("hash-equal historical projection was not backfilled")
	}

	var successor *contracts.Receipt
	if err := store.AppendCausal(ctx, legacySessionID, func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		if previous == nil || previous.ReceiptID != projectionOnly.ReceiptID {
			t.Fatalf("causal predecessor = %+v, want legacy projection", previous)
		}
		if lamport != projectionOnly.LamportClock+1 || prevHash != projectionOnlyHash {
			t.Fatalf("causal allocation = lamport %d prev_hash %q, want %d and durable %q", lamport, prevHash, projectionOnly.LamportClock+1, projectionOnlyHash)
		}
		successor = &contracts.Receipt{
			ReceiptID:    "r-after-legacy-projection",
			DecisionID:   "d-after-legacy-projection",
			EffectID:     "effect",
			Status:       "OK",
			Timestamp:    time.Unix(1700000300, 0).UTC(),
			ExecutorID:   legacySessionID,
			Signature:    "new-signature",
			PrevHash:     prevHash,
			LamportClock: lamport,
			ArgsHash:     "args",
		}
		return successor, nil
	}); err != nil {
		t.Fatalf("append after projection-only receipt: %v", err)
	}
	if successor == nil || successor.PrevHash != projectionOnlyHash {
		t.Fatalf("successor lost durable legacy predecessor hash: %+v", successor)
	}
}

func TestSQLiteReceiptCanonicalEnvelopeRejectsTamperedFilterProjection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		field     string
		updateSQL string
		value     any
	}{
		{"verdict", "verdict", `UPDATE receipts SET verdict = ? WHERE receipt_id = ?`, "DENY"},
		{"reason code", "reason_code", `UPDATE receipts SET reason_code = ? WHERE receipt_id = ?`, "tampered.reason"},
		{"executor", "executor_id", `UPDATE receipts SET executor_id = ? WHERE receipt_id = ?`, "tampered-executor"},
		{"effect", "effect_id", `UPDATE receipts SET effect_id = ? WHERE receipt_id = ?`, "tampered-effect"},
		{"timestamp", "timestamp", `UPDATE receipts SET timestamp = ? WHERE receipt_id = ?`, "2026-08-02T12:00:00.123456790Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, cleanup := newTestSQLiteStore(t)
			defer cleanup()
			ctx := context.Background()
			receipt := storeCoverageReceipt(
				"receipt-projection-tamper",
				"decision-projection-tamper",
				"projection-session",
				1,
				time.Date(2026, 8, 2, 12, 0, 0, 123456789, time.UTC),
			)
			if err := store.Store(ctx, receipt); err != nil {
				t.Fatalf("store canonical receipt: %v", err)
			}
			if _, err := store.db.ExecContext(ctx, tc.updateSQL, tc.value, receipt.ReceiptID); err != nil {
				t.Fatalf("tamper %s projection: %v", tc.field, err)
			}
			if _, err := store.GetByReceiptID(ctx, receipt.ReceiptID); err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("tampered %s projection did not fail closed: %v", tc.field, err)
			}
		})
	}
}

func insertLegacySQLiteReceiptProjection(t *testing.T, store *SQLiteReceiptStore, receipt *contracts.Receipt, causalSessionID, chainHash string) {
	t.Helper()
	_, err := store.db.ExecContext(context.Background(), `INSERT INTO receipts (
		receipt_id, decision_id, effect_id, status, blob_hash, output_hash, timestamp,
		executor_id, signature, prev_hash, lamport_clock, args_hash, causal_session_id, chain_hash
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		receipt.ReceiptID,
		receipt.DecisionID,
		receipt.EffectID,
		receipt.Status,
		receipt.BlobHash,
		receipt.OutputHash,
		receipt.Timestamp.UTC().Format(time.RFC3339Nano),
		receipt.ExecutorID,
		receipt.Signature,
		receipt.PrevHash,
		receipt.LamportClock,
		receipt.ArgsHash,
		causalSessionID,
		chainHash,
	)
	if err != nil {
		t.Fatalf("insert legacy receipt projection %q: %v", receipt.ReceiptID, err)
	}
}

func TestSQLiteReceiptMigrationBackfillsOrRejectsV5DecisionHash(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()
	timestamp := time.Unix(1700000000, 0).UTC().Format(time.RFC3339Nano)

	// This models rows written before the decision_hash column was added. The
	// known metadata value is a trusted recovery source and must be materialized
	// into the dedicated column by the additive migration.
	if _, err := store.db.ExecContext(ctx, `INSERT INTO receipts (
		receipt_id, decision_id, effect_id, status, blob_hash, output_hash, timestamp,
		signature_version, session_id, metadata
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"r-v5-recoverable", "d-v5-recoverable", "effect", "ALLOW", "", "sha256:output", timestamp,
		contracts.ReceiptSignatureV5, "session-recoverable", `{"decision_hash":"sha256:trusted"}`); err != nil {
		t.Fatalf("insert recoverable historical receipt: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO receipts (
		receipt_id, decision_id, effect_id, status, blob_hash, output_hash, timestamp,
		signature_version, session_id
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"r-v5-unrecoverable", "d-v5-unrecoverable", "effect", "ALLOW", "", "sha256:output", timestamp,
		contracts.ReceiptSignatureV5, "session-unrecoverable"); err != nil {
		t.Fatalf("insert unrecoverable historical receipt: %v", err)
	}
	if err := store.migrate(); err != nil {
		t.Fatalf("backfill decision hashes: %v", err)
	}

	var recoveredHash string
	if err := store.db.QueryRowContext(ctx, `SELECT decision_hash FROM receipts WHERE receipt_id = ?`, "r-v5-recoverable").Scan(&recoveredHash); err != nil {
		t.Fatalf("read recovered decision hash: %v", err)
	}
	if recoveredHash != "sha256:trusted" {
		t.Fatalf("durable migration decision_hash = %q, want trusted metadata value", recoveredHash)
	}
	recovered, err := store.GetByReceiptID(ctx, "r-v5-recoverable")
	if err != nil || recovered.DecisionHash != recoveredHash {
		t.Fatalf("recoverable V5 receipt = %+v err=%v", recovered, err)
	}
	if _, err := store.GetByReceiptID(ctx, "r-v5-unrecoverable"); err == nil || !strings.Contains(err.Error(), "004_add_receipt_decision_hash.sql") {
		t.Fatalf("unrecoverable V5 receipt did not fail closed with migration guidance: %v", err)
	}
}

func TestSQLiteReceiptGetByReceiptID(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	r := &contracts.Receipt{ReceiptID: "r2", DecisionID: "d2", EffectID: "e2", Status: "OK", Timestamp: time.Now()}
	store.Store(context.Background(), r)
	got, err := store.GetByReceiptID(context.Background(), "r2")
	if err != nil || got.DecisionID != "d2" {
		t.Fatal("GetByReceiptID failed")
	}
}

func TestSQLiteReceiptList(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		store.Store(ctx, &contracts.Receipt{
			ReceiptID: fmt.Sprintf("r%d", i), DecisionID: fmt.Sprintf("d%d", i),
			EffectID: "e", Status: "OK", Timestamp: time.Now(),
		})
	}
	list, err := store.List(ctx, 3)
	if err != nil || len(list) != 3 {
		t.Fatalf("expected 3 receipts, got %d, err=%v", len(list), err)
	}
}

func TestSQLiteReceiptRoundTripsChainFieldsAndAgentFilter(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()
	receipts := []*contracts.Receipt{
		{
			ReceiptID:    "r-agent-1",
			DecisionID:   "d-agent-1",
			EffectID:     "e",
			Status:       "OK",
			Timestamp:    time.Now().Add(-time.Second),
			ExecutorID:   "agent.demo.exec",
			PrevHash:     "prev-0",
			LamportClock: 1,
			ArgsHash:     "args-1",
			BlobHash:     "blob-1",
		},
		{
			ReceiptID:    "r-agent-2",
			DecisionID:   "d-agent-2",
			EffectID:     "e",
			Status:       "OK",
			Timestamp:    time.Now(),
			ExecutorID:   "agent.demo.exec",
			PrevHash:     "prev-1",
			LamportClock: 2,
			ArgsHash:     "args-2",
			BlobHash:     "blob-2",
		},
		{
			ReceiptID:    "r-other",
			DecisionID:   "d-other",
			EffectID:     "e",
			Status:       "OK",
			Timestamp:    time.Now(),
			ExecutorID:   "agent.other",
			LamportClock: 3,
		},
	}
	for _, receipt := range receipts {
		if err := store.Store(ctx, receipt); err != nil {
			t.Fatal(err)
		}
	}

	got, err := store.GetByReceiptID(ctx, "r-agent-2")
	if err != nil {
		t.Fatal(err)
	}
	if got.PrevHash != "prev-1" || got.LamportClock != 2 || got.ArgsHash != "args-2" || got.BlobHash != "blob-2" {
		t.Fatalf("chain fields did not round-trip: %+v", got)
	}

	filtered, err := store.ListByAgent(ctx, "agent.demo.exec", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].ReceiptID != "r-agent-2" {
		t.Fatalf("unexpected agent filter result: %+v", filtered)
	}

	allSince, err := store.ListSince(ctx, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(allSince) != 2 || allSince[0].ReceiptID != "r-agent-2" || allSince[1].ReceiptID != "r-other" {
		t.Fatalf("unexpected cursor result: %+v", allSince)
	}
}

func TestSQLiteReceiptEnforcesLamportUniquenessPerSession(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()
	first := &contracts.Receipt{
		ReceiptID:        "r-dup-1",
		DecisionID:       "d-dup-1",
		EffectID:         "e",
		Status:           "OK",
		Timestamp:        time.Now(),
		ExecutorID:       "agent.dup",
		DecisionHash:     "decision-hash-1",
		SignatureVersion: contracts.ReceiptSignatureV5,
		SessionID:        "session-a",
		LamportClock:     9,
	}
	second := &contracts.Receipt{
		ReceiptID:        "r-dup-2",
		DecisionID:       "d-dup-2",
		EffectID:         "e",
		Status:           "OK",
		Timestamp:        time.Now().Add(time.Second),
		ExecutorID:       "agent.dup",
		DecisionHash:     "decision-hash-2",
		SignatureVersion: contracts.ReceiptSignatureV5,
		SessionID:        "session-b",
		LamportClock:     9,
	}
	if err := store.Store(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Store(ctx, second); err != nil {
		t.Fatalf("same executor should be able to begin a second session at the same Lamport clock: %v", err)
	}

	duplicateSessionLamport := *first
	duplicateSessionLamport.ReceiptID = "r-dup-3"
	duplicateSessionLamport.DecisionID = "d-dup-3"
	duplicateSessionLamport.Timestamp = time.Now().Add(2 * time.Second)
	if err := store.Store(ctx, &duplicateSessionLamport); err == nil {
		t.Fatal("expected duplicate session/lamport receipt to fail")
	}
}

func TestSQLiteReceiptMigrationReplacesExecutorLamportUniqueIndex(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()

	if _, err := store.db.Exec(`DROP INDEX idx_receipts_causal_session_lamport_unique`); err != nil {
		t.Fatalf("drop current causal-session index: %v", err)
	}
	if _, err := store.db.Exec(`CREATE UNIQUE INDEX idx_receipts_executor_lamport_unique ON receipts(executor_id, lamport_clock) WHERE executor_id IS NOT NULL AND executor_id <> '' AND lamport_clock > 0`); err != nil {
		t.Fatalf("install legacy executor index: %v", err)
	}
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `INSERT INTO receipts (receipt_id, decision_id, effect_id, status, blob_hash, output_hash, timestamp, executor_id, lamport_clock, signature_version, session_id, causal_session_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"r-legacy", "d-legacy", "e", "OK", "", "", time.Now().UTC().Format(time.RFC3339Nano), "agent.migrated", 1, "", "", ""); err != nil {
		t.Fatalf("insert legacy receipt: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO receipts (receipt_id, decision_id, effect_id, status, blob_hash, output_hash, timestamp, executor_id, lamport_clock, signature_version, session_id, causal_session_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"r-v5-empty-session", "d-v5-empty-session", "e", "OK", "", "", time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano), "agent-v5", 1, contracts.ReceiptSignatureV5, "", ""); err != nil {
		t.Fatalf("insert V5 receipt: %v", err)
	}
	if err := store.migrate(); err != nil {
		t.Fatalf("migrate legacy executor index: %v", err)
	}

	for receiptID, wantCausalSession := range map[string]string{
		"r-legacy":           "agent.migrated",
		"r-v5-empty-session": "",
	} {
		var got string
		if err := store.db.QueryRowContext(ctx, `SELECT causal_session_id FROM receipts WHERE receipt_id = ?`, receiptID).Scan(&got); err != nil {
			t.Fatalf("read causal session for %s: %v", receiptID, err)
		}
		if got != wantCausalSession {
			t.Fatalf("causal session for %s = %q, want %q", receiptID, got, wantCausalSession)
		}
	}
	legacy, err := store.GetLastForSession(ctx, "agent.migrated")
	if err != nil || legacy == nil || legacy.ReceiptID != "r-legacy" || legacy.SessionID != "" {
		t.Fatalf("legacy receipt was not found without rewriting its envelope: receipt=%+v err=%v", legacy, err)
	}

	legacyBuilderCalled := false
	err = store.AppendCausal(ctx, "agent.migrated", func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		legacyBuilderCalled = true
		return &contracts.Receipt{
			ReceiptID:        "r-v5-after-legacy",
			DecisionID:       "d-v5-after-legacy",
			EffectID:         "e",
			Status:           "OK",
			Timestamp:        time.Now().UTC(),
			ExecutorID:       "agent.migrated",
			DecisionHash:     "decision-hash-after-legacy",
			SignatureVersion: contracts.ReceiptSignatureV5,
			SessionID:        "agent.migrated",
			PrevHash:         prevHash,
			LamportClock:     lamport,
		}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "no persisted chain hash") {
		t.Fatalf("expected legacy chain rejection, got %v", err)
	}
	if legacyBuilderCalled {
		t.Fatal("legacy chain builder ran despite missing persisted hash")
	}

	if err := store.AppendCausal(ctx, "session-after-legacy", func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		return &contracts.Receipt{
			ReceiptID:        "r-v5-after-legacy",
			DecisionID:       "d-v5-after-legacy",
			EffectID:         "e",
			Status:           "OK",
			Timestamp:        time.Now().UTC(),
			ExecutorID:       "agent.migrated",
			DecisionHash:     "decision-hash-after-legacy",
			SignatureVersion: contracts.ReceiptSignatureV5,
			SessionID:        "session-after-legacy",
			PrevHash:         prevHash,
			LamportClock:     lamport,
		}, nil
	}); err != nil {
		t.Fatalf("append new session after legacy migration: %v", err)
	}
	fresh, err := store.GetLastForSession(ctx, "session-after-legacy")
	if err != nil || fresh == nil || fresh.ReceiptID != "r-v5-after-legacy" || fresh.LamportClock != 1 {
		t.Fatalf("new signed session did not start after migration: receipt=%+v err=%v", fresh, err)
	}

	for _, receipt := range []*contracts.Receipt{
		{
			ReceiptID:        "r-migrated-a",
			DecisionID:       "d-migrated-a",
			EffectID:         "e",
			Status:           "OK",
			Timestamp:        time.Now(),
			ExecutorID:       "agent.migrated",
			DecisionHash:     "decision-hash-migrated-a",
			SignatureVersion: contracts.ReceiptSignatureV5,
			SessionID:        "session-a",
			LamportClock:     1,
		},
		{
			ReceiptID:        "r-migrated-b",
			DecisionID:       "d-migrated-b",
			EffectID:         "e",
			Status:           "OK",
			Timestamp:        time.Now().Add(time.Second),
			ExecutorID:       "agent.migrated",
			DecisionHash:     "decision-hash-migrated-b",
			SignatureVersion: contracts.ReceiptSignatureV5,
			SessionID:        "session-b",
			LamportClock:     1,
		},
	} {
		if err := store.Store(ctx, receipt); err != nil {
			t.Fatalf("store %s after migration: %v", receipt.ReceiptID, err)
		}
	}
}

func TestSQLiteReceiptAppendCausalAssignsChainInsideStore(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()
	const sessionID = "agent.causal"
	first := func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		return &contracts.Receipt{
			ReceiptID:    "r-causal-1",
			DecisionID:   "d-causal-1",
			EffectID:     "e",
			Status:       "OK",
			Timestamp:    time.Unix(1700000000, 0).UTC(),
			ExecutorID:   "agent.causal",
			SessionID:    sessionID,
			PrevHash:     prevHash,
			LamportClock: lamport,
			Signature:    "sig-1",
		}, nil
	}
	if err := store.AppendCausal(ctx, sessionID, first); err != nil {
		t.Fatal(err)
	}

	var seenPrevious *contracts.Receipt
	second := func(previous *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		seenPrevious = previous
		return &contracts.Receipt{
			ReceiptID:    "r-causal-2",
			DecisionID:   "d-causal-2",
			EffectID:     "e",
			Status:       "OK",
			Timestamp:    time.Unix(1700000001, 0).UTC(),
			ExecutorID:   "agent.causal",
			SessionID:    sessionID,
			PrevHash:     prevHash,
			LamportClock: lamport,
			Signature:    "sig-2",
		}, nil
	}
	if err := store.AppendCausal(ctx, sessionID, second); err != nil {
		t.Fatal(err)
	}
	if seenPrevious == nil || seenPrevious.ReceiptID != "r-causal-1" {
		t.Fatalf("builder did not receive previous receipt: %+v", seenPrevious)
	}
	got, err := store.GetByReceiptID(ctx, "r-causal-2")
	if err != nil {
		t.Fatal(err)
	}
	expectedPrevHash, err := contracts.ReceiptChainHash(seenPrevious)
	if err != nil {
		t.Fatal(err)
	}
	if got.LamportClock != 2 || got.PrevHash != expectedPrevHash {
		t.Fatalf("causal fields = lamport %d prev %q, want 2 %q", got.LamportClock, got.PrevHash, expectedPrevHash)
	}
}

func TestSQLiteReceiptAppendCausalRejectsLegacyBlankChainHash(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()
	const sessionID = "agent.legacy-chain"
	if err := store.AppendCausal(ctx, sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		return &contracts.Receipt{
			ReceiptID:    "r-legacy-chain-1",
			DecisionID:   "d-legacy-chain-1",
			EffectID:     "e",
			Status:       "OK",
			Timestamp:    time.Unix(1700000000, 0).UTC(),
			ExecutorID:   "agent.legacy-chain",
			SessionID:    sessionID,
			PrevHash:     prevHash,
			LamportClock: lamport,
			Signature:    "sig-1",
		}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE receipts SET chain_hash = '' WHERE receipt_id = ?`, "r-legacy-chain-1"); err != nil {
		t.Fatalf("clear persisted chain hash: %v", err)
	}
	if err := store.PreflightCausalAppend(ctx, sessionID); err == nil || !strings.Contains(err.Error(), "no persisted chain hash") {
		t.Fatalf("expected legacy chain preflight rejection, got %v", err)
	}
	builderCalled := false
	err := store.AppendCausal(ctx, sessionID, func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error) {
		builderCalled = true
		return nil, nil
	})
	if err == nil || !strings.Contains(err.Error(), "no persisted chain hash") {
		t.Fatalf("expected legacy chain hash rejection, got %v", err)
	}
	if builderCalled {
		t.Fatal("builder ran after legacy chain hash rejection")
	}
}

func TestSQLiteReceiptGetLastForSignedSessionWithoutExecutorID(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	ctx := context.Background()

	for _, receipt := range []*contracts.Receipt{
		{
			ReceiptID:        "r-session-1",
			DecisionID:       "d-session-1",
			EffectID:         "effect",
			Status:           "OK",
			Timestamp:        time.Unix(1700000000, 0).UTC(),
			DecisionHash:     "decision-hash-session-1",
			SignatureVersion: contracts.ReceiptSignatureV5,
			SessionID:        "signed-session",
			LamportClock:     1,
		},
		{
			ReceiptID:        "r-other-session",
			DecisionID:       "d-other-session",
			EffectID:         "effect",
			Status:           "OK",
			Timestamp:        time.Unix(1700000001, 0).UTC(),
			DecisionHash:     "decision-hash-other-session",
			SignatureVersion: contracts.ReceiptSignatureV5,
			SessionID:        "other-session",
			LamportClock:     99,
		},
		{
			ReceiptID:        "r-session-2",
			DecisionID:       "d-session-2",
			EffectID:         "effect",
			Status:           "OK",
			Timestamp:        time.Unix(1700000002, 0).UTC(),
			DecisionHash:     "decision-hash-session-2",
			SignatureVersion: contracts.ReceiptSignatureV5,
			SessionID:        "signed-session",
			LamportClock:     2,
		},
	} {
		if err := store.Store(ctx, receipt); err != nil {
			t.Fatalf("store %s: %v", receipt.ReceiptID, err)
		}
	}

	got, err := store.GetLastForSession(ctx, "signed-session")
	if err != nil {
		t.Fatalf("get last signed session: %v", err)
	}
	if got == nil || got.ReceiptID != "r-session-2" || got.ExecutorID != "" || got.SessionID != "signed-session" || got.LamportClock != 2 {
		t.Fatalf("last receipt should be selected by signed session_id, got %+v", got)
	}
}

func TestPostgresReceiptAppendCausalParallelOutperformsSQLite(t *testing.T) {
	postgresURL := os.Getenv("HELM_TEST_POSTGRES_URL")
	if postgresURL == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run Postgres receipt throughput gate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	const sessions = 64
	const appendsPerSession = 50

	sqliteDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "receipts.db"))
	if err != nil {
		t.Fatal(err)
	}
	sqliteStore, err := NewSQLiteReceiptStore(sqliteDB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteDB.Close() }()

	schema := fmt.Sprintf("helm_receipts_%d", time.Now().UnixNano())
	pgURL := postgresURLWithSearchPath(t, postgresURL, schema)
	postgresDB, err := sql.Open("postgres", pgURL)
	if err != nil {
		t.Fatal(err)
	}
	postgresDB.SetMaxOpenConns(sessions)
	postgresDB.SetMaxIdleConns(sessions)
	postgresDB.SetConnMaxLifetime(time.Minute)
	defer func() { _ = postgresDB.Close() }()
	if _, err := postgresDB.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS `+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = postgresDB.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	}()
	postgresStore := NewPostgresReceiptStore(postgresDB)
	if err := postgresStore.Init(ctx); err != nil {
		t.Fatalf("init postgres store: %v", err)
	}

	sqliteDuration := runReceiptAppendCausalLoad(t, ctx, sqliteStore, "sqlite", sessions, appendsPerSession)
	postgresDuration := runReceiptAppendCausalLoad(t, ctx, postgresStore, "postgres", sessions, appendsPerSession)
	t.Logf("parallel causal append: sqlite=%s postgres=%s sessions=%d appends_per_session=%d", sqliteDuration, postgresDuration, sessions, appendsPerSession)
	if postgresDuration >= sqliteDuration {
		t.Fatalf("parallel Postgres receipt append did not outperform SQLite: postgres=%s sqlite=%s", postgresDuration, sqliteDuration)
	}
}

func postgresURLWithSearchPath(t *testing.T, rawURL, schema string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		t.Fatalf("HELM_TEST_POSTGRES_URL must be a URL-style Postgres DSN for schema isolation: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func runReceiptAppendCausalLoad(t *testing.T, ctx context.Context, store ReceiptStore, prefix string, sessions, appendsPerSession int) time.Duration {
	t.Helper()
	start := time.Now()
	var wg sync.WaitGroup
	errCh := make(chan error, sessions)
	for sessionIndex := 0; sessionIndex < sessions; sessionIndex++ {
		sessionIndex := sessionIndex
		wg.Add(1)
		go func() {
			defer wg.Done()
			sessionID := fmt.Sprintf("%s-session-%02d", prefix, sessionIndex)
			for appendIndex := 0; appendIndex < appendsPerSession; appendIndex++ {
				appendIndex := appendIndex
				if err := store.AppendCausal(ctx, sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
					return &contracts.Receipt{
						ReceiptID:    fmt.Sprintf("%s-receipt-%02d-%03d", prefix, sessionIndex, appendIndex),
						DecisionID:   fmt.Sprintf("%s-decision-%02d-%03d", prefix, sessionIndex, appendIndex),
						EffectID:     "receipt-throughput",
						Status:       "OK",
						Timestamp:    time.Unix(1700000000+int64(appendIndex), 0).UTC(),
						ExecutorID:   sessionID,
						SessionID:    sessionID,
						PrevHash:     prevHash,
						LamportClock: lamport,
						Signature:    "sig",
					}, nil
				}); err != nil {
					errCh <- fmt.Errorf("%s append %d: %w", sessionID, appendIndex, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	return time.Since(start)
}

func TestSQLiteReceiptRejectsUnmarshalableMetadata(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	err := store.Store(context.Background(), &contracts.Receipt{
		ReceiptID:  "r-bad-meta",
		DecisionID: "d-bad-meta",
		EffectID:   "e",
		Status:     "OK",
		Timestamp:  time.Now(),
		Metadata:   map[string]any{"bad": func() {}},
	})
	if err == nil {
		t.Fatal("expected metadata marshal failure")
	}
}

func TestSQLiteReceiptNotFound(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	_, err := store.GetByReceiptID(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error for missing receipt")
	}
}

func TestSQLiteReceiptGetLastForSessionGenesis(t *testing.T) {
	store, cleanup := newTestSQLiteStore(t)
	defer cleanup()
	got, err := store.GetLastForSession(context.Background(), "no-session")
	if err != nil || got != nil {
		t.Fatalf("expected nil genesis, got err=%v, receipt=%+v", err, got)
	}
}

// --- Airgap Store tests ---

func TestAirgapStorePutGet(t *testing.T) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("airgap-test-%d", time.Now().UnixNano()))
	defer os.RemoveAll(dir)
	s, err := NewAirgapStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s.Put(ctx, "k1", []byte("hello"))
	got, err := s.Get(ctx, "k1")
	if err != nil || string(got) != "hello" {
		t.Fatalf("expected hello, got %s, err=%v", got, err)
	}
}
