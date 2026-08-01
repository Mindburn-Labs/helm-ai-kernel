package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestPostgresReceiptMigrationBackfillsOrRejectsV5DecisionHash(t *testing.T) {
	postgresURL := os.Getenv("HELM_TEST_POSTGRES_URL")
	if postgresURL == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the Postgres receipt migration proof")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	schema := fmt.Sprintf("helm_receipt_v5_migration_%d", time.Now().UnixNano())
	db, err := sql.Open("postgres", postgresURLWithSearchPath(t, postgresURL, schema))
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS `+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	}()

	// This is the historical shape needed by the V5 migration: metadata was
	// already durable, but decision_hash was not yet a dedicated column.
	if _, err := db.ExecContext(ctx, `CREATE TABLE receipts (
		receipt_id TEXT PRIMARY KEY,
		decision_id TEXT NOT NULL,
		execution_intent_id TEXT,
		status TEXT NOT NULL,
		timestamp TIMESTAMPTZ NOT NULL,
		executor_id TEXT NOT NULL DEFAULT '',
		metadata JSONB,
		prev_hash TEXT NOT NULL DEFAULT '',
		lamport_clock BIGINT NOT NULL DEFAULT 0,
		signature_version TEXT NOT NULL DEFAULT '',
		session_id TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		t.Fatalf("create pre-004 receipts table: %v", err)
	}

	timestamp := time.Unix(1700000000, 0).UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO receipts (
		receipt_id, decision_id, execution_intent_id, status, timestamp, executor_id,
		metadata, signature_version, session_id
	) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)`,
		"r-v5-recoverable", "d-v5-recoverable", "effect", "ALLOW", timestamp, "executor",
		`{"decision_hash":"sha256:trusted"}`, contracts.ReceiptSignatureV5, "session-recoverable"); err != nil {
		t.Fatalf("insert recoverable historical receipt: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO receipts (
		receipt_id, decision_id, execution_intent_id, status, timestamp, executor_id,
		signature_version, session_id
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		"r-v5-unrecoverable", "d-v5-unrecoverable", "effect", "ALLOW", timestamp, "executor",
		contracts.ReceiptSignatureV5, "session-unrecoverable"); err != nil {
		t.Fatalf("insert unrecoverable historical receipt: %v", err)
	}

	migration, err := os.ReadFile(filepath.Join("migrations", "004_add_receipt_decision_hash.sql"))
	if err != nil {
		t.Fatalf("read 004 receipt migration: %v", err)
	}
	if _, err := db.ExecContext(ctx, string(migration)); err != nil {
		t.Fatalf("apply 004 receipt migration: %v", err)
	}

	var recoveredHash string
	if err := db.QueryRowContext(ctx, `SELECT decision_hash FROM receipts WHERE receipt_id = $1`, "r-v5-recoverable").Scan(&recoveredHash); err != nil {
		t.Fatalf("read recovered decision hash: %v", err)
	}
	if recoveredHash != "sha256:trusted" {
		t.Fatalf("durable migration decision_hash = %q, want trusted metadata value", recoveredHash)
	}

	store := NewPostgresReceiptStore(db)
	if err := store.Init(ctx); err != nil {
		t.Fatalf("initialize current receipt store after migration: %v", err)
	}
	recovered, err := store.GetByReceiptID(ctx, "r-v5-recoverable")
	if err != nil || recovered.DecisionHash != recoveredHash {
		t.Fatalf("recoverable V5 receipt = %+v err=%v", recovered, err)
	}
	if _, err := store.GetByReceiptID(ctx, "r-v5-unrecoverable"); err == nil || !strings.Contains(err.Error(), "004_add_receipt_decision_hash.sql") {
		t.Fatalf("unrecoverable V5 receipt did not fail closed with migration guidance: %v", err)
	}
}
