package ledger

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcquireNextPending_Concurrency(t *testing.T) {
	// Note: sqlmock is single-threaded in expectations, so simulating TRUE concurrency
	// against a mock is tricky (it expects sequential order).
	// However, we can verify the SQL SYNTAX generated includes "FOR UPDATE SKIP LOCKED".

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	ledger := NewPostgresLedger(db)
	ctx := context.Background()

	// Expectation: The query MUST contain "SKIP LOCKED"
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM obligations .* FOR UPDATE SKIP LOCKED`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("task-1"))

	mock.ExpectExec("UPDATE obligations").
		WithArgs("worker-1", sqlmock.AnyArg(), sqlmock.AnyArg(), "task-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit()

	// Get Validation - PostgresLedger.Get expects 9 columns
	mock.ExpectQuery("SELECT .* FROM obligations").
		WithArgs("task-1").
		WillReturnRows(sqlmock.NewRows([]string{"id", "idempotency_key", "intent", "state", "created_at", "updated_at", "hash", "previous_hash", "metadata", "tenant_id"}).
			AddRow("task-1", "key-1", "{}", "PENDING", time.Now(), time.Now(), "abc123", "000000", "", "tenant-default"))

	_, err = ledger.AcquireNextPending(ctx, "worker-1", 10*time.Minute)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAcquireNextPending_NoRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	ledger := NewPostgresLedger(db)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id FROM obligations`).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, err = ledger.AcquireNextPending(context.Background(), "worker-1", time.Minute)
	assert.Error(t, err)
	assert.Equal(t, "no pending obligations", err.Error())
}
