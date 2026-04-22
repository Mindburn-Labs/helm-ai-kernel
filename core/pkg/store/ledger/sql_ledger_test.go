package ledger

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSQLLedger_Create(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer func() { _ = db.Close() }()

	ledger := NewSQLLedger(db)
	ctx := context.Background()
	now := time.Now()

	obl := Obligation{
		ID:        "obl-1",
		Intent:    "Test",
		State:     StatePending,
		CreatedAt: now,
		UpdatedAt: now,
	}

	mock.ExpectExec("INSERT INTO obligations").
		WithArgs(obl.ID, obl.IdempotencyKey, obl.Intent, obl.State, obl.CreatedAt, obl.UpdatedAt).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := ledger.Create(ctx, obl); err != nil {
		t.Errorf("error was not expected while creating stats: %s", err)
	}
}
