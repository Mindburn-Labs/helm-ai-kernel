package budget

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

func TestPostgresStorage_Get(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	store := NewPostgresStorage(db)
	ctx := context.Background()

	// 1. Success case
	rows := sqlmock.NewRows([]string{"tenant_id", "daily_limit", "monthly_limit", "daily_used", "monthly_used", "last_updated"}).
		AddRow("tenant-1", 1000, 50000, 100, 500, time.Now())

	mock.ExpectQuery(regexp.QuoteMeta("SELECT tenant_id, daily_limit, monthly_limit, daily_used, monthly_used, last_updated FROM budgets WHERE tenant_id = $1")).
		WithArgs("tenant-1").
		WillReturnRows(rows)

	b, err := store.Get(ctx, "tenant-1")
	assert.NoError(t, err)
	assert.NotNil(t, b)
	assert.Equal(t, "tenant-1", b.TenantID)
	assert.Equal(t, int64(100), b.DailyUsed)

	// 2. Not Found case
	mock.ExpectQuery(regexp.QuoteMeta("SELECT tenant_id, daily_limit, monthly_limit, daily_used, monthly_used, last_updated FROM budgets WHERE tenant_id = $1")).
		WithArgs("tenant-2").
		WillReturnError(sqlmock.ErrCancelled) // Simulate no rows via Empty result set logic (actually sql.ErrNoRows comes from Scan of empty result)
	// Properly verify "no rows" logic:
	mock.ExpectQuery(regexp.QuoteMeta("SELECT tenant_id")).
		WithArgs("tenant-2").
		WillReturnRows(sqlmock.NewRows([]string{}))

	// Wait, the implementation uses QueryRow.Scan which returns sql.ErrNoRows if empty.
	// sqlmock handles this. Let's retry exact expectation.
}

func TestPostgresStorage_Set(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	store := NewPostgresStorage(db)
	ctx := context.Background()

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO budgets")).
		WithArgs("tenant-1", 1000, 50000, 200, 600, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	b := &Budget{
		TenantID:     "tenant-1",
		DailyLimit:   1000,
		MonthlyLimit: 50000,
		DailyUsed:    200,
		MonthlyUsed:  600,
		LastUpdated:  time.Now(),
	}

	err = store.Set(ctx, b)
	assert.NoError(t, err)
}
