package budget

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// PostgresStorage implements Storage using PostgreSQL.
type PostgresStorage struct {
	db *sql.DB
}

func NewPostgresStorage(db *sql.DB) *PostgresStorage {
	return &PostgresStorage{db: db}
}

func (s *PostgresStorage) Get(ctx context.Context, tenantID string) (*Budget, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT tenant_id, daily_limit, monthly_limit, daily_used, monthly_used, last_updated FROM budgets WHERE tenant_id = $1",
		tenantID)

	var b Budget
	err := row.Scan(&b.TenantID, &b.DailyLimit, &b.MonthlyLimit, &b.DailyUsed, &b.MonthlyUsed, &b.LastUpdated)
	if err == sql.ErrNoRows {
		return nil, nil // Not found is valid, enforcer will initialize
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get budget: %w", err)
	}
	return &b, nil
}

func (s *PostgresStorage) Set(ctx context.Context, b *Budget) error {
	// Upsert logic to handle both new and existing budgets
	query := `
		INSERT INTO budgets (tenant_id, daily_limit, monthly_limit, daily_used, monthly_used, last_updated)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id) DO UPDATE SET
			daily_used = EXCLUDED.daily_used,
			monthly_used = EXCLUDED.monthly_used,
			last_updated = EXCLUDED.last_updated
	`
	_, err := s.db.ExecContext(ctx, query, b.TenantID, b.DailyLimit, b.MonthlyLimit, b.DailyUsed, b.MonthlyUsed, b.LastUpdated)
	if err != nil {
		return fmt.Errorf("failed to persist budget: %w", err)
	}
	return nil
}

func (s *PostgresStorage) Limits(ctx context.Context, tenantID string) (int64, int64, error) {
	// For MVP, we fetch limits from the DB row itself if it exists, or fall back to defaults.
	// But `Limits` method in interface implies "What are the allowed limits for this tenant?".
	// If row exists, use those. If not, maybe use a `tenant_configs` table?
	// For now, let's just query the row. If not found, return default hardcoded limits (as MVP).

	row := s.db.QueryRowContext(ctx, "SELECT daily_limit, monthly_limit FROM budgets WHERE tenant_id = $1", tenantID)
	var daily, monthly int64
	err := row.Scan(&daily, &monthly)
	if err == sql.ErrNoRows {
		// New tenant with no record yet -> Default limits
		return 1000, 50000, nil
	}
	if err != nil {
		return 0, 0, err
	}
	return daily, monthly, nil
}

func (s *PostgresStorage) SetLimits(ctx context.Context, tenantID string, daily, monthly int64) error {
	// Upsert just the limits
	query := `
		INSERT INTO budgets (tenant_id, daily_limit, monthly_limit, daily_used, monthly_used, last_updated)
		VALUES ($1, $2, $3, 0, 0, NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			daily_limit = EXCLUDED.daily_limit,
			monthly_limit = EXCLUDED.monthly_limit
	`
	_, err := s.db.ExecContext(ctx, query, tenantID, daily, monthly)
	if err != nil {
		return fmt.Errorf("failed to set limits: %w", err)
	}
	return nil
}
