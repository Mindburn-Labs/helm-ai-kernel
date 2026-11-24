package budget

import (
	"database/sql"

	_ "github.com/lib/pq"
)

// PostgresStorage preserves the type of the retired Postgres budget store.
type PostgresStorage struct {
	db *sql.DB
}
