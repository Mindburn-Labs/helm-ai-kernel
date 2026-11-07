package budget

import (
	"database/sql"

	_ "github.com/lib/pq"
)

// PostgresStorage implements Storage using PostgreSQL.
type PostgresStorage struct {
	db *sql.DB
}
