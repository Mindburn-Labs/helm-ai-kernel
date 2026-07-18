package store

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

func TestPrincipalBindingStoreSQLite(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := NewSQLitePrincipalBindingStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	ok, err := s.Exists(ctx, "acme", "acme-admin")
	require.NoError(t, err)
	require.False(t, ok)

	require.NoError(t, s.Upsert(ctx, PrincipalBinding{TenantID: "acme", PrincipalID: "acme-admin"}))
	ok, err = s.Exists(ctx, "acme", "acme-admin")
	require.NoError(t, err)
	require.True(t, ok)

	// idempotent
	require.NoError(t, s.Upsert(ctx, PrincipalBinding{TenantID: "acme", PrincipalID: "acme-admin"}))

	// distinct pair not matched
	ok, err = s.Exists(ctx, "acme", "someone-else")
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = s.Exists(ctx, "other", "acme-admin")
	require.NoError(t, err)
	require.False(t, ok)
}
