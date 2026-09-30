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

	result, err := s.Bind(ctx, PrincipalBinding{TenantID: "acme", PrincipalID: "acme-admin"}, false)
	require.NoError(t, err)
	require.Equal(t, BindResult{Outcome: BindCreated}, result)
	ok, err = s.Exists(ctx, "acme", "acme-admin")
	require.NoError(t, err)
	require.True(t, ok)

	// idempotent
	result, err = s.Bind(ctx, PrincipalBinding{TenantID: "acme", PrincipalID: "acme-admin"}, false)
	require.NoError(t, err)
	require.Equal(t, BindResult{Outcome: BindExisting}, result)

	// distinct pair not matched
	ok, err = s.Exists(ctx, "acme", "someone-else")
	require.NoError(t, err)
	require.False(t, ok)
	ok, err = s.Exists(ctx, "other", "acme-admin")
	require.NoError(t, err)
	require.False(t, ok)
}

// ADR-0005 §11: a principal bound in one tenant is not bound in another unless
// cross-tenant bindings are allowed for it.
func TestPrincipalBindingStoreSQLiteRefusesCrossTenantBind(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	s, err := NewSQLitePrincipalBindingStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	_, err = s.Bind(ctx, PrincipalBinding{TenantID: "tenant-a", PrincipalID: "member"}, false)
	require.NoError(t, err)
	result, err := s.Bind(ctx, PrincipalBinding{TenantID: "tenant-b", PrincipalID: "member"}, false)
	require.NoError(t, err)
	require.Equal(t, BindResult{Outcome: BindRefusedCrossTenant, OtherTenants: []string{"tenant-a"}}, result)
	ok, err := s.Exists(ctx, "tenant-b", "member")
	require.NoError(t, err)
	require.False(t, ok, "a refused bind must not insert")

	result, err = s.Bind(ctx, PrincipalBinding{TenantID: "tenant-b", PrincipalID: "member"}, true)
	require.NoError(t, err)
	require.Equal(t, BindResult{Outcome: BindCreated, OtherTenants: []string{"tenant-a"}}, result)
	result, err = s.Bind(ctx, PrincipalBinding{TenantID: "tenant-a", PrincipalID: "member"}, false)
	require.NoError(t, err)
	require.Equal(t, BindResult{Outcome: BindExisting, OtherTenants: []string{"tenant-b"}}, result)
}
