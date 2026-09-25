package postgresmigration

// HELM-755 / ADR-0004 B-I3 and B-I5 against real Postgres: after the full
// kernel migration every table with a tenant_id column is under forced row
// security with the tenant policy, the tables without one are exactly the
// declared global set, and a restricted role sees and writes only the tenant
// its transaction is bound to.

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

// tablesWithoutTenantID are the kernel tables that hold no per-tenant rows.
// A new table without tenant_id must be added here deliberately.
var tablesWithoutTenantID = []string{
	"boundary_records_index",     // process-wide SurfaceRegistry; its routes serve the configured tenant only
	"boundary_surface_events",    // same
	"boundary_surface_snapshots", // same
	"credential_audit_log",       // operator credentials, keyed by operator
	"credentials",                // same
	"kernel_schema_migrations",
	// Receipts are tenant data bound through causal_session_id, a private
	// tenant-qualified key, not a tenant_id column. Putting them under row
	// security needs that column first (HELM-755 follow-up).
	"receipts",
	"registry_bundles",  // global pack catalog
	"registry_rollouts", // global pack rollout state
}

func postgresTestDB(t *testing.T) (*sql.DB, string, string) {
	t.Helper()
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the tenant row-security proofs")
	}
	schema := fmt.Sprintf("helm_tenant_rls_%d", time.Now().UnixNano())
	admin, err := sql.Open("postgres", base)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) })
	db, err := sql.Open("postgres", withSearchPath(t, base, schema))
	if err != nil {
		t.Fatalf("open schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, base, schema
}

func withSearchPath(t *testing.T, raw, schema string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse postgres url: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func TestKernelTenantTablesHaveForcedRowSecurity(t *testing.T) {
	db, _, _ := postgresTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	unforced, err := TenantTablesWithoutForcedRowSecurity(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if len(unforced) > 0 {
		t.Fatalf("tenant tables without forced row security and the tenant policy: %v", unforced)
	}

	rows, err := db.QueryContext(ctx, `SELECT relation.relname FROM pg_catalog.pg_class AS relation
		JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
		WHERE namespace.nspname = current_schema() AND relation.relkind IN ('r', 'p')
		  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute AS attribute
		      WHERE attribute.attrelid = relation.oid AND attribute.attname = 'tenant_id' AND NOT attribute.attisdropped)
		ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var global []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		global = append(global, table)
	}
	want := append([]string(nil), tablesWithoutTenantID...)
	sort.Strings(want)
	if strings.Join(global, ",") != strings.Join(want, ",") {
		t.Fatalf("tables without tenant_id = %v, want the declared global set %v", global, want)
	}
	var tenantTables int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_catalog.pg_class AS relation
		JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
		JOIN pg_catalog.pg_attribute AS attribute ON attribute.attrelid = relation.oid AND attribute.attname = 'tenant_id'
		WHERE namespace.nspname = current_schema() AND relation.relkind IN ('r', 'p')`).Scan(&tenantTables); err != nil {
		t.Fatal(err)
	}
	if tenantTables < 11 {
		t.Fatalf("only %d tenant tables found: the migration no longer creates the kernel stores", tenantTables)
	}
}

// ADR-0005 §3: the principal_lookup exception holds only for the exact policy
// the migration installs; a widened or write-capable variant is reported, and
// serving refuses a database without it.
func TestPrincipalLookupExceptionIsExact(t *testing.T) {
	db, _, _ := postgresTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	check := func(name string, wantPresent bool, wantFlagged bool) {
		t.Helper()
		present, err := principalLookupPolicyPresent(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		unforced, err := TenantTablesWithoutForcedRowSecurity(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		flagged := strings.Contains(strings.Join(unforced, ","), "principal_bindings")
		if present != wantPresent || flagged != wantFlagged {
			t.Fatalf("%s: lookup policy present=%v (want %v), principal_bindings flagged=%v (want %v)", name, present, wantPresent, flagged, wantFlagged)
		}
	}
	check("as migrated", true, false)
	for _, variant := range []struct{ name, ddl string }{
		{"widened predicate", `CREATE POLICY principal_lookup ON principal_bindings FOR SELECT USING (true OR current_setting('app.current_principal', true) IS NULL)`},
		{"all commands", `CREATE POLICY principal_lookup ON principal_bindings USING (principal_id = current_setting('app.current_principal', true))`},
		// A SELECT policy cannot carry WITH CHECK; an ALL policy with one is the write-capable variant.
		{"with a write check", `CREATE POLICY principal_lookup ON principal_bindings USING (principal_id = current_setting('app.current_principal', true)) WITH CHECK (true)`},
	} {
		if _, err := db.ExecContext(ctx, `DROP POLICY principal_lookup ON principal_bindings`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, variant.ddl); err != nil {
			t.Fatalf("%s: %v", variant.name, err)
		}
		check(variant.name, false, true)
	}
	if _, err := db.ExecContext(ctx, `DROP POLICY principal_lookup ON principal_bindings`); err != nil {
		t.Fatal(err)
	}
	check("policy dropped", false, false)
}

// Negative controls (ADR-0004 B-I9): each way of weakening a tenant table is
// reported, so an empty result above is not what a broken check returns.
func TestTenantRowSecurityCheckDetectsWeakenedTables(t *testing.T) {
	db, _, _ := postgresTestDB(t)
	ctx := context.Background()
	if _, err := db.Exec(`CREATE TABLE probe_rows (tenant_id TEXT NOT NULL, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		name, ddl string
		flagged   bool
	}{
		{name: "no row security", ddl: `SELECT 1`, flagged: true},
		{name: "enabled, not forced", ddl: `ALTER TABLE probe_rows ENABLE ROW LEVEL SECURITY`, flagged: true},
		{name: "forced, no policy", ddl: `ALTER TABLE probe_rows FORCE ROW LEVEL SECURITY`, flagged: true},
		{name: "tenant policy", ddl: `CREATE POLICY tenant_isolation ON probe_rows USING (` + store.TenantRowSecurityPolicy + `) WITH CHECK (` + store.TenantRowSecurityPolicy + `)`, flagged: false},
		{name: "extra permissive policy", ddl: `CREATE POLICY open_read ON probe_rows USING (true)`, flagged: true},
		{name: "permissive policy removed", ddl: `DROP POLICY open_read ON probe_rows`, flagged: false},
		{name: "write check that ignores the tenant", ddl: `CREATE POLICY loose_write ON probe_rows FOR INSERT WITH CHECK (true)`, flagged: true},
		{name: "loose write removed", ddl: `DROP POLICY loose_write ON probe_rows`, flagged: false},
		// The principal_lookup exception is for principal_bindings only.
		{name: "principal lookup on another table", ddl: `CREATE POLICY principal_lookup ON probe_rows FOR SELECT USING (value = current_setting('app.current_principal', true))`, flagged: true},
	} {
		if _, err := db.Exec(step.ddl); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		unforced, err := TenantTablesWithoutForcedRowSecurity(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if flagged := strings.Join(unforced, ",") == "probe_rows"; flagged != step.flagged {
			t.Fatalf("%s: flagged=%v (%v), want %v", step.name, flagged, unforced, step.flagged)
		}
	}
}

// B-I5: a restricted role (no superuser, no BYPASSRLS, not the owner) reads and
// writes only the tenant its transaction is bound to.
func TestTenantRowSecurityIsolatesTenantsForARestrictedRole(t *testing.T) {
	db, base, schema := postgresTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	role := schema + "_runtime"
	for _, statement := range []string{
		`CREATE ROLE ` + role + ` LOGIN PASSWORD 'rls-probe' NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB`,
		`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + role,
		`GRANT SELECT, INSERT, UPDATE ON principal_bindings, registry_installations, obligations TO ` + role,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`REVOKE ALL ON ALL TABLES IN SCHEMA ` + schema + ` FROM ` + role)
		_, _ = db.Exec(`REVOKE ALL ON SCHEMA ` + schema + ` FROM ` + role)
		_, _ = db.Exec(`DROP ROLE IF EXISTS ` + role)
	})
	parsed, err := url.Parse(withSearchPath(t, base, schema))
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(role, "rls-probe")
	runtime, err := sql.Open("postgres", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	bindings, err := store.NewPostgresPrincipalBindingStore(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindings.Upsert(ctx, store.PrincipalBinding{TenantID: "tenant-a", PrincipalID: "principal-a"}); err != nil {
		t.Fatalf("tenant A upsert: %v", err)
	}
	if ok, err := bindings.Exists(ctx, "tenant-a", "principal-a"); err != nil || !ok {
		t.Fatalf("tenant A cannot read its own binding: ok=%v err=%v", ok, err)
	}
	// ADR-0005 §3: the any-tenant lookup is bound to the principal, not a tenant.
	if bound, err := bindings.PrincipalBound(ctx, "principal-a"); err != nil || !bound {
		t.Fatalf("principal lookup for a bound principal: bound=%v err=%v", bound, err)
	}
	if bound, err := bindings.PrincipalBound(ctx, "principal-z"); err != nil || bound {
		t.Fatalf("principal lookup for an unbound principal: bound=%v err=%v", bound, err)
	}
	if ok, err := bindings.Exists(ctx, "tenant-b", "principal-a"); err != nil || ok {
		t.Fatalf("tenant B saw tenant A's binding: ok=%v err=%v", ok, err)
	}

	var visible int
	if err := runtime.QueryRowContext(ctx, `SELECT count(*) FROM principal_bindings`).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	if visible != 0 {
		t.Fatalf("a query with no tenant bound saw %d rows; an unset tenant must match none", visible)
	}
	err = store.WithTenant(ctx, runtime, "tenant-b", func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM principal_bindings`).Scan(&visible); err != nil {
			return err
		}
		if visible != 0 {
			return fmt.Errorf("tenant B saw %d of tenant A's rows", visible)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = store.WithTenant(ctx, runtime, "tenant-b", func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO registry_installations (tenant_id, pack_id, installed_at) VALUES ('tenant-a', 'pack', now())`)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("tenant B wrote a row into tenant A: err=%v", err)
	}
	_, err = runtime.ExecContext(ctx, `INSERT INTO obligations (id, state) VALUES ('obligation-without-tenant', 'PENDING')`)
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("an obligation without a tenant was written: err=%v", err)
	}
}

// HELM-750 s2a: the authority rows are tenant tables under the same catalog
// check ValidateRuntime runs. After the migration (twice: it is idempotent)
// each one exists with tenant_id and forced tenant row security, and weakening
// any one of them is reported by name.
func TestAuthorityRowTablesAreCoveredByTheTenantCatalogCheck(t *testing.T) {
	db, base, schema := postgresTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for run := 0; run < 2; run++ {
		if err := Migrate(ctx, db); err != nil {
			t.Fatalf("migrate (run %d): %v", run+1, err)
		}
	}
	for _, table := range AuthorityRowTables {
		var forced bool
		err := db.QueryRowContext(ctx, `SELECT relation.relrowsecurity AND relation.relforcerowsecurity
			FROM pg_catalog.pg_class AS relation
			JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
			JOIN pg_catalog.pg_attribute AS attribute ON attribute.attrelid = relation.oid AND attribute.attname = 'tenant_id'
			WHERE namespace.nspname = current_schema() AND relation.relname = $1`, table).Scan(&forced)
		if err != nil {
			t.Fatalf("%s: not a tenant table in the kernel schema: %v", table, err)
		}
		if !forced {
			t.Fatalf("%s: row security is not forced", table)
		}
	}
	if unforced, err := TenantTablesWithoutForcedRowSecurity(ctx, db); err != nil || len(unforced) > 0 {
		t.Fatalf("after migration: unforced=%v err=%v", unforced, err)
	}
	for _, table := range AuthorityRowTables {
		for _, weaken := range []struct{ ddl, restore string }{
			{`ALTER TABLE ` + table + ` NO FORCE ROW LEVEL SECURITY`, `ALTER TABLE ` + table + ` FORCE ROW LEVEL SECURITY`},
			{`CREATE POLICY open_read ON ` + table + ` USING (true)`, `DROP POLICY open_read ON ` + table},
		} {
			if _, err := db.ExecContext(ctx, weaken.ddl); err != nil {
				t.Fatalf("%s: %v", weaken.ddl, err)
			}
			unforced, err := TenantTablesWithoutForcedRowSecurity(ctx, db)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(unforced, ",") != table {
				t.Fatalf("%s: the catalog check reported %v, want exactly %s", weaken.ddl, unforced, table)
			}
			if _, err := db.ExecContext(ctx, weaken.restore); err != nil {
				t.Fatalf("%s: %v", weaken.restore, err)
			}
		}
	}

	// ValidateRuntime, under a restricted serving role, starts on the
	// migrated schema and refuses once an authority table loses FORCE.
	role := schema + "_serving"
	for _, statement := range []string{
		`CREATE ROLE ` + role + ` LOGIN PASSWORD 'rls-probe' NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB`,
		`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + role,
		`GRANT SELECT ON ALL TABLES IN SCHEMA ` + schema + ` TO ` + role,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`REVOKE ALL ON ALL TABLES IN SCHEMA ` + schema + ` FROM ` + role)
		_, _ = db.Exec(`REVOKE ALL ON SCHEMA ` + schema + ` FROM ` + role)
		_, _ = db.Exec(`DROP ROLE IF EXISTS ` + role)
	})
	parsed, err := url.Parse(withSearchPath(t, base, schema))
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(role, "rls-probe")
	serving, err := sql.Open("postgres", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer serving.Close()
	if err := ValidateRuntime(ctx, serving, RuntimeOptions{}); err != nil {
		t.Fatalf("ValidateRuntime refused the migrated schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE authority_mandates NO FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRuntime(ctx, serving, RuntimeOptions{}); err == nil || !strings.Contains(err.Error(), "authority_mandates") {
		t.Fatalf("ValidateRuntime started with authority_mandates unforced: %v", err)
	}
}
