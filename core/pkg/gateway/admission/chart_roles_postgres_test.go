package admission

// HELM-789 against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): the chart's database bootstrap
// (deploy/helm-chart/files/gateway-db) run the way the migrate hook runs it.
// 001_roles.sql as an administrator, Migrate as the owner role through a
// startup `role` option, 002_grants.sql as the owner, each SQL file twice.
// The runtime role then serves admission with exactly the ADR-0004 attributes
// and grants, and cannot act as the owner.

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

// chartSQL reads one of the chart's gateway database files.
func chartSQL(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "helm-chart", "files", "gateway-db", name))
	must(t, err)
	return string(body)
}

// dsnWith returns raw with the user replaced (when user is set) and the
// given query parameters added.
func dsnWith(t *testing.T, raw, user, password string, params map[string]string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	must(t, err)
	if user != "" {
		parsed.User = url.UserPassword(user, password)
	}
	query := parsed.Query()
	for k, v := range params {
		query.Set(k, v)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// runBootstrapFile runs one chart SQL file in one transaction, after the
// session settings the hook sets.
func runBootstrapFile(t *testing.T, dsn, owner, runtime, schema, file string) {
	t.Helper()
	if err := tryBootstrapFile(t, dsn, owner, runtime, schema, file); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
}

func tryBootstrapFile(t *testing.T, dsn, owner, runtime, schema, file string) error {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	must(t, err)
	defer func() { _ = db.Close() }()
	tx, err := db.Begin()
	must(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('helm_gateway_bootstrap.owner_role', $1, true),
		set_config('helm_gateway_bootstrap.runtime_role', $2, true),
		set_config('helm_gateway_bootstrap.schema', $3, true)`, owner, runtime, schema)
	must(t, err)
	if _, err := tx.Exec(chartSQL(t, file)); err != nil {
		return err
	}
	return tx.Commit()
}

func TestPostgresChartBootstrapGivesTheRuntimeRoleOnlyItsGrants(t *testing.T) {
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the chart database bootstrap proof")
	}
	for _, admin := range []string{"superuser", "createrole"} {
		t.Run(admin, func(t *testing.T) { chartBootstrapProof(t, base, admin) })
	}
}

func chartBootstrapProof(t *testing.T, base, adminKind string) {
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	owner, runtime, schema := "helm_owner_"+suffix, "helm_gateway_"+suffix, "helm_gateway_"+suffix
	superDB, err := sql.Open("postgres", base)
	must(t, err)
	t.Cleanup(func() { _ = superDB.Close() })
	var database string
	must(t, superDB.QueryRow(`SELECT current_database()`).Scan(&database))

	adminDSN := base
	adminRole := ""
	if adminKind == "createrole" {
		// A managed database's administrator: CREATEROLE and CREATE on the
		// database, no superuser.
		adminRole = "helm_admin_" + suffix
		for _, statement := range []string{
			`CREATE ROLE ` + adminRole + ` LOGIN PASSWORD 'bootstrap-probe' CREATEROLE`,
			`GRANT CREATE ON DATABASE "` + database + `" TO ` + adminRole,
		} {
			_, err := superDB.Exec(statement)
			must(t, err)
		}
		adminDSN = dsnWith(t, base, adminRole, "bootstrap-probe", nil)
	}
	t.Cleanup(func() {
		_, _ = superDB.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`)
		for _, role := range []string{runtime, owner, adminRole} {
			if role != "" {
				_, _ = superDB.Exec(`DROP OWNED BY ` + role)
				_, _ = superDB.Exec(`DROP ROLE IF EXISTS ` + role)
			}
		}
	})

	// The hook's order, each SQL file twice: a re-run must converge, not fail.
	ownerDSN := dsnWith(t, adminDSN, "", "", map[string]string{"options": "-c role=" + owner + " -c search_path=" + schema})
	for range 2 {
		runBootstrapFile(t, adminDSN, owner, runtime, schema, "001_roles.sql")
	}
	ownerDB, err := sql.Open("postgres", ownerDSN)
	must(t, err)
	t.Cleanup(func() { _ = ownerDB.Close() })
	ctx := context.Background()
	must(t, Migrate(ctx, ownerDB))
	for range 2 {
		runBootstrapFile(t, ownerDSN, owner, runtime, schema, "002_grants.sql")
	}

	// A drifted attribute is converged back by the next run.
	_, err = superDB.Exec(`ALTER ROLE ` + runtime + ` CREATEROLE`)
	must(t, err)
	runBootstrapFile(t, adminDSN, owner, runtime, schema, "001_roles.sql")
	if adminKind == "createrole" {
		// A drift the administrator may not undo fails the run: the hook
		// stops before migrate rather than serve with an escalated role.
		_, err = superDB.Exec(`ALTER ROLE ` + runtime + ` BYPASSRLS`)
		must(t, err)
		if err := tryBootstrapFile(t, adminDSN, owner, runtime, schema, "001_roles.sql"); err == nil {
			t.Fatal("001_roles.sql converged BYPASSRLS without the privilege to")
		}
		_, err = superDB.Exec(`ALTER ROLE ` + runtime + ` NOBYPASSRLS`)
		must(t, err)
	}

	// Role attributes (ADR-0004 §1): nothing escalates; the owner cannot log in.
	for role, login := range map[string]bool{owner: false, runtime: true} {
		var super, bypass, createRole, createDB, replication, canLogin bool
		must(t, superDB.QueryRow(`SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolcanlogin
			FROM pg_roles WHERE rolname = $1`, role).Scan(&super, &bypass, &createRole, &createDB, &replication, &canLogin))
		if super || bypass || createRole || createDB || replication || canLogin != login {
			t.Fatalf("%s: super=%v bypassrls=%v createrole=%v createdb=%v replication=%v login=%v, want none and login=%v",
				role, super, bypass, createRole, createDB, replication, canLogin, login)
		}
	}
	var runtimeIsOwner bool
	must(t, superDB.QueryRow(`SELECT pg_has_role($1, $2, 'MEMBER')`, runtime, owner).Scan(&runtimeIsOwner))
	if runtimeIsOwner {
		t.Fatal("the runtime role is a member of the owner role")
	}

	// The owner owns the schema and every table in it.
	var foreign int
	must(t, superDB.QueryRow(`SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND pg_get_userbyid(c.relowner) <> $2`, schema, owner).Scan(&foreign))
	var schemaOwner string
	must(t, superDB.QueryRow(`SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = $1`, schema).Scan(&schemaOwner))
	if foreign != 0 || schemaOwner != owner {
		t.Fatalf("schema owner %s and %d objects not owned by %s", schemaOwner, foreign, owner)
	}

	// Exactly the grants the admission proofs run under, table by table, and
	// every table Migrate creates has one.
	want := map[string]string{"gateway_schema_migrations": "SELECT"}
	for _, table := range append(append([]string{}, mandates.Tables...), Tables...) {
		want[table] = "INSERT,SELECT,UPDATE"
	}
	want["authority_postings"] = "INSERT,SELECT"
	if _, ok := want["authority_token_replay"]; ok {
		want["authority_token_replay"] = "DELETE,INSERT,SELECT,UPDATE"
	}
	rows, err := superDB.Query(`SELECT c.relname, COALESCE((
			SELECT string_agg(p, ',' ORDER BY p) FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) p
			WHERE has_table_privilege($2, c.oid, p)), '')
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relkind IN ('r', 'p')`, schema, runtime)
	must(t, err)
	got := map[string]string{}
	for rows.Next() {
		var table, privileges string
		must(t, rows.Scan(&table, &privileges))
		got[table] = privileges
	}
	must(t, rows.Err())
	_ = rows.Close()
	if len(got) != len(want) {
		t.Fatalf("runtime privileges cover %d tables, want %d: %v", len(got), len(want), got)
	}
	for table, privileges := range want {
		if got[table] != privileges {
			t.Fatalf("%s: runtime role holds %q, want %q", table, got[table], privileges)
		}
	}

	// The runtime role, with no search_path in its DSN, serves admission.
	_, err = superDB.Exec(`ALTER ROLE ` + runtime + ` PASSWORD 'gateway-probe'`)
	must(t, err)
	runtimeDB, err := sql.Open("postgres", dsnWith(t, base, runtime, "gateway-probe", nil))
	must(t, err)
	t.Cleanup(func() { _ = runtimeDB.Close() })
	version, err := SchemaVersion(ctx, runtimeDB)
	must(t, err)
	if version != HeadVersion() {
		t.Fatalf("runtime role reads schema version %d, want %d", version, HeadVersion())
	}
	svc, err := New(runtimeDB, Config{})
	must(t, err)
	authority, err := authorityrows.New(ownerDB)
	must(t, err)
	f := &fixture{t: t, owner: ownerDB, runtime: runtimeDB, svc: svc, rows: authority}
	must(t, ownerDB.QueryRow(`SELECT now()`).Scan(&f.now))
	must(t, authority.CreateTenant(ctx, tenantA))
	for _, p := range []string{"human-a", "human-b"} {
		must(t, authority.CreatePrincipal(ctx, tenantA, p, authorityrows.PrincipalHuman))
	}
	must(t, authority.CreatePrincipal(ctx, tenantA, "agent-a", authorityrows.PrincipalAgent))
	for effectType, risk := range map[string]authorityrows.RiskClass{
		effectargs.GitHubBranchCreateFromChanges: authorityrows.RiskMedium,
		effectargs.GitHubPullRequestCreateDraft:  authorityrows.RiskMedium,
		effectargs.GitHubRepositoryGet:           authorityrows.RiskLow,
		noteType:                                 authorityrows.RiskLow,
	} {
		must(t, authority.CreateEffectType(ctx, tenantA, effectType, risk))
	}
	f.rootMandate(tenantA, "human-a", skeletonTerms(f.now))
	if a := f.propose(human, note("chart-bootstrap")); a.State != "ADMITTED" {
		t.Fatalf("a note proposed as the runtime role is %s %q, want ADMITTED", a.State, a.ReasonCode)
	}

	// And it cannot do what only the owner may.
	for _, statement := range []string{
		`ALTER TABLE authority_effect_attempts NO FORCE ROW LEVEL SECURITY`,
		`DELETE FROM authority_postings`,
		`UPDATE authority_postings SET amount = 0`,
		`DELETE FROM authority_effect_attempts`,
		`TRUNCATE authority_postings`,
		`CREATE TABLE authority_extra (tenant_id TEXT)`,
		`SET ROLE ` + owner,
	} {
		if _, err := runtimeDB.Exec(statement); err == nil || !strings.Contains(err.Error(), "denied") && !strings.Contains(err.Error(), "must be owner") {
			t.Fatalf("runtime role %q: err = %v, want a permission error", statement, err)
		}
	}
}
