package admission

// HELM-789 against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): the chart's database bootstrap
// (deploy/helm-chart/files/gateway-db), extracted from the rendered migrate
// Job after kubelet env expansion, run the way the migrate hook runs it,
// in a gateway database of its own on a shared instance. 001_roles.sql as an
// administrator, Migrate as the owner role through a startup `role` option,
// 002_grants.sql as the owner, each SQL file twice. The runtime role then
// serves admission with exactly the ADR-0004 attributes and grants, cannot
// act as the owner, and is the only role besides the administrator that can
// connect to the gateway database. Its password is set as a client-side
// SCRAM-SHA-256 verifier and never appears in the server's statement log.
//
// quantum_posture: computes a classical SCRAM-SHA-256 verifier; no
// post-quantum claim.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/pgscram"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

// dsnFor returns raw pointed at database (when set), with the user replaced
// (when set) and the given query parameters added.
func dsnFor(t *testing.T, raw, database, user, password string, params map[string]string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	must(t, err)
	if database != "" {
		parsed.Path = "/" + database
	}
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

// bootstrapRun is one invocation of a chart SQL file with the session
// settings the hook sets.
type bootstrapRun struct {
	owner, runtime, schema, verifier string
	sql                              map[string]string
}

func (b bootstrapRun) try(t *testing.T, dsn, file string) error {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	must(t, err)
	defer func() { _ = db.Close() }()
	tx, err := db.Begin()
	must(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('helm_gateway_bootstrap.owner_role', $1, true),
		set_config('helm_gateway_bootstrap.runtime_role', $2, true),
		set_config('helm_gateway_bootstrap.schema', $3, true),
		set_config('helm_gateway_bootstrap.runtime_verifier', $4, true)`, b.owner, b.runtime, b.schema, b.verifier)
	must(t, err)
	if b.sql[file] == "" {
		t.Fatalf("no rendered bootstrap SQL for %s", file)
	}
	if _, err := tx.Exec(b.sql[file]); err != nil {
		return err
	}
	return tx.Commit()
}

func (b bootstrapRun) run(t *testing.T, dsn, file string) {
	t.Helper()
	if err := b.try(t, dsn, file); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
}

// serverLog returns the PostgreSQL server log: the file named by
// HELM_TEST_POSTGRES_LOG (scripts/ci/postgres_proofs_gate.sh sets it for its
// disposable cluster), else the logging collector's current file.
func serverLog(t *testing.T, super *sql.DB) string {
	t.Helper()
	if path := os.Getenv("HELM_TEST_POSTGRES_LOG"); path != "" {
		body, err := os.ReadFile(path) // #nosec G304 -- test-provided server log path
		must(t, err)
		return string(body)
	}
	var body string
	if err := super.QueryRow(`SELECT pg_read_file(pg_current_logfile())`).Scan(&body); err != nil || body == "" {
		t.Fatalf("cannot read the server log (err %v): set HELM_TEST_POSTGRES_LOG to the log file of the server in HELM_TEST_POSTGRES_URL", err)
	}
	return body
}

func randomToken(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 16)
	_, err := rand.Read(b)
	must(t, err)
	return prefix + hex.EncodeToString(b)
}

func TestPostgresChartBootstrapGivesTheRuntimeRoleOnlyItsGrants(t *testing.T) {
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the chart database bootstrap proof")
	}
	sql := renderedBootstrapSQL(t, gatewayChartPath(t), false)
	for _, admin := range []string{"superuser", "createrole"} {
		t.Run(admin, func(t *testing.T) { chartBootstrapProof(t, base, admin, sql) })
	}
}

func chartBootstrapProof(t *testing.T, base, adminKind string, sqlFiles map[string]string) {
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	owner, runtime, schema := "helm_owner_"+suffix, "helm_gateway_"+suffix, "helm_gateway_"+suffix
	gatewayDB, controlPlane := "helm_gw_"+suffix, "helm_cp_"+suffix
	superDB, err := sql.Open("postgres", base)
	must(t, err)
	t.Cleanup(func() { _ = superDB.Close() })

	// A managed database's administrator has CREATEROLE and owns the
	// gateway database, without superuser.
	adminRole, databaseOwner := "", ""
	if adminKind == "createrole" {
		adminRole = "helm_admin_" + suffix
		databaseOwner = " OWNER " + adminRole
		_, err := superDB.Exec(`CREATE ROLE ` + adminRole + ` LOGIN PASSWORD 'bootstrap-probe' CREATEROLE`)
		must(t, err)
	}
	t.Cleanup(func() {
		for _, role := range []string{controlPlane, runtime, owner, adminRole} {
			if role != "" {
				_, _ = superDB.Exec(`DROP OWNED BY ` + role)
				_, _ = superDB.Exec(`DROP ROLE IF EXISTS ` + role)
			}
		}
	})
	// The gateway's own database on the shared instance, with every
	// statement logged.
	for _, statement := range []string{
		`CREATE DATABASE ` + gatewayDB + databaseOwner,
		`ALTER DATABASE ` + gatewayDB + ` SET log_statement = 'all'`,
		`CREATE ROLE ` + controlPlane + ` LOGIN PASSWORD 'control-plane-probe'`,
	} {
		_, err := superDB.Exec(statement)
		must(t, err)
	}
	t.Cleanup(func() { _, _ = superDB.Exec(`DROP DATABASE IF EXISTS ` + gatewayDB + ` WITH (FORCE)`) })
	superGW, err := sql.Open("postgres", dsnFor(t, base, gatewayDB, "", "", nil))
	must(t, err)
	t.Cleanup(func() { _ = superGW.Close() })

	adminDSN := dsnFor(t, base, gatewayDB, "", "", nil)
	if adminRole != "" {
		adminDSN = dsnFor(t, base, gatewayDB, adminRole, "bootstrap-probe", nil)
	}
	ownerDSN := dsnFor(t, adminDSN, "", "", "", map[string]string{"options": "-c role=" + owner + " -c search_path=" + schema})

	// The runtime password as the hook sets it: a verifier computed here.
	password := randomToken(t, "pw-")
	verifier, err := pgscram.New(password)
	must(t, err)
	run := bootstrapRun{owner: owner, runtime: runtime, schema: schema, verifier: verifier, sql: sqlFiles}

	// The hook's order, each SQL file twice: a re-run must converge, not fail.
	for range 2 {
		run.run(t, adminDSN, "001_roles.sql")
	}
	ownerDB, err := sql.Open("postgres", ownerDSN)
	must(t, err)
	t.Cleanup(func() { _ = ownerDB.Close() })
	ctx := context.Background()
	must(t, Migrate(ctx, ownerDB))
	for range 2 {
		run.run(t, ownerDSN, "002_grants.sql")
	}

	// The password never reaches the server log, where a plaintext
	// ALTER ROLE ... PASSWORD visibly lands (the positive control), and the
	// server stores the verifier as sent: it accepted it as a verifier and
	// did not hash it again.
	canary := randomToken(t, "canary-")
	_, err = superGW.Exec(`ALTER ROLE ` + runtime + ` PASSWORD '` + canary + `'`)
	must(t, err)
	if !strings.Contains(serverLog(t, superDB), canary) {
		t.Fatal("positive control: a plaintext ALTER ROLE ... PASSWORD did not reach the server log, so its absence proves nothing")
	}
	run.run(t, adminDSN, "001_roles.sql")
	if strings.Contains(serverLog(t, superDB), password) {
		t.Fatal("the runtime role's plaintext password is in the server log")
	}
	var stored string
	must(t, superDB.QueryRow(`SELECT rolpassword FROM pg_authid WHERE rolname = $1`, runtime).Scan(&stored))
	if stored != verifier {
		t.Fatalf("the runtime role's stored password is not the verifier the bootstrap sent")
	}
	plaintext := run
	plaintext.verifier = randomToken(t, "not-a-verifier-")
	if err := plaintext.try(t, adminDSN, "001_roles.sql"); err == nil || !strings.Contains(err.Error(), "never a plaintext password") {
		t.Fatalf("001_roles.sql accepted a plaintext runtime password: %v", err)
	}

	// A drifted attribute is converged back by the next run.
	_, err = superDB.Exec(`ALTER ROLE ` + runtime + ` CREATEROLE`)
	must(t, err)
	run.run(t, adminDSN, "001_roles.sql")
	if adminKind == "createrole" {
		// A drift the administrator may not undo fails the run: the hook
		// stops before migrate rather than serve with an escalated role.
		_, err = superDB.Exec(`ALTER ROLE ` + runtime + ` BYPASSRLS`)
		must(t, err)
		if err := run.try(t, adminDSN, "001_roles.sql"); err == nil {
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
	must(t, superGW.QueryRow(`SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND pg_get_userbyid(c.relowner) <> $2`, schema, owner).Scan(&foreign))
	var schemaOwner string
	must(t, superGW.QueryRow(`SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = $1`, schema).Scan(&schemaOwner))
	if foreign != 0 || schemaOwner != owner {
		t.Fatalf("schema owner %s and %d objects not owned by %s", schemaOwner, foreign, owner)
	}

	// River's tables (HELM-751 s3b), as its migration creates them: the rules
	// apply to the tables that exist. Stand-ins with River's names and
	// bigserial ids are enough to prove the rules; the job proofs prove the
	// privileges suffice for River itself.
	for _, table := range []string{"river_job", "river_leader", "river_queue", "river_notification", "river_migration"} {
		_, err := ownerDB.Exec(`CREATE TABLE ` + table + ` (id BIGSERIAL PRIMARY KEY)`)
		must(t, err)
	}
	// The grants never guess: a table or sequence without a rule fails the
	// run, River's included.
	for statement, message := range map[string]string{
		`CREATE TABLE river_extra (id BIGINT)`:      "table " + schema + ".river_extra has no helm_gateway grant rule",
		`CREATE TABLE unplanned_things (id BIGINT)`: "table " + schema + ".unplanned_things has no helm_gateway grant rule",
		`CREATE SEQUENCE unplanned_counter`:         "sequence " + schema + ".unplanned_counter has no helm_gateway grant rule",
	} {
		_, err := ownerDB.Exec(statement)
		must(t, err)
		if err := run.try(t, ownerDSN, "002_grants.sql"); err == nil || !strings.Contains(err.Error(), message) {
			t.Fatalf("002_grants.sql after %q: err = %v, want %q", statement, err, message)
		}
		object := strings.Fields(statement)[1] + " " + strings.Fields(statement)[2]
		_, err = ownerDB.Exec(`DROP ` + object)
		must(t, err)
	}
	run.run(t, ownerDSN, "002_grants.sql")

	// Exactly the grants the admission proofs run under, table by table, and
	// every table Migrate creates has one.
	want := map[string]string{"gateway_schema_migrations": "SELECT"}
	for _, table := range append(append([]string{}, mandates.Tables...), Tables...) {
		want[table] = "INSERT,SELECT,UPDATE"
	}
	want["authority_postings"] = "INSERT,SELECT"
	want["authority_provision_limits"] = "INSERT,SELECT"
	want["authority_distinct_values"] = "INSERT,SELECT"
	if _, ok := want["authority_token_replay"]; ok {
		want["authority_token_replay"] = "DELETE,INSERT,SELECT"
	}
	for _, table := range []string{"river_job", "river_leader", "river_queue", "river_notification"} {
		want[table] = "DELETE,INSERT,SELECT,UPDATE"
	}
	want["river_migration"] = "SELECT"
	rows, err := superGW.Query(`SELECT c.relname, COALESCE((
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
	// Sequences: USAGE on River's bigserial sequences only; the identity
	// sequences behind authority_postings and authority_observations need
	// none.
	seqRows, err := superGW.Query(`SELECT c.relname, has_sequence_privilege($2, c.oid, 'USAGE'),
			has_sequence_privilege($2, c.oid, 'SELECT') OR has_sequence_privilege($2, c.oid, 'UPDATE')
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relkind = 'S' ORDER BY 1`, schema, runtime)
	must(t, err)
	riverSequences := 0
	for seqRows.Next() {
		var name string
		var usage, more bool
		must(t, seqRows.Scan(&name, &usage, &more))
		river := strings.HasPrefix(name, "river_")
		if usage != river || more {
			t.Fatalf("sequence %s: runtime USAGE=%v, SELECT or UPDATE=%v; want USAGE only on river_* sequences", name, usage, more)
		}
		if river {
			riverSequences++
		}
	}
	must(t, seqRows.Err())
	_ = seqRows.Close()
	if riverSequences != 5 {
		t.Fatalf("%d river_* sequences, want 5", riverSequences)
	}

	// Database isolation: a Control Plane role on the same instance cannot
	// connect to the gateway database; the runtime role can, and cannot
	// create temporary tables there.
	cpDB, err := sql.Open("postgres", dsnFor(t, base, gatewayDB, controlPlane, "control-plane-probe", nil))
	must(t, err)
	err = cpDB.Ping()
	_ = cpDB.Close()
	if err == nil || !strings.Contains(err.Error(), "permission denied for database") {
		t.Fatalf("the Control Plane role connecting to the gateway database: err = %v, want permission denied", err)
	}

	// The runtime role, with no search_path in its DSN, serves admission.
	runtimeDB, err := sql.Open("postgres", dsnFor(t, base, gatewayDB, runtime, password, nil))
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
	mandate := f.rootMandate(tenantA, "human-a", skeletonTerms(f.now))
	// A distinct-value limit, so admission writes authority_distinct_values,
	// the second time through its ON CONFLICT DO NOTHING path: SELECT and
	// INSERT are enough there.
	_, err = authority.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &mandate.ID, Unit: "repos", Measure: "distinct", Window: "day", Value: 1, Span: 1})
	must(t, err)
	repo := DistinctValue{Unit: "repos", Digest: make([]byte, 32)}
	for _, key := range []string{"chart-bootstrap-1", "chart-bootstrap-2"} {
		in := note(key)
		in.Distinct = []DistinctValue{repo}
		if a := f.propose(human, in); a.State != "ADMITTED" {
			t.Fatalf("a note proposed as the runtime role is %s %q, want ADMITTED", a.State, a.ReasonCode)
		}
	}
	var distinctRows int
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM authority_distinct_values`).Scan(&distinctRows)
	})
	if distinctRows != 1 {
		t.Fatalf("%d distinct-value rows, want 1", distinctRows)
	}

	// And it cannot do what only the owner may.
	for _, statement := range []string{
		`ALTER TABLE authority_effect_attempts NO FORCE ROW LEVEL SECURITY`,
		`DELETE FROM authority_postings`,
		`UPDATE authority_postings SET amount = 0`,
		`UPDATE authority_provision_limits SET first_revision = 0`,
		`DELETE FROM authority_provision_limits`,
		`UPDATE authority_distinct_values SET attempt_id = attempt_id`,
		`DELETE FROM authority_effect_attempts`,
		`TRUNCATE authority_postings`,
		`CREATE TABLE authority_extra (tenant_id TEXT)`,
		`CREATE TEMPORARY TABLE scratch (x int)`,
		`SET ROLE ` + owner,
	} {
		if _, err := runtimeDB.Exec(statement); err == nil || !strings.Contains(err.Error(), "denied") && !strings.Contains(err.Error(), "must be owner") {
			t.Fatalf("runtime role %q: err = %v, want a permission error", statement, err)
		}
	}
}
