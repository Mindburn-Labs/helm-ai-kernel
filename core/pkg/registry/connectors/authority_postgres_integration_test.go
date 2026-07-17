package connectors

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/lib/pq"
)

// TestPostgresReleaseAuthorityAppendOnlyCurrentStateAndIsolation is the
// source-owned real-Postgres proof for append-only history, anti-rollback,
// terminal revocation, trusted-time planning reads, RLS, and least-privilege
// roles. Durable effect admission is intentionally a separate boundary.
func TestPostgresReleaseAuthorityAppendOnlyCurrentStateAndIsolation(t *testing.T) {
	postgresURL := os.Getenv("HELM_TEST_POSTGRES_URL")
	if postgresURL == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run connector release authority PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	suffix := time.Now().UnixNano()
	schema := fmt.Sprintf("helm_connector_authority_%d", suffix)
	ownerDB := openReleaseAuthorityPostgres(t, postgresURL, schema, "", "")
	defer func() { _ = ownerDB.Close() }()
	if _, err := ownerDB.ExecContext(ctx, `CREATE SCHEMA `+pq.QuoteIdentifier(schema)); err != nil {
		t.Fatalf("create connector authority test schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = ownerDB.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+pq.QuoteIdentifier(schema)+` CASCADE`)
	}()
	if err := ApplyConnectorReleaseAuthorityMigrations(ctx, ownerDB); err != nil {
		t.Fatalf("ApplyConnectorReleaseAuthorityMigrations(): %v", err)
	}
	if err := ApplyConnectorReleaseAuthorityMigrations(ctx, ownerDB); err != nil {
		t.Fatalf("idempotent ApplyConnectorReleaseAuthorityMigrations(): %v", err)
	}

	writerRole := fmt.Sprintf("helm_connector_writer_%d", suffix)
	runtimeRole := fmt.Sprintf("helm_connector_runtime_%d", suffix)
	rolePassword := "helm-connector-authority-test"
	createReleaseAuthorityRole(t, ctx, ownerDB, writerRole, rolePassword)
	createReleaseAuthorityRole(t, ctx, ownerDB, runtimeRole, rolePassword)
	revokeReleaseAuthorityTemporaryPrivilege(t, ctx, ownerDB)
	defer cleanupReleaseAuthorityRoles(ownerDB, writerRole, runtimeRole)()
	quotedSchema := pq.QuoteIdentifier(schema)
	quotedWriter := pq.QuoteIdentifier(writerRole)
	quotedRuntime := pq.QuoteIdentifier(runtimeRole)
	if _, err := ownerDB.ExecContext(ctx, `GRANT USAGE ON SCHEMA `+quotedSchema+` TO `+quotedWriter+`, `+quotedRuntime); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT SELECT, INSERT ON connector_release_authorities TO `+quotedWriter); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT SELECT ON connector_release_authorities TO `+quotedRuntime); err != nil {
		t.Fatal(err)
	}

	writerDB := openReleaseAuthorityPostgres(t, postgresURL, schema, writerRole, rolePassword)
	defer func() { _ = writerDB.Close() }()
	runtimeDB := openReleaseAuthorityPostgres(t, postgresURL, schema, runtimeRole, rolePassword)
	defer func() { _ = runtimeDB.Close() }()
	if err := writerDB.PingContext(ctx); err != nil {
		t.Fatalf("connect writer role: %v", err)
	}
	if err := runtimeDB.PingContext(ctx); err != nil {
		t.Fatalf("connect runtime role: %v", err)
	}
	assertReleaseAuthorityRole(t, ctx, ownerDB, writerRole)
	assertReleaseAuthorityRole(t, ctx, ownerDB, runtimeRole)

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{37}, ed25519.SeedSize))
	base := releaseAuthorityFixtureFor(t, "connector-main", contracts.ConnectorReleaseAuthorityScopeGlobal, "", "")
	verifier := releaseAuthorityVerifierFixture(t, base, privateKey.Public().(ed25519.PublicKey), true)
	admin, err := NewPostgresReleaseAuthorityAdminStore(writerDB, verifier)
	if err != nil {
		t.Fatal(err)
	}
	runtimeStore, err := NewPostgresReleaseAuthorityStore(runtimeDB, verifier)
	if err != nil {
		t.Fatal(err)
	}

	baseEnvelope := signReleaseAuthorityForPostgres(t, base, privateKey)
	appended, err := admin.Append(ctx, baseEnvelope)
	if err != nil || appended.Replay {
		t.Fatalf("initial Append() = %+v, %v", appended, err)
	}
	replayed, err := admin.Append(ctx, baseEnvelope)
	if err != nil || !replayed.Replay {
		t.Fatalf("replay Append() = %+v, %v", replayed, err)
	}
	assertReleaseAuthorityRowCount(t, ctx, ownerDB, releaseAuthorityLookup(base), 1)
	if _, err := runtimeStore.LoadCurrentCertified(ctx, releaseAuthorityLookup(base)); err != nil {
		t.Fatalf("LoadCurrentCertified(): %v", err)
	}
	expired := releaseAuthorityFixtureFor(t, "connector-expired", contracts.ConnectorReleaseAuthorityScopeGlobal, "", "")
	expiredUntil := time.Now().UTC().Truncate(time.Microsecond).Add(-30 * time.Second)
	expired.ValidUntil = &expiredUntil
	expired.AuthorityHash = ""
	expired, err = expired.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Append(ctx, signReleaseAuthorityForPostgres(t, expired, privateKey)); err != nil {
		t.Fatalf("append expired authority: %v", err)
	}
	if _, err := runtimeStore.LoadCurrentCertified(ctx, releaseAuthorityLookup(expired)); !errors.Is(err, ErrReleaseAuthorityRejected) {
		t.Fatalf("expired LoadCurrentCertified() error = %v", err)
	}
	missingLookup := releaseAuthorityLookup(base)
	missingLookup.ConnectorVersion = "9.9.9"
	if _, err := runtimeStore.LoadCurrent(ctx, missingLookup); !errors.Is(err, ErrReleaseAuthorityNotFound) {
		t.Fatalf("missing LoadCurrent() error = %v", err)
	}
	var replayWG sync.WaitGroup
	replayErrors := make(chan error, 8)
	for range 8 {
		replayWG.Add(1)
		go func() {
			defer replayWG.Done()
			result, appendErr := admin.Append(ctx, baseEnvelope)
			if appendErr == nil && !result.Replay {
				appendErr = errors.New("concurrent exact replay appended a second row")
			}
			replayErrors <- appendErr
		}()
	}
	replayWG.Wait()
	close(replayErrors)
	for replayErr := range replayErrors {
		if replayErr != nil {
			t.Fatal(replayErr)
		}
	}
	assertReleaseAuthorityRowCount(t, ctx, ownerDB, releaseAuthorityLookup(base), 1)

	tenantAuthority := releaseAuthorityFixtureFor(t, "connector-tenant", contracts.ConnectorReleaseAuthorityScopeWorkspace, "tenant-a", "workspace-a")
	if _, err := admin.Append(ctx, signReleaseAuthorityForPostgres(t, tenantAuthority, privateKey)); err != nil {
		t.Fatalf("append tenant authority: %v", err)
	}
	assertReleaseAuthorityRLSCount(t, ctx, runtimeDB, "tenant-a", "workspace-a", tenantAuthority.ConnectorID, 1)
	assertReleaseAuthorityRLSCount(t, ctx, runtimeDB, "tenant-b", "workspace-a", tenantAuthority.ConnectorID, 0)
	wrongTenant := releaseAuthorityLookup(tenantAuthority)
	wrongTenant.TenantID = "tenant-b"
	if _, err := runtimeStore.LoadCurrent(ctx, wrongTenant); !errors.Is(err, ErrReleaseAuthorityNotFound) {
		t.Fatalf("cross-tenant LoadCurrent() error = %v", err)
	}

	assertReleaseAuthorityPrivileges(t, ctx, runtimeDB, writerDB, ownerDB, schema)
	skippedRevision := nextCertifiedReleaseAuthority(t, nextCertifiedReleaseAuthority(t, base))
	if err := rawInsertReleaseAuthority(ctx, writerDB, signReleaseAuthorityForPostgres(t, skippedRevision, privateKey)); err == nil {
		t.Fatal("database accepted a direct skipped revision")
	}
	materialSubstitution := nextCertifiedReleaseAuthority(t, base)
	materialSubstitution.ConnectorBinaryHash = "sha256:" + strings.Repeat("f", 64)
	materialSubstitution.AuthorityHash = ""
	materialSubstitution, err = materialSubstitution.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := rawInsertReleaseAuthority(ctx, writerDB, signReleaseAuthorityForPostgres(t, materialSubstitution, privateKey)); err == nil {
		t.Fatal("database accepted direct exact-version material substitution")
	}
	assertReleaseAuthorityTriggerIgnoresTemporaryShadow(t, ctx, ownerDB, admin, privateKey, schema)

	renewal := nextCertifiedReleaseAuthority(t, base)
	revocation := nextReleaseAuthorityRevocation(t, base)
	rivals := []contracts.ConnectorReleaseAuthorityEnvelope{
		signReleaseAuthorityForPostgres(t, renewal, privateKey),
		signReleaseAuthorityForPostgres(t, revocation, privateKey),
	}
	start := make(chan struct{})
	rivalErrors := make(chan error, len(rivals))
	for _, rival := range rivals {
		rival := rival
		go func() {
			<-start
			_, appendErr := admin.Append(ctx, rival)
			rivalErrors <- appendErr
		}()
	}
	close(start)
	var successes, conflicts int
	for range rivals {
		appendErr := <-rivalErrors
		switch {
		case appendErr == nil:
			successes++
		case errors.Is(appendErr, ErrReleaseAuthorityConflict):
			conflicts++
		default:
			t.Fatalf("rival append error = %v", appendErr)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("rival revisions: successes=%d conflicts=%d", successes, conflicts)
	}
	currentEnvelope, err := runtimeStore.LoadCurrent(ctx, releaseAuthorityLookup(base))
	if err != nil {
		t.Fatal(err)
	}
	current := currentEnvelope.Authority
	if current.State != contracts.ConnectorReleaseAuthorityStateRevoked {
		current = nextReleaseAuthorityRevocation(t, current)
		if _, err := admin.Append(ctx, signReleaseAuthorityForPostgres(t, current, privateKey)); err != nil {
			t.Fatalf("append terminal revocation: %v", err)
		}
	}
	terminalSuccessor := nextCertifiedReleaseAuthority(t, current)
	if _, err := admin.Append(ctx, signReleaseAuthorityForPostgres(t, terminalSuccessor, privateKey)); !errors.Is(err, ErrReleaseAuthorityTerminal) {
		t.Fatalf("post-revocation append error = %v", err)
	}
	if _, err := admin.Append(ctx, baseEnvelope); !errors.Is(err, ErrReleaseAuthorityConflict) {
		t.Fatalf("anti-rollback append error = %v", err)
	}
	assertReleaseAuthorityRowCount(t, ctx, ownerDB, releaseAuthorityLookup(base), int(current.RegistryRevision))
}

func createReleaseAuthorityRole(t *testing.T, ctx context.Context, db *sql.DB, role, password string) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `CREATE ROLE `+pq.QuoteIdentifier(role)+` WITH LOGIN PASSWORD '`+password+`' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatalf("create role %s: %v", role, err)
	}
}

func cleanupReleaseAuthorityRoles(db *sql.DB, roles ...string) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, role := range roles {
			quoted := pq.QuoteIdentifier(role)
			_, _ = db.ExecContext(ctx, `DROP OWNED BY `+quoted)
			_, _ = db.ExecContext(ctx, `DROP ROLE IF EXISTS `+quoted)
		}
	}
}

func assertReleaseAuthorityRole(t *testing.T, ctx context.Context, db *sql.DB, role string) {
	t.Helper()
	var superuser, bypassRLS, createDB, createRole bool
	if err := db.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = $1`, role).
		Scan(&superuser, &bypassRLS, &createDB, &createRole); err != nil {
		t.Fatal(err)
	}
	if superuser || bypassRLS || createDB || createRole {
		t.Fatalf("role %s is privileged: super=%t bypassrls=%t createdb=%t createrole=%t", role, superuser, bypassRLS, createDB, createRole)
	}
}

func assertReleaseAuthorityPrivileges(t *testing.T, ctx context.Context, runtimeDB, writerDB, ownerDB *sql.DB, schema string) {
	t.Helper()
	if _, err := runtimeDB.ExecContext(ctx, `CREATE TEMP TABLE connector_release_authorities (id int)`); err == nil {
		t.Fatal("runtime role unexpectedly created a temporary authority shadow")
	}
	if _, err := writerDB.ExecContext(ctx, `CREATE TEMP TABLE connector_release_authorities (id int)`); err == nil {
		t.Fatal("writer role unexpectedly created a temporary authority shadow")
	}
	if _, err := runtimeDB.ExecContext(ctx, `UPDATE connector_release_authorities SET state = state`); err == nil {
		t.Fatal("runtime role unexpectedly updated authority history")
	}
	if _, err := runtimeDB.ExecContext(ctx, `DELETE FROM connector_release_authorities`); err == nil {
		t.Fatal("runtime role unexpectedly deleted authority history")
	}
	if _, err := runtimeDB.ExecContext(ctx, `INSERT INTO connector_release_authorities (scope_kind) VALUES ('global')`); err == nil {
		t.Fatal("runtime role unexpectedly inserted authority history")
	}
	if _, err := runtimeDB.ExecContext(ctx, `CREATE TABLE `+pq.QuoteIdentifier(schema)+`.runtime_ddl_probe (id int)`); err == nil {
		t.Fatal("runtime role unexpectedly executed DDL")
	}
	if err := ApplyConnectorReleaseAuthorityMigrations(ctx, runtimeDB); err == nil {
		t.Fatal("runtime role unexpectedly applied authority migrations")
	}
	if _, err := writerDB.ExecContext(ctx, `UPDATE connector_release_authorities SET state = state`); err == nil {
		t.Fatal("writer role unexpectedly updated authority history")
	}
	if _, err := writerDB.ExecContext(ctx, `DELETE FROM connector_release_authorities`); err == nil {
		t.Fatal("writer role unexpectedly deleted authority history")
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE connector_release_authorities SET state = state`); err == nil {
		t.Fatal("append-only trigger allowed owner mutation")
	}
}

func revokeReleaseAuthorityTemporaryPrivilege(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var databaseName string
	if err := db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&databaseName); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `REVOKE TEMPORARY ON DATABASE `+pq.QuoteIdentifier(databaseName)+` FROM PUBLIC`); err != nil {
		t.Fatalf("revoke public temporary-table privilege: %v", err)
	}
}

func assertReleaseAuthorityTriggerIgnoresTemporaryShadow(
	t *testing.T,
	ctx context.Context,
	ownerDB *sql.DB,
	admin *PostgresReleaseAuthorityAdminStore,
	privateKey ed25519.PrivateKey,
	schema string,
) {
	t.Helper()
	base := releaseAuthorityFixtureFor(t, "connector-shadow-proof", contracts.ConnectorReleaseAuthorityScopeGlobal, "", "")
	if _, err := admin.Append(ctx, signReleaseAuthorityForPostgres(t, base, privateKey)); err != nil {
		t.Fatal(err)
	}
	connection, err := ownerDB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	if _, err := connection.ExecContext(ctx, `CREATE TEMP TABLE connector_release_authorities (
		registry_revision BIGINT, state TEXT, authority_hash TEXT, envelope_json JSONB,
		signed_at TIMESTAMPTZ, valid_from TIMESTAMPTZ, scope_kind TEXT, tenant_id TEXT,
		workspace_id TEXT, connector_id TEXT, connector_version TEXT
	)`); err != nil {
		t.Fatalf("create owner-only temporary shadow proof: %v", err)
	}
	defer func() {
		_, _ = connection.ExecContext(context.Background(), `DROP TABLE IF EXISTS pg_temp.connector_release_authorities`)
	}()
	if _, err := connection.ExecContext(ctx, `INSERT INTO connector_release_authorities VALUES (
		99, 'revoked', $1, '{}'::jsonb, clock_timestamp(), clock_timestamp(),
		$2, $3, $4, $5, $6
	)`, "sha256:"+strings.Repeat("e", 64), base.ScopeKind, base.TenantID, base.WorkspaceID, base.ConnectorID, base.ConnectorVersion); err != nil {
		t.Fatal(err)
	}
	next := nextCertifiedReleaseAuthority(t, base)
	table := pq.QuoteIdentifier(schema) + "." + pq.QuoteIdentifier("connector_release_authorities")
	if err := rawInsertReleaseAuthorityInto(ctx, connection, table, signReleaseAuthorityForPostgres(t, next, privateKey)); err != nil {
		t.Fatalf("schema-qualified append consulted temporary shadow: %v", err)
	}
}

type releaseAuthorityExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func rawInsertReleaseAuthority(ctx context.Context, db *sql.DB, envelope contracts.ConnectorReleaseAuthorityEnvelope) error {
	return rawInsertReleaseAuthorityInto(ctx, db, "connector_release_authorities", envelope)
}

func rawInsertReleaseAuthorityInto(ctx context.Context, db releaseAuthorityExecer, table string, envelope contracts.ConnectorReleaseAuthorityEnvelope) error {
	authority := envelope.Authority
	payload, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO `+table+` (
		scope_kind, tenant_id, workspace_id, connector_id, connector_version,
		registry_revision, state, authority_hash, previous_authority_hash,
		revokes_authority_hash, signed_at, valid_from, valid_until, envelope_json, signature
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		authority.ScopeKind, authority.TenantID, authority.WorkspaceID,
		authority.ConnectorID, authority.ConnectorVersion, authority.RegistryRevision,
		authority.State, authority.AuthorityHash, nullableAuthorityHash(authority.PreviousAuthorityHash),
		nullableAuthorityHash(authority.RevokesAuthorityHash), authority.SignedAt,
		authority.ValidFrom, authority.ValidUntil, payload, envelope.Signature,
	)
	return err
}

func assertReleaseAuthorityRLSCount(t *testing.T, ctx context.Context, db *sql.DB, tenantID, workspaceID, connectorID string, want int) {
	t.Helper()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_workspace', $1, true)`, workspaceID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM connector_release_authorities WHERE connector_id = $1`, connectorID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("RLS count for %s/%s connector %s = %d, want %d", tenantID, workspaceID, connectorID, count, want)
	}
}

func assertReleaseAuthorityRowCount(t *testing.T, ctx context.Context, db *sql.DB, lookup ReleaseAuthorityLookup, want int) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM connector_release_authorities
		WHERE scope_kind = $1 AND tenant_id = $2 AND workspace_id = $3
		  AND connector_id = $4 AND connector_version = $5`,
		lookup.ScopeKind, lookup.TenantID, lookup.WorkspaceID, lookup.ConnectorID, lookup.ConnectorVersion,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("authority row count = %d, want %d", count, want)
	}
}

func releaseAuthorityFixtureFor(t *testing.T, connectorID, scopeKind, tenantID, workspaceID string) contracts.ConnectorReleaseAuthority {
	t.Helper()
	authority := signedReleaseAuthorityFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	authority.SignedAt = now.Add(-2 * time.Minute)
	authority.ValidFrom = now.Add(-time.Minute)
	validUntil := now.Add(24 * time.Hour)
	authority.ValidUntil = &validUntil
	authority.ConnectorID = connectorID
	authority.ScopeKind = scopeKind
	authority.TenantID = tenantID
	authority.WorkspaceID = workspaceID
	authority.AuthorityHash = ""
	sealed, err := authority.Seal()
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func nextCertifiedReleaseAuthority(t *testing.T, current contracts.ConnectorReleaseAuthority) contracts.ConnectorReleaseAuthority {
	t.Helper()
	next := current
	next.RegistryRevision++
	next.State = contracts.ConnectorReleaseAuthorityStateCertified
	next.SignedAt = current.ValidFrom.Add(time.Minute)
	next.ValidFrom = next.SignedAt
	validUntil := next.ValidFrom.Add(24 * time.Hour)
	next.ValidUntil = &validUntil
	next.PreviousAuthorityHash = current.AuthorityHash
	next.RevokesAuthorityHash = ""
	next.AuthorityHash = ""
	sealed, err := next.Seal()
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func nextReleaseAuthorityRevocation(t *testing.T, current contracts.ConnectorReleaseAuthority) contracts.ConnectorReleaseAuthority {
	t.Helper()
	next := current
	next.RegistryRevision++
	next.State = contracts.ConnectorReleaseAuthorityStateRevoked
	next.SignedAt = current.ValidFrom.Add(time.Minute)
	next.ValidFrom = next.SignedAt
	next.ValidUntil = nil
	next.PreviousAuthorityHash = current.AuthorityHash
	next.RevokesAuthorityHash = current.AuthorityHash
	next.AuthorityHash = ""
	sealed, err := next.Seal()
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func signReleaseAuthorityForPostgres(t *testing.T, authority contracts.ConnectorReleaseAuthority, privateKey ed25519.PrivateKey) contracts.ConnectorReleaseAuthorityEnvelope {
	t.Helper()
	envelope, err := SignConnectorReleaseAuthority(authority, crypto.NewEd25519SignerFromKey(privateKey, authority.SigningKeyRef))
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func openReleaseAuthorityPostgres(t *testing.T, rawURL, schema, username, password string) *sql.DB {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		t.Fatalf("HELM_TEST_POSTGRES_URL must be a URL-style PostgreSQL DSN: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	if username != "" {
		parsed.User = url.UserPassword(username, password)
	}
	db, err := sql.Open("postgres", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(16)
	return db
}
