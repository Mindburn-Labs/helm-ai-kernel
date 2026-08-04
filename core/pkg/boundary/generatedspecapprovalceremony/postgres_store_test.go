package generatedspecapprovalceremony

import (
	"context"
	cryptorand "crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapproval"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	"github.com/lib/pq"
)

func TestPostgresStoreValidatesPinnedArtifactsOnRead(t *testing.T) {
	fixture := newCeremonyFixture(t)
	ctx := context.Background()
	granted := fixture.toGrant(t, ctx)
	store := &PostgresStore{verifier: fixture.verifier}

	if _, err := store.validateLoaded(granted); err != nil {
		t.Fatalf("validateLoaded(grant) error = %v", err)
	}
	tamperedGrant := granted
	tamperedGrant.SignedGrant = &generatedspecapproval.SignedGrant{
		Grant:     granted.SignedGrant.Grant,
		Algorithm: granted.SignedGrant.Algorithm,
		Signature: strings.Repeat("0", 128),
	}
	if _, err := store.validateLoaded(tamperedGrant); !errors.Is(err, generatedspecapproval.ErrSignatureRejected) {
		t.Fatalf("validateLoaded(tampered grant) error = %v, want signature rejection", err)
	}

	consumed, err := fixture.service.ConsumeGrant(ctx, granted.ApprovalID, granted.SignedGrant.Grant.GrantID, granted.SignedGrant.Grant.GrantHash, granted.SignedGrant.Grant.Nonce)
	if err != nil {
		t.Fatalf("ConsumeGrant() error = %v", err)
	}
	if _, err := store.validateLoaded(consumed); err != nil {
		t.Fatalf("validateLoaded(consumption) error = %v", err)
	}
	tamperedConsumption := consumed
	tamperedConsumption.SignedConsumption = &generatedspecapproval.SignedConsumption{
		Consumption: consumed.SignedConsumption.Consumption,
		Algorithm:   consumed.SignedConsumption.Algorithm,
		Signature:   strings.Repeat("0", 128),
	}
	if _, err := store.validateLoaded(tamperedConsumption); !errors.Is(err, generatedspecapproval.ErrSignatureRejected) {
		t.Fatalf("validateLoaded(tampered consumption) error = %v, want signature rejection", err)
	}
}

func TestPostgresStoreRequiresDatabaseAndVerifier(t *testing.T) {
	if err := NewPostgresStore(nil, nil).Init(context.Background()); err == nil {
		t.Fatal("Init() without database and verifier unexpectedly succeeded")
	}
}

func TestPostgresSchemaKeepsOneActiveCeremonyPerBinding(t *testing.T) {
	for _, required := range []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS generated_spec_approval_ceremonies_active_binding_ref_uq",
		"ON generated_spec_approval_ceremonies (tenant_id, workspace_id, binding_ref)",
		"WHERE state IN ('HOLD_PENDING', 'CHALLENGE_ISSUED', 'QUORUM_VERIFIED', 'GRANT_ISSUED')",
	} {
		if !strings.Contains(generatedSpecApprovalPostgresSchema, required) {
			t.Fatalf("generated spec approval schema missing %q", required)
		}
	}
}

func TestPostgresSchemaPreflightsLegacyDuplicateActiveBindings(t *testing.T) {
	const diagnostic = "generated spec approval ceremony migration blocked: duplicate active bindings require operator reconciliation"
	preflight := strings.Index(generatedSpecApprovalPostgresSchema, diagnostic)
	uniqueIndex := strings.Index(generatedSpecApprovalPostgresSchema, "CREATE UNIQUE INDEX IF NOT EXISTS generated_spec_approval_ceremonies_active_binding_ref_uq")
	if preflight < 0 || uniqueIndex < 0 || preflight > uniqueIndex {
		t.Fatalf("legacy duplicate preflight must precede active binding unique index")
	}
	if !strings.Contains(generatedSpecApprovalPostgresSchema, "PERFORM pg_catalog.set_config('row_security', 'off', true)") {
		t.Fatal("legacy duplicate preflight must require complete row visibility")
	}
}

func TestPostgresSchemaPreflightDistinguishesLegacyPrivilegeAndRLS(t *testing.T) {
	const missingSelect = "generated spec approval ceremony migration blocked: migration role lacks SELECT privilege for legacy active-binding preflight"
	const rlsBlocked = "generated spec approval ceremony migration blocked: row-level security prevents complete legacy active-binding visibility"
	privilegeCheck := strings.Index(generatedSpecApprovalPostgresSchema, "pg_catalog.has_table_privilege")
	missingSelectDiagnostic := strings.Index(generatedSpecApprovalPostgresSchema, missingSelect)
	rlsDiagnostic := strings.Index(generatedSpecApprovalPostgresSchema, rlsBlocked)
	rowSecurityCheck := strings.Index(generatedSpecApprovalPostgresSchema, "pg_catalog.set_config('row_security', 'off', true)")
	legacyScan := strings.Index(generatedSpecApprovalPostgresSchema, "SELECT EXISTS")
	visibilityException := strings.Index(generatedSpecApprovalPostgresSchema, "WHEN insufficient_privilege")
	if privilegeCheck < 0 || missingSelectDiagnostic < privilegeCheck || rowSecurityCheck < missingSelectDiagnostic || legacyScan < rowSecurityCheck || visibilityException < legacyScan || rlsDiagnostic < visibilityException {
		t.Fatal("legacy visibility preflight must distinguish missing SELECT before RLS visibility")
	}
}

// TestPostgresStoreInitPreflightsLegacyActiveBindings exercises a schema that
// predates the active-binding unique index. It never repairs or exposes the
// duplicate scope; the migration must stop with its static operator diagnostic.
func TestPostgresStoreInitPreflightsLegacyActiveBindings(t *testing.T) {
	postgresURL := os.Getenv("HELM_TEST_POSTGRES_URL")
	if postgresURL == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run generated spec approval PostgreSQL migration proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, test := range []struct {
		name       string
		duplicates bool
		wantErr    bool
	}{
		{name: "valid legacy data migrates"},
		{name: "duplicate active bindings fail closed", duplicates: true, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			schema := fmt.Sprintf("helm_generated_spec_approval_migration_%d", time.Now().UnixNano())
			db := openGeneratedSpecApprovalTestPostgres(t, postgresURL, schema, "", "")
			defer func() { _ = db.Close() }()
			if _, err := db.ExecContext(ctx, `CREATE SCHEMA `+pq.QuoteIdentifier(schema)); err != nil {
				t.Fatalf("create generated spec approval migration schema: %v", err)
			}
			defer func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cleanupCancel()
				_, _ = db.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+pq.QuoteIdentifier(schema)+` CASCADE`)
			}()
			if _, err := db.ExecContext(ctx, generatedSpecApprovalLegacyTableSchema(t)); err != nil {
				t.Fatalf("create legacy generated spec approval table: %v", err)
			}

			fixture := newCeremonyFixture(t)
			legacyStore := NewPostgresStore(db, fixture.verifier)
			hold, err := fixture.service.BeginHold(ctx, fixture.binding.BindingRef)
			if err != nil {
				t.Fatalf("create legacy hold: %v", err)
			}
			if _, err := legacyStore.CreateHold(ctx, hold); err != nil {
				t.Fatalf("persist legacy hold: %v", err)
			}
			if test.duplicates {
				duplicate := hold
				duplicate.ApprovalID = "approval-legacy-duplicate"
				if _, err := legacyStore.CreateHold(ctx, duplicate); err != nil {
					t.Fatalf("persist duplicate legacy hold: %v", err)
				}
			}

			err = legacyStore.Init(ctx)
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), "generated spec approval ceremony migration blocked: duplicate active bindings require operator reconciliation") {
					t.Fatalf("legacy duplicate migration error = %v", err)
				}
				for _, identifier := range []string{"tenant-a", "workspace-a", "binding-a", "approval-legacy-duplicate"} {
					if strings.Contains(err.Error(), identifier) {
						t.Fatalf("legacy duplicate migration diagnostic leaked %q: %v", identifier, err)
					}
				}
				var index sql.NullString
				if indexErr := db.QueryRowContext(ctx, `SELECT to_regclass('generated_spec_approval_ceremonies_active_binding_ref_uq')`).Scan(&index); indexErr != nil || index.Valid {
					t.Fatalf("duplicate migration created active binding unique index = %q, error = %v", index.String, indexErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("migrate valid legacy data: %v", err)
			}
			var index sql.NullString
			if err := db.QueryRowContext(ctx, `SELECT to_regclass('generated_spec_approval_ceremonies_active_binding_ref_uq')`).Scan(&index); err != nil || !index.Valid {
				t.Fatalf("active binding unique index = %q, error = %v", index.String, err)
			}
		})
	}
}

// TestPostgresStoreInitPreflightsLegacyVisibility verifies that a migration
// role receives different static diagnostics for missing SELECT and forced RLS.
func TestPostgresStoreInitPreflightsLegacyVisibility(t *testing.T) {
	postgresURL := os.Getenv("HELM_TEST_POSTGRES_URL")
	if postgresURL == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run generated spec approval PostgreSQL visibility proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, test := range []struct {
		name       string
		forceRLS   bool
		diagnostic string
	}{
		{
			name:       "migration role lacks select",
			diagnostic: "generated spec approval ceremony migration blocked: migration role lacks SELECT privilege for legacy active-binding preflight",
		},
		{
			name:       "forced row level security",
			forceRLS:   true,
			diagnostic: "generated spec approval ceremony migration blocked: row-level security prevents complete legacy active-binding visibility",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			schema := fmt.Sprintf("helm_generated_spec_approval_visibility_%d", time.Now().UnixNano())
			ownerDB := openGeneratedSpecApprovalTestPostgres(t, postgresURL, schema, "", "")
			defer func() { _ = ownerDB.Close() }()
			if _, err := ownerDB.ExecContext(ctx, `CREATE SCHEMA `+pq.QuoteIdentifier(schema)); err != nil {
				t.Fatalf("create generated spec approval visibility schema: %v", err)
			}
			role := fmt.Sprintf("helm_generated_spec_visibility_%d", time.Now().UnixNano())
			quotedRole := pq.QuoteIdentifier(role)
			if _, err := ownerDB.ExecContext(ctx, `CREATE ROLE `+quotedRole+` WITH
				LOGIN PASSWORD 'helm-generated-spec-visibility-password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`); err != nil {
				t.Fatalf("create generated spec approval visibility role: %v", err)
			}
			defer func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cleanupCancel()
				_, _ = ownerDB.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+pq.QuoteIdentifier(schema)+` CASCADE`)
				_, _ = ownerDB.ExecContext(cleanupCtx, `DROP OWNED BY `+quotedRole)
				_, _ = ownerDB.ExecContext(cleanupCtx, `DROP ROLE IF EXISTS `+quotedRole)
			}()
			if _, err := ownerDB.ExecContext(ctx, `GRANT USAGE, CREATE ON SCHEMA `+pq.QuoteIdentifier(schema)+` TO `+quotedRole); err != nil {
				t.Fatalf("grant migration role schema access: %v", err)
			}
			if _, err := ownerDB.ExecContext(ctx, generatedSpecApprovalLegacyTableSchema(t)); err != nil {
				t.Fatalf("create legacy generated spec approval table: %v", err)
			}
			if test.forceRLS {
				if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE generated_spec_approval_ceremonies OWNER TO `+quotedRole); err != nil {
					t.Fatalf("assign legacy table owner: %v", err)
				}
			}
			var hasSelect bool
			if err := ownerDB.QueryRowContext(ctx, `SELECT pg_catalog.has_table_privilege($1, 'generated_spec_approval_ceremonies'::regclass, 'SELECT')`, role).Scan(&hasSelect); err != nil {
				t.Fatalf("read migration role legacy table privilege: %v", err)
			}
			if hasSelect != test.forceRLS {
				t.Fatalf("migration role SELECT privilege = %t, want %t", hasSelect, test.forceRLS)
			}

			runtimeDB := openGeneratedSpecApprovalTestPostgres(t, postgresURL, schema, role, "helm-generated-spec-visibility-password")
			defer func() { _ = runtimeDB.Close() }()
			if test.forceRLS {
				if _, err := runtimeDB.ExecContext(ctx, `ALTER TABLE generated_spec_approval_ceremonies ENABLE ROW LEVEL SECURITY; ALTER TABLE generated_spec_approval_ceremonies FORCE ROW LEVEL SECURITY; CREATE POLICY generated_spec_approval_ceremonies_visibility_test ON generated_spec_approval_ceremonies USING (false)`); err != nil {
					t.Fatalf("force legacy table RLS: %v", err)
				}
			}

			fixture := newCeremonyFixture(t)
			err := NewPostgresStore(runtimeDB, fixture.verifier).Init(ctx)
			if err == nil || !strings.Contains(err.Error(), test.diagnostic) {
				t.Fatalf("legacy visibility migration error = %v, want %q", err, test.diagnostic)
			}
		})
	}
}

func generatedSpecApprovalLegacyTableSchema(t *testing.T) string {
	t.Helper()
	legacySchema, _, found := strings.Cut(generatedSpecApprovalPostgresSchema, "\n-- Fail closed before enforcing one active binding for legacy rows.")
	if !found {
		t.Fatal("generated spec approval migration missing legacy duplicate preflight")
	}
	return legacySchema
}

// TestPostgresLifecycleSingleIssueConsumeAndFence is a source-owned real-
// Postgres proof. It intentionally skips until the caller supplies a database
// URL; it never falls back to SQLite or a missing emergency-stop table.
func TestPostgresLifecycleSingleIssueConsumeAndFence(t *testing.T) {
	postgresURL := os.Getenv("HELM_TEST_POSTGRES_URL")
	if postgresURL == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run generated spec approval PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	schema := fmt.Sprintf("helm_generated_spec_approval_%d", time.Now().UnixNano())
	ownerDB := openGeneratedSpecApprovalTestPostgres(t, postgresURL, schema, "", "")
	defer func() { _ = ownerDB.Close() }()
	if _, err := ownerDB.ExecContext(ctx, `CREATE SCHEMA `+pq.QuoteIdentifier(schema)); err != nil {
		t.Fatalf("create generated spec approval schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = ownerDB.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+pq.QuoteIdentifier(schema)+` CASCADE`)
	}()

	fixture := newCeremonyFixture(t)
	ownerStore := NewPostgresStore(ownerDB, fixture.verifier)
	if err := ownerStore.Init(ctx); err != nil {
		t.Fatalf("PostgresStore.Init() error = %v", err)
	}
	stopStore := kernel.NewScopedStopStore(ownerDB, time.Now, kernel.WithPostgresScopeLocks())
	if err := stopStore.Init(ctx); err != nil {
		t.Fatalf("ScopedStopStore.Init() error = %v", err)
	}

	runtimeRole := fmt.Sprintf("helm_generated_spec_runtime_%d", time.Now().UnixNano())
	runtimePassword := "helm-generated-spec-test-password"
	quotedRole := pq.QuoteIdentifier(runtimeRole)
	if _, err := ownerDB.ExecContext(ctx, `CREATE ROLE `+quotedRole+` WITH
		LOGIN PASSWORD '`+runtimePassword+`' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatalf("create runtime role: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = ownerDB.ExecContext(cleanupCtx, `DROP OWNED BY `+quotedRole)
		_, _ = ownerDB.ExecContext(cleanupCtx, `DROP ROLE IF EXISTS `+quotedRole)
	}()
	if _, err := ownerDB.ExecContext(ctx, `GRANT USAGE ON SCHEMA `+pq.QuoteIdentifier(schema)+` TO `+quotedRole); err != nil {
		t.Fatalf("grant runtime schema usage: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT SELECT, INSERT, UPDATE ON generated_spec_approval_ceremonies TO `+quotedRole); err != nil {
		t.Fatalf("grant runtime ceremony table privileges: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT SELECT ON emergency_stop_fences TO `+quotedRole); err != nil {
		t.Fatalf("grant runtime emergency-stop read privilege: %v", err)
	}
	var runtimeSuperuser, runtimeBypassRLS bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1`, runtimeRole).
		Scan(&runtimeSuperuser, &runtimeBypassRLS); err != nil {
		t.Fatalf("read runtime role attributes: %v", err)
	}
	if runtimeSuperuser || runtimeBypassRLS {
		t.Fatalf("runtime role bypasses RLS: superuser=%t bypassrls=%t", runtimeSuperuser, runtimeBypassRLS)
	}

	runtimeDB := openGeneratedSpecApprovalTestPostgres(t, postgresURL, schema, runtimeRole, runtimePassword)
	defer func() { _ = runtimeDB.Close() }()
	if err := runtimeDB.PingContext(ctx); err != nil {
		t.Fatalf("connect runtime role: %v", err)
	}
	store := NewPostgresStore(runtimeDB, fixture.verifier)
	store.clock = func() time.Time { return fixture.now }
	service, err := newService(
		store,
		bindingStub{binding: fixture.binding},
		fixture.authority,
		fixture.control,
		fixture.consumer,
		fixture.service.signer,
		fixture.verifier,
		func() time.Time { return fixture.now },
		cryptorand.Reader,
		fixture.config,
	)
	if err != nil {
		t.Fatalf("newService(PostgresStore) error = %v", err)
	}

	granted := issueGeneratedSpecApprovalPostgresGrant(t, ctx, service, fixture)
	assertGeneratedSpecApprovalRLSVisibility(t, ctx, runtimeDB, granted.TenantID, granted.WorkspaceID, granted.ApprovalID, 1)
	assertGeneratedSpecApprovalRLSVisibility(t, ctx, runtimeDB, "tenant-other", granted.WorkspaceID, granted.ApprovalID, 0)
	assertGeneratedSpecApprovalRLSVisibility(t, ctx, runtimeDB, granted.TenantID, "workspace-other", granted.ApprovalID, 0)
	if _, err := store.Get(ctx, "tenant-other", granted.WorkspaceID, granted.ApprovalID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant Get() error = %v, want ErrNotFound", err)
	}

	type consumeResult struct {
		record Record
		err    error
	}
	results := make(chan consumeResult, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			record, consumeErr := service.ConsumeGrant(ctx, granted.ApprovalID, granted.SignedGrant.Grant.GrantID, granted.SignedGrant.Grant.GrantHash, granted.SignedGrant.Grant.Nonce)
			results <- consumeResult{record: record, err: consumeErr}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var consumed Record
	var successCount, conflictCount int
	for result := range results {
		if result.err == nil {
			successCount++
			consumed = result.record
			continue
		}
		if errors.Is(result.err, ErrTransitionConflict) {
			conflictCount++
			continue
		}
		t.Fatalf("concurrent ConsumeGrant() error = %v", result.err)
	}
	if successCount != 1 || conflictCount != 1 || consumed.State != StateConsumed || consumed.SignedConsumption == nil {
		t.Fatalf("concurrent consumption = successes=%d conflicts=%d record=%+v", successCount, conflictCount, consumed)
	}
	recovered, err := service.RecoverGrantConsumption(ctx, granted.ApprovalID, granted.SignedGrant.Grant.GrantID, granted.SignedGrant.Grant.GrantHash, granted.SignedGrant.Grant.Nonce)
	if err != nil || recovered.SignedConsumption == nil || recovered.SignedConsumption.Consumption.ConsumptionHash != consumed.SignedConsumption.Consumption.ConsumptionHash {
		t.Fatalf("RecoverGrantConsumption() record=%+v error=%v", recovered, err)
	}

	pending, err := service.BeginHold(ctx, fixture.binding.BindingRef)
	if err != nil {
		t.Fatalf("BeginHold() for expiry proof error = %v", err)
	}
	if _, err := service.BeginHold(ctx, fixture.binding.BindingRef); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("second active BeginHold() error = %v, want ErrTransitionConflict", err)
	}
	fixture.advance(fixture.config.MaxChallengeLifetime)
	expired, err := service.Expire(ctx, pending.ApprovalID)
	if err != nil || expired.State != StateExpired || expired.ExpiresAt == nil || !expired.ExpiresAt.Equal(pending.HoldStartedAt.Add(fixture.config.MaxChallengeLifetime)) {
		t.Fatalf("Expire(unissued hold) record=%+v error=%v", expired, err)
	}
	recoveredAfterExpiry, err := service.RecoverGrantConsumption(ctx, granted.ApprovalID, granted.SignedGrant.Grant.GrantID, granted.SignedGrant.Grant.GrantHash, granted.SignedGrant.Grant.Nonce)
	if err != nil || recoveredAfterExpiry.SignedConsumption == nil || recoveredAfterExpiry.SignedConsumption.Consumption.ConsumptionHash != consumed.SignedConsumption.Consumption.ConsumptionHash {
		t.Fatalf("RecoverGrantConsumption(after grant expiry) record=%+v error=%v", recoveredAfterExpiry, err)
	}

	fencedGrant := issueGeneratedSpecApprovalPostgresGrant(t, ctx, service, fixture)
	if _, replayed, err := stopStore.Fence(ctx, generatedSpecApprovalFenceCommand(kernel.StopScope{
		TenantID: fencedGrant.TenantID, WorkspaceID: fencedGrant.WorkspaceID,
	}), generatedSpecApprovalFenceAcknowledgement()); err != nil || replayed {
		t.Fatalf("Fence() replayed=%t error=%v", replayed, err)
	}
	if _, err := service.ConsumeGrant(ctx, fencedGrant.ApprovalID, fencedGrant.SignedGrant.Grant.GrantID, fencedGrant.SignedGrant.Grant.GrantHash, fencedGrant.SignedGrant.Grant.Nonce); !errors.Is(err, ErrEmergencyStopFenced) {
		t.Fatalf("ConsumeGrant(fenced) error = %v, want ErrEmergencyStopFenced", err)
	}
}

func issueGeneratedSpecApprovalPostgresGrant(t *testing.T, ctx context.Context, service *Service, fixture *ceremonyFixture) Record {
	t.Helper()
	hold, err := service.BeginHold(ctx, fixture.binding.BindingRef)
	if err != nil {
		t.Fatalf("BeginHold() error = %v", err)
	}
	fixture.advance(fixture.config.MinHoldDuration)
	challenged, err := service.IssueChallenge(ctx, hold.ApprovalID)
	if err != nil {
		t.Fatalf("IssueChallenge() error = %v", err)
	}
	quorum, err := service.VerifyQuorum(ctx, hold.ApprovalID, []contracts.GeneratedSpecApprovalAssertion{fixture.assertion(t, *challenged.Challenge)})
	if err != nil {
		t.Fatalf("VerifyQuorum() error = %v", err)
	}
	granted, err := service.IssueGrant(ctx, quorum.ApprovalID)
	if err != nil {
		t.Fatalf("IssueGrant() error = %v", err)
	}
	return granted
}

func generatedSpecApprovalFenceCommand(scope kernel.StopScope) kernel.FenceCommand {
	now := time.Now().UTC()
	return kernel.FenceCommand{
		ContractVersion: kernel.EmergencyStopFenceContractVersion,
		Audience:        "generated-spec-approval-postgres-test",
		KeyID:           "control-plane-test",
		CommandID:       fmt.Sprintf("generated-spec-fence-%d", now.UnixNano()),
		TenantID:        scope.TenantID,
		WorkspaceID:     scope.WorkspaceID,
		Epoch:           1,
		ActorID:         "operator-test",
		Reason:          "generated spec approval containment proof",
		IssuedAt:        now,
		ExpiresAt:       now.Add(5 * time.Minute),
	}
}

func generatedSpecApprovalFenceAcknowledgement() kernel.AcknowledgementIdentity {
	return kernel.AcknowledgementIdentity{
		KeyID:         "kernel-test",
		SignerProfile: kernel.EmergencyStopSignerClassical,
		PublicKey:     strings.Repeat("a", 64),
	}
}

func assertGeneratedSpecApprovalRLSVisibility(t *testing.T, ctx context.Context, db *sql.DB, tenantID, workspaceID, approvalID string, want int) {
	t.Helper()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("begin RLS visibility transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenantID); err != nil {
		t.Fatalf("set RLS tenant: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_workspace', $1, true)`, workspaceID); err != nil {
		t.Fatalf("set RLS workspace: %v", err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM generated_spec_approval_ceremonies WHERE approval_id = $1`, approvalID).Scan(&count); err != nil {
		t.Fatalf("query RLS visibility: %v", err)
	}
	if count != want {
		t.Fatalf("RLS visibility tenant=%q workspace=%q = %d, want %d", tenantID, workspaceID, count, want)
	}
}

func openGeneratedSpecApprovalTestPostgres(t *testing.T, rawURL, schema, username, password string) *sql.DB {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		t.Fatalf("HELM_TEST_POSTGRES_URL must be a URL-style Postgres DSN: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	if username != "" {
		parsed.User = url.UserPassword(username, password)
	}
	db, err := sql.Open("postgres", parsed.String())
	if err != nil {
		t.Fatalf("open Postgres: %v", err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	return db
}
