package postgresmigration

// ADR-0005 §11 against real Postgres: binding a principal checks its other
// tenants and inserts in one transaction, so concurrent binds of one principal
// into different tenants leave it bound in exactly one of them.

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

func TestPostgresPrincipalBindRefusesConcurrentCrossTenantBinds(t *testing.T) {
	db, base, schema := postgresTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	runtime := restrictedRuntimeDB(ctx, t, db, base, schema)
	const tenants = 16
	runtime.SetMaxOpenConns(tenants)
	bindings, err := store.NewPostgresPrincipalBindingStore(runtime)
	if err != nil {
		t.Fatal(err)
	}

	bindAll := func(principal string, allowCrossTenant bool) []store.BindResult {
		t.Helper()
		results := make([]store.BindResult, tenants)
		errs := make([]error, tenants)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range tenants {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results[i], errs[i] = bindings.Bind(ctx, store.PrincipalBinding{TenantID: fmt.Sprintf("tenant-%02d", i), PrincipalID: principal}, allowCrossTenant)
			}()
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("bind %s into tenant-%02d: %v", principal, i, err)
			}
		}
		return results
	}

	for round := range 5 {
		principal := fmt.Sprintf("member-%d", round)
		created := 0
		for _, result := range bindAll(principal, false) {
			switch result.Outcome {
			case store.BindCreated:
				created++
			case store.BindRefusedCrossTenant:
				if len(result.OtherTenants) != 1 {
					t.Fatalf("round %d: a refusal names %v, want the one winning tenant", round, result.OtherTenants)
				}
			default:
				t.Fatalf("round %d: outcome %v", round, result.Outcome)
			}
		}
		if created != 1 {
			t.Fatalf("round %d: %d concurrent binds into different tenants succeeded, want exactly 1", round, created)
		}
		if got := boundTenantCount(ctx, t, runtime, principal); got != 1 {
			t.Fatalf("round %d: %s is bound in %d tenants, want 1", round, principal, got)
		}
	}

	// A principal allowed to cross tenants is bound in every one of them.
	for _, result := range bindAll("helm-workflow-runner", true) {
		if result.Outcome != store.BindCreated {
			t.Fatalf("cross-tenant principal: outcome %v", result.Outcome)
		}
	}
	if got := boundTenantCount(ctx, t, runtime, "helm-workflow-runner"); got != tenants {
		t.Fatalf("cross-tenant principal bound in %d tenants, want %d", got, tenants)
	}

	// Re-binding the same pair is idempotent.
	result, err := bindings.Bind(ctx, store.PrincipalBinding{TenantID: "tenant-00", PrincipalID: "helm-workflow-runner"}, false)
	if err != nil || result.Outcome != store.BindExisting {
		t.Fatalf("re-bind of an existing pair: %+v %v, want BindExisting", result, err)
	}
}

// boundTenantCount counts the principal's bindings through the principal_lookup
// policy, the only way the runtime role sees rows outside one tenant.
func boundTenantCount(ctx context.Context, t *testing.T, db *sql.DB, principal string) int {
	t.Helper()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_principal', $1, true)`, principal); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM principal_bindings WHERE principal_id = $1`, principal).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
