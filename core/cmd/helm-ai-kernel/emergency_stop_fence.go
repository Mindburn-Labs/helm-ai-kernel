package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

// The scoped emergency-stop fence is the kernel's one stop mechanism (binding
// rule R4). POST /internal/emergency-stop/fence records a fence in the kernel
// database and the Guardian's scoped-stop gate reads it. serve, proxy and mcp
// serve open the same store and bind the same configured scope, so a fence
// recorded through the server stops every entry point that shares its database.

// openEmergencyStopStore opens the fence store on db. It returns nil while
// HELM_EMERGENCY_STOP_FENCE_ENABLED is off.
func openEmergencyStopStore(ctx context.Context, db *sql.DB, databaseMode string) (*kernel.ScopedStopStore, error) {
	if !emergencyStopFenceEnabled() {
		return nil, nil
	}
	if db == nil {
		return nil, fmt.Errorf("scoped emergency-stop fence requires a durable database")
	}
	var options []kernel.ScopedStopStoreOption
	if databaseMode == "postgres" {
		options = append(options, kernel.WithPostgresScopeLocks())
	}
	stops := kernel.NewScopedStopStore(db, time.Now, options...)
	if databaseMode != "postgres" {
		if err := stops.Init(ctx); err != nil {
			return nil, fmt.Errorf("init scoped emergency-stop store: %w", err)
		}
	}
	return stops, nil
}

// emergencyStopScope is the one tenant and workspace a fenced process governs.
// It is the scope bindRuntimeScope binds on the server's routes.
type emergencyStopScope struct {
	TenantID    string
	WorkspaceID string
}

func configuredEmergencyStopScope() (emergencyStopScope, error) {
	scope := emergencyStopScope{
		TenantID:    strings.TrimSpace(os.Getenv(runtimeTenantIDEnv)),
		WorkspaceID: configuredRuntimeWorkspaceID(),
	}
	if scope.TenantID == "" || scope.WorkspaceID == "" {
		return emergencyStopScope{}, fmt.Errorf("%s is on, so %s and %s must name the scope this process governs", emergencyStopFenceEnabledEnv, runtimeTenantIDEnv, runtimeWorkspaceIDEnv)
	}
	return scope, nil
}

// bind returns a copy of decisionContext whose tenant and workspace are the
// configured scope. Every alias the Guardian reads is replaced, so a caller
// cannot name an unfenced scope through tool arguments or a request body.
func (s emergencyStopScope) bind(decisionContext map[string]any) map[string]any {
	bound := make(map[string]any, len(decisionContext)+2)
	for key, value := range decisionContext {
		switch key {
		case "tenant", "tenantId", "tenant_id", "workspace", "workspaceId", "workspace_id":
			continue
		}
		bound[key] = value
	}
	bound["tenant_id"] = s.TenantID
	bound["workspace_id"] = s.WorkspaceID
	return bound
}

// fenceScopedEvaluator decides with the configured emergency-stop scope bound.
type fenceScopedEvaluator struct {
	inner mcppkg.PolicyEvaluator
	scope emergencyStopScope
}

func (e fenceScopedEvaluator) EvaluateDecision(ctx context.Context, req guardian.DecisionRequest) (*contracts.DecisionRecord, error) {
	req.Context = e.scope.bind(req.Context)
	return e.inner.EvaluateDecision(ctx, req)
}

// bindEmergencyStopScope returns evaluator with the configured scope bound
// while the fence is on, and evaluator itself while it is off.
func bindEmergencyStopScope(evaluator mcppkg.PolicyEvaluator) (mcppkg.PolicyEvaluator, error) {
	if !emergencyStopFenceEnabled() {
		return evaluator, nil
	}
	scope, err := configuredEmergencyStopScope()
	if err != nil {
		return nil, err
	}
	return fenceScopedEvaluator{inner: evaluator, scope: scope}, nil
}

// standaloneEmergencyStopFence is the fence of a process that does not share
// the server's database handle: proxy and mcp serve.
type standaloneEmergencyStopFence struct {
	stops *kernel.ScopedStopStore
	scope emergencyStopScope
	db    *sql.DB
}

// openStandaloneEmergencyStopFence opens the server's fence store. As for
// serve, DATABASE_URL selects Postgres; without it the store is the Lite Mode
// database, <dataDir>/helm.db. It returns nil while the fence is off.
func openStandaloneEmergencyStopFence(ctx context.Context, dataDir string) (*standaloneEmergencyStopFence, error) {
	if !emergencyStopFenceEnabled() {
		return nil, nil
	}
	scope, err := configuredEmergencyStopScope()
	if err != nil {
		return nil, err
	}
	databaseMode := "sqlite"
	var db *sql.DB
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		databaseMode = "postgres"
		if err := validateRuntimePostgresURL(dbURL); err != nil {
			return nil, fmt.Errorf("invalid postgres DATABASE_URL: %w", err)
		}
		if db, err = sql.Open("postgres", dbURL); err != nil {
			return nil, fmt.Errorf("open emergency-stop fence database: %w", err)
		}
		configurePostgresPool(db)
	} else {
		path := filepath.Join(normalizedDataDir(dataDir), "helm.db")
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return nil, fmt.Errorf("create emergency-stop fence database directory: %w", err)
		}
		if db, err = sql.Open("sqlite", path); err != nil {
			return nil, fmt.Errorf("open emergency-stop fence database: %w", err)
		}
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("reach emergency-stop fence database: %w", err)
	}
	stops, err := openEmergencyStopStore(ctx, db, databaseMode)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &standaloneEmergencyStopFence{stops: stops, scope: scope, db: db}, nil
}

// guardianState is the stop state a Guardian built beside this fence reads.
func (f *standaloneEmergencyStopFence) guardianState(dataDir string) productionGuardianState {
	state := productionGuardianState{DataDir: dataDir}
	if f != nil {
		state.Stops = f.stops
	}
	return state
}

func (f *standaloneEmergencyStopFence) Close() error {
	if f == nil {
		return nil
	}
	return f.db.Close()
}
