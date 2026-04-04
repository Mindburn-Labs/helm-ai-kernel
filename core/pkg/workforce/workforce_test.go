package workforce_test

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/workforce"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validEmployee(id string) *workforce.VirtualEmployee {
	return &workforce.VirtualEmployee{
		EmployeeID: id,
		Name:       "Test Agent " + id,
		ManagerID:  "mgr-1",
		RoleID:     "role-analyst",
		ToolScope: workforce.ToolScope{
			AllowedTools: []string{"web_search", "read_file"},
			MaxRiskClass: "R2",
		},
		BudgetEnvelope: workforce.BudgetEnvelope{
			TenantID:        "tenant-1",
			DailyCentsCap:   5000,
			MonthlyCentsCap: 100000,
			ToolCallCap:     1000,
		},
		ExecutionMode: workforce.ModeSupervised,
		CreatedAt:     time.Now().UTC(),
	}
}

func TestCreate_RequiresManagerID(t *testing.T) {
	registry := workforce.NewInMemoryRegistry()
	lm := workforce.NewLifecycleManager(registry)
	ctx := context.Background()

	emp := validEmployee("emp-1")
	emp.ManagerID = ""

	err := lm.Create(ctx, emp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "manager_id")
}

func TestCreate_RequiresBudgetEnvelope(t *testing.T) {
	registry := workforce.NewInMemoryRegistry()
	lm := workforce.NewLifecycleManager(registry)
	ctx := context.Background()

	emp := validEmployee("emp-1")
	emp.BudgetEnvelope.DailyCentsCap = 0

	err := lm.Create(ctx, emp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "daily_cents_cap")
}

func TestCreate_ValidEmployee(t *testing.T) {
	registry := workforce.NewInMemoryRegistry()
	lm := workforce.NewLifecycleManager(registry)
	ctx := context.Background()

	emp := validEmployee("emp-1")
	err := lm.Create(ctx, emp)
	require.NoError(t, err)

	got, err := registry.Get(ctx, "emp-1")
	require.NoError(t, err)
	assert.Equal(t, "ACTIVE", got.Status)
	assert.Equal(t, "mgr-1", got.ManagerID)
}

func TestSuspendAndResume(t *testing.T) {
	registry := workforce.NewInMemoryRegistry()
	lm := workforce.NewLifecycleManager(registry)
	ctx := context.Background()

	require.NoError(t, lm.Create(ctx, validEmployee("emp-1")))

	// Suspend.
	err := lm.Suspend(ctx, "emp-1")
	require.NoError(t, err)

	got, err := registry.Get(ctx, "emp-1")
	require.NoError(t, err)
	assert.Equal(t, "SUSPENDED", got.Status)

	// Resume.
	err = lm.Resume(ctx, "emp-1")
	require.NoError(t, err)

	got, err = registry.Get(ctx, "emp-1")
	require.NoError(t, err)
	assert.Equal(t, "ACTIVE", got.Status)
}

func TestTerminate_IsPermanent(t *testing.T) {
	registry := workforce.NewInMemoryRegistry()
	lm := workforce.NewLifecycleManager(registry)
	ctx := context.Background()

	require.NoError(t, lm.Create(ctx, validEmployee("emp-1")))

	// Terminate.
	err := lm.Terminate(ctx, "emp-1")
	require.NoError(t, err)

	got, err := registry.Get(ctx, "emp-1")
	require.NoError(t, err)
	assert.Equal(t, "TERMINATED", got.Status)

	// Cannot resume from TERMINATED.
	err = lm.Resume(ctx, "emp-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SUSPENDED")
}

func TestKillSwitch_IsSuspend(t *testing.T) {
	registry := workforce.NewInMemoryRegistry()
	lm := workforce.NewLifecycleManager(registry)
	ctx := context.Background()

	require.NoError(t, lm.Create(ctx, validEmployee("emp-1")))

	// Kill switch = Suspend.
	err := lm.Suspend(ctx, "emp-1")
	require.NoError(t, err)

	got, err := registry.Get(ctx, "emp-1")
	require.NoError(t, err)
	assert.Equal(t, "SUSPENDED", got.Status)
}

func TestRegistry_CRUD(t *testing.T) {
	registry := workforce.NewInMemoryRegistry()
	ctx := context.Background()

	// Create.
	emp := validEmployee("emp-1")
	emp.Status = "ACTIVE"
	require.NoError(t, registry.Create(ctx, emp))

	// Get.
	got, err := registry.Get(ctx, "emp-1")
	require.NoError(t, err)
	assert.Equal(t, "emp-1", got.EmployeeID)
	assert.Equal(t, "ACTIVE", got.Status)

	// List.
	all, err := registry.List(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 1)

	// Update.
	got.Name = "Updated Agent"
	require.NoError(t, registry.Update(ctx, got))

	updated, err := registry.Get(ctx, "emp-1")
	require.NoError(t, err)
	assert.Equal(t, "Updated Agent", updated.Name)

	// Get not found.
	_, err = registry.Get(ctx, "nonexistent")
	assert.Error(t, err)
}

func TestToolScope_AllowedTools(t *testing.T) {
	emp := validEmployee("emp-1")
	emp.ToolScope = workforce.ToolScope{
		AllowedTools: []string{"web_search", "read_file", "write_file"},
		BlockedTools: []string{"delete_file"},
		MaxRiskClass: "R2",
	}

	// Verify allowed tools are set.
	assert.Contains(t, emp.ToolScope.AllowedTools, "web_search")
	assert.Contains(t, emp.ToolScope.AllowedTools, "read_file")
	assert.Contains(t, emp.ToolScope.AllowedTools, "write_file")
	assert.NotContains(t, emp.ToolScope.AllowedTools, "delete_file")

	// Verify blocked tools.
	assert.Contains(t, emp.ToolScope.BlockedTools, "delete_file")
	assert.Equal(t, "R2", emp.ToolScope.MaxRiskClass)
}
