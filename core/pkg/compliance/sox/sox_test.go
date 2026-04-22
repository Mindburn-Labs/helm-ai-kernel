package sox

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewSOXEngine(t *testing.T) {
	engine := NewSOXEngine()
	require.NotNil(t, engine)

	status := engine.GetStatus()
	require.Equal(t, 0, status["total_controls"])
}

func TestRegisterControl(t *testing.T) {
	engine := NewSOXEngine()
	ctx := context.Background()

	ctrl := &InternalControl{
		ID:            "ctrl-1",
		Name:          "Revenue Recognition Review",
		Type:          ControlDetective,
		Section:       "404",
		Process:       "Revenue",
		Owner:         "CFO",
		Description:   "Monthly revenue recognition review",
		Effectiveness: EffectivenessOperating,
		LastTested:    time.Now(),
		TestFrequency: "QUARTERLY",
		EvidenceRefs:  []string{"ev-001", "ev-002"},
	}

	err := engine.RegisterControl(ctx, ctrl)
	require.NoError(t, err)

	status := engine.GetStatus()
	require.Equal(t, 1, status["total_controls"])
	require.Equal(t, 0, status["material_weaknesses"])
}

func TestRegisterControl_EmptyName(t *testing.T) {
	engine := NewSOXEngine()
	err := engine.RegisterControl(context.Background(), &InternalControl{ID: "bad"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "control name")
}

func TestRegisterControl_MaterialWeakness(t *testing.T) {
	engine := NewSOXEngine()
	ctrl := &InternalControl{ID: "ctrl-2", Name: "Access Control", Effectiveness: EffectivenessWeakness}
	require.NoError(t, engine.RegisterControl(context.Background(), ctrl))

	status := engine.GetStatus()
	require.Equal(t, 1, status["material_weaknesses"])
}

func TestRegisterControl_Deficiency(t *testing.T) {
	engine := NewSOXEngine()
	_ = engine.RegisterControl(context.Background(), &InternalControl{
		ID: "c1", Name: "Control A", Effectiveness: EffectivenessDeficiency,
	})
	_ = engine.RegisterControl(context.Background(), &InternalControl{
		ID: "c2", Name: "Control B", Effectiveness: EffectivenessSignificant,
	})

	status := engine.GetStatus()
	require.Equal(t, 2, status["deficiencies"])
}

func TestRecordAuditEntry(t *testing.T) {
	engine := NewSOXEngine()

	entry := AuditTrail{
		ID:            "audit-1",
		Timestamp:     time.Now(),
		Actor:         "admin@example.com",
		Action:        "MODIFY",
		Resource:      "revenue_config",
		OldValue:      `{"threshold": 1000}`,
		NewValue:      `{"threshold": 5000}`,
		Justification: "Increased threshold per quarterly review",
	}

	engine.RecordAuditEntry(context.Background(), entry)

	status := engine.GetStatus()
	require.Equal(t, 1, status["audit_trail_entries"])
}

func TestCheckSoD_NoConflict(t *testing.T) {
	engine := NewSOXEngine()
	engine.AddSoDRule(DutySegregation{
		ID:          "sod-1",
		RoleA:       "approver",
		RoleB:       "requestor",
		Description: "Approver cannot be requestor",
		Enforced:    true,
	})

	require.True(t, engine.CheckSoD("approver", "auditor"))
	require.True(t, engine.CheckSoD("viewer", "requestor"))
}

func TestCheckSoD_Conflict(t *testing.T) {
	engine := NewSOXEngine()
	engine.AddSoDRule(DutySegregation{
		ID: "sod-1", RoleA: "approver", RoleB: "requestor", Enforced: true,
	})

	// Direct conflict
	require.False(t, engine.CheckSoD("approver", "requestor"))
	// Reverse conflict
	require.False(t, engine.CheckSoD("requestor", "approver"))
}

func TestCheckSoD_UnenforceRule(t *testing.T) {
	engine := NewSOXEngine()
	engine.AddSoDRule(DutySegregation{
		ID: "sod-1", RoleA: "approver", RoleB: "requestor", Enforced: false,
	})

	// Not enforced → no conflict
	require.True(t, engine.CheckSoD("approver", "requestor"))
}

func TestControlTypeConstants(t *testing.T) {
	require.Equal(t, ControlType("PREVENTIVE"), ControlPreventive)
	require.Equal(t, ControlType("DETECTIVE"), ControlDetective)
	require.Equal(t, ControlType("CORRECTIVE"), ControlCorrective)
}
