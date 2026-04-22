package sox

import (
	"context"
	"testing"
	"time"
)

func TestSOXEngine_InitEmpty(t *testing.T) {
	engine := NewSOXEngine()
	if engine == nil {
		t.Fatal("engine should not be nil")
	}
	status := engine.GetStatus()
	if status["total_controls"].(int) != 0 {
		t.Error("new engine should have 0 controls")
	}
}

func TestRegisterControl_ValidControl(t *testing.T) {
	engine := NewSOXEngine()
	err := engine.RegisterControl(context.Background(), &InternalControl{
		ID: "ctrl-1", Name: "Revenue Recognition", Type: ControlPreventive, Section: "404",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegisterControl_EmptyNameReturnsError(t *testing.T) {
	engine := NewSOXEngine()
	err := engine.RegisterControl(context.Background(), &InternalControl{ID: "ctrl-1"})
	if err == nil {
		t.Error("expected error for missing name")
	}
}

func TestRecordAuditEntry_StoresEntry(t *testing.T) {
	engine := NewSOXEngine()
	engine.RecordAuditEntry(context.Background(), AuditTrail{
		ID: "audit-1", Actor: "admin", Action: "modify", Resource: "ledger",
	})
	status := engine.GetStatus()
	if status["audit_trail_entries"].(int) != 1 {
		t.Error("expected 1 audit trail entry")
	}
}

func TestCheckSoD_NoRulesNoConflict(t *testing.T) {
	engine := NewSOXEngine()
	if !engine.CheckSoD("approver", "initiator") {
		t.Error("should return true when no SoD rules exist")
	}
}

func TestCheckSoD_DetectsConflict(t *testing.T) {
	engine := NewSOXEngine()
	engine.AddSoDRule(DutySegregation{
		ID: "sod-1", RoleA: "approver", RoleB: "initiator", Enforced: true,
	})
	if engine.CheckSoD("approver", "initiator") {
		t.Error("should detect SoD conflict")
	}
}

func TestCheckSoD_ConflictReversed(t *testing.T) {
	engine := NewSOXEngine()
	engine.AddSoDRule(DutySegregation{
		ID: "sod-1", RoleA: "approver", RoleB: "initiator", Enforced: true,
	})
	if engine.CheckSoD("initiator", "approver") {
		t.Error("should detect SoD conflict in reverse order")
	}
}

func TestCheckSoD_NotEnforced(t *testing.T) {
	engine := NewSOXEngine()
	engine.AddSoDRule(DutySegregation{
		ID: "sod-1", RoleA: "approver", RoleB: "initiator", Enforced: false,
	})
	if !engine.CheckSoD("approver", "initiator") {
		t.Error("unenforced rule should not cause conflict")
	}
}

func TestGetStatus_MaterialWeaknesses(t *testing.T) {
	engine := NewSOXEngine()
	engine.RegisterControl(context.Background(), &InternalControl{
		ID: "c1", Name: "Weak Control", Effectiveness: EffectivenessWeakness,
	})
	status := engine.GetStatus()
	if status["material_weaknesses"].(int) != 1 {
		t.Error("expected 1 material weakness")
	}
}

func TestGetStatus_Deficiencies(t *testing.T) {
	engine := NewSOXEngine()
	ctx := context.Background()
	engine.RegisterControl(ctx, &InternalControl{
		ID: "c1", Name: "Deficient", Effectiveness: EffectivenessDeficiency,
	})
	engine.RegisterControl(ctx, &InternalControl{
		ID: "c2", Name: "Significant", Effectiveness: EffectivenessSignificant,
	})
	status := engine.GetStatus()
	if status["deficiencies"].(int) != 2 {
		t.Errorf("expected 2 deficiencies, got %d", status["deficiencies"].(int))
	}
}

func TestGetStatus_OperatingEffectively(t *testing.T) {
	engine := NewSOXEngine()
	engine.RegisterControl(context.Background(), &InternalControl{
		ID: "c1", Name: "Good Control", Effectiveness: EffectivenessOperating,
	})
	status := engine.GetStatus()
	if status["material_weaknesses"].(int) != 0 {
		t.Error("operating control should not be a weakness")
	}
}

func TestGetStatus_SoDRulesCount(t *testing.T) {
	engine := NewSOXEngine()
	engine.AddSoDRule(DutySegregation{ID: "s1", RoleA: "a", RoleB: "b", Enforced: true})
	engine.AddSoDRule(DutySegregation{ID: "s2", RoleA: "c", RoleB: "d", Enforced: true})
	status := engine.GetStatus()
	if status["sod_rules"].(int) != 2 {
		t.Errorf("expected 2 SoD rules, got %d", status["sod_rules"].(int))
	}
}

func TestControlType_AllUnique(t *testing.T) {
	types := []ControlType{ControlPreventive, ControlDetective, ControlCorrective}
	seen := make(map[ControlType]bool)
	for _, ct := range types {
		if seen[ct] {
			t.Errorf("duplicate control type: %s", ct)
		}
		seen[ct] = true
	}
}

func TestAuditTrailFields(t *testing.T) {
	engine := NewSOXEngine()
	ts := time.Now()
	engine.RecordAuditEntry(context.Background(), AuditTrail{
		ID: "a1", Timestamp: ts, Actor: "user1",
		Action: "update", Resource: "account", OldValue: "100", NewValue: "200",
		Justification: "correction",
	})
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	entry := engine.auditTrail[0]
	if entry.OldValue != "100" || entry.NewValue != "200" {
		t.Error("audit trail should preserve old/new values")
	}
}
