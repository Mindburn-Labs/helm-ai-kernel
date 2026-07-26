package capability

import (
	"strings"
	"testing"
)

func validManifest() Manifest {
	return Manifest{
		SchemaVersion:       SchemaVersion,
		CapabilityID:        "helm.cap.gui.gelab.tap",
		Name:                "gelab-tap",
		Version:             "1.0.0",
		Protocol:            ProtocolGUIAction,
		Binding:             Binding{Kind: "gui_action_primitive", Ref: "tap"},
		EffectClass:         EffectWriteExternal,
		Reversibility:       ReversibilityCompensatingAction,
		DataBoundary:        BoundaryDevice,
		RiskScore:           40,
		RequiredPermitLevel: PermitNone,
		Rollback:            RollbackRequirement{Required: true, PlanRef: "plans/back.v1"},
		Receipts:            ReceiptRequirement{Required: true},
		MemoryAccess:        MemoryAccess{UserDomain: "none", AgentDomain: "write"},
	}
}

func TestManifestValidate_Valid(t *testing.T) {
	m := validManifest()
	if err := m.Validate(); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
}

func TestManifestValidate_Rejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Manifest)
		wantErr string
	}{
		{"bad schema version", func(m *Manifest) { m.SchemaVersion = "v0" }, "schema_version"},
		{"bad capability id", func(m *Manifest) { m.CapabilityID = "Cap.Tap" }, "capability_id"},
		{"missing name", func(m *Manifest) { m.Name = "" }, "name"},
		{"bad version", func(m *Manifest) { m.Version = "1.0" }, "version"},
		{"bad protocol", func(m *Manifest) { m.Protocol = "carrier-pigeon" }, "protocol"},
		{"missing binding ref", func(m *Manifest) { m.Binding.Ref = "" }, "binding"},
		{"bad effect class", func(m *Manifest) { m.EffectClass = "vibes" }, "effect_class"},
		{"bad reversibility", func(m *Manifest) { m.Reversibility = "maybe" }, "reversibility"},
		{"bad boundary", func(m *Manifest) { m.DataBoundary = "wherever" }, "data_boundary"},
		{"risk score high", func(m *Manifest) { m.RiskScore = 101 }, "risk_score"},
		{"risk score negative", func(m *Manifest) { m.RiskScore = -1 }, "risk_score"},
		{"bad permit level", func(m *Manifest) { m.RequiredPermitLevel = "yolo" }, "required_permit_level"},
		{"missing rollback plan", func(m *Manifest) { m.Rollback.PlanRef = "" }, "rollback.plan_ref"},
		{"receipts not required", func(m *Manifest) { m.Receipts.Required = false }, "receipts.required"},
		{"bad memory grant", func(m *Manifest) { m.MemoryAccess.UserDomain = "everything" }, "memory_access"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest()
			tc.mutate(&m)
			err := m.Validate()
			if err == nil {
				t.Fatalf("expected validation error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestManifestValidate_RollbackPlanNotRequiredForReadOnly(t *testing.T) {
	m := validManifest()
	m.EffectClass = EffectReadOnly
	m.Rollback = RollbackRequirement{Required: false}
	if err := m.Validate(); err != nil {
		t.Fatalf("read-only reversible capability should not need a rollback plan: %v", err)
	}
}

func TestManifestValidate_RollbackPlanNotRequiredForIrreversible(t *testing.T) {
	m := validManifest()
	m.Reversibility = ReversibilityNone
	m.EffectClass = EffectIrreversible
	m.Rollback = RollbackRequirement{Required: false}
	if err := m.Validate(); err != nil {
		t.Fatalf("irreversible capability has no rollback plan requirement: %v", err)
	}
}
