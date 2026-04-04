package contracts

import (
	"testing"
)

func TestDefaultEffectCatalog_Count(t *testing.T) {
	catalog := DefaultEffectCatalog()
	if len(catalog.EffectTypes) != 21 {
		t.Errorf("DefaultEffectCatalog: want 21 effect types, got %d", len(catalog.EffectTypes))
	}
}

func TestDefaultEffectCatalog_Version(t *testing.T) {
	catalog := DefaultEffectCatalog()
	if catalog.CatalogVersion == "" {
		t.Error("DefaultEffectCatalog: CatalogVersion must not be empty")
	}
}

func TestDefaultEffectCatalog_AllFieldsPopulated(t *testing.T) {
	catalog := DefaultEffectCatalog()
	for _, et := range catalog.EffectTypes {
		if et.TypeID == "" {
			t.Error("EffectType has empty TypeID")
		}
		if et.Name == "" {
			t.Errorf("EffectType %s has empty Name", et.TypeID)
		}
		if et.Description == "" {
			t.Errorf("EffectType %s has empty Description", et.TypeID)
		}
		if et.Classification.Reversibility == "" {
			t.Errorf("EffectType %s has empty Reversibility", et.TypeID)
		}
		if et.Classification.BlastRadius == "" {
			t.Errorf("EffectType %s has empty BlastRadius", et.TypeID)
		}
		if et.Classification.Urgency == "" {
			t.Errorf("EffectType %s has empty Urgency", et.TypeID)
		}
		if et.Idempotency.Strategy == "" {
			t.Errorf("EffectType %s has empty Idempotency.Strategy", et.TypeID)
		}
		if et.ReceiptSchema == "" {
			t.Errorf("EffectType %s has empty ReceiptSchema", et.TypeID)
		}
	}
}

func TestDefaultEffectCatalog_UniqueTypeIDs(t *testing.T) {
	catalog := DefaultEffectCatalog()
	seen := make(map[string]bool)
	for _, et := range catalog.EffectTypes {
		if seen[et.TypeID] {
			t.Errorf("duplicate TypeID: %s", et.TypeID)
		}
		seen[et.TypeID] = true
	}
}

func TestDefaultEffectCatalog_AllConstantsPresent(t *testing.T) {
	catalog := DefaultEffectCatalog()
	ids := make(map[string]bool)
	for _, et := range catalog.EffectTypes {
		ids[et.TypeID] = true
	}

	required := []string{
		EffectTypeInfraDestroy,
		EffectTypeEnvRecreate,
		EffectTypeProtectedInfraWrite,
		EffectTypeCICredentialAccess,
		EffectTypeSoftwarePublish,
		EffectTypeAgentInvokePrivileged,
		EffectTypeAgentIdentityIsolation,
		EffectTypeDataEgress,
		EffectTypeTunnelStart,
		EffectTypeCloudComputeBudget,
	}

	for _, r := range required {
		if !ids[r] {
			t.Errorf("required effect type %s not found in DefaultEffectCatalog", r)
		}
	}
}

func TestEffectRiskClass(t *testing.T) {
	tests := []struct {
		effectType string
		wantClass  string
	}{
		{EffectTypeInfraDestroy, "E4"},
		{EffectTypeCICredentialAccess, "E4"},
		{EffectTypeSoftwarePublish, "E4"},
		{EffectTypeDataEgress, "E4"},
		{EffectTypeProtectedInfraWrite, "E3"},
		{EffectTypeEnvRecreate, "E3"},
		{EffectTypeAgentInvokePrivileged, "E3"},
		{EffectTypeTunnelStart, "E3"},
		{EffectTypeCloudComputeBudget, "E2"},
		{EffectTypeAgentIdentityIsolation, "E1"},
		{"UNKNOWN_EFFECT", "E3"}, // fail-closed default
	}

	for _, tt := range tests {
		got := EffectRiskClass(tt.effectType)
		if got != tt.wantClass {
			t.Errorf("EffectRiskClass(%s) = %s, want %s", tt.effectType, got, tt.wantClass)
		}
	}
}

func TestLookupEffectType(t *testing.T) {
	et := LookupEffectType(EffectTypeInfraDestroy)
	if et == nil {
		t.Fatal("LookupEffectType(INFRA_DESTROY) returned nil")
	}
	if et.TypeID != EffectTypeInfraDestroy {
		t.Errorf("LookupEffectType returned wrong type: %s", et.TypeID)
	}
	if et.DefaultApprovalLevel != "dual_control" {
		t.Errorf("INFRA_DESTROY approval level = %s, want dual_control", et.DefaultApprovalLevel)
	}
}

func TestLookupEffectType_NotFound(t *testing.T) {
	et := LookupEffectType("NONEXISTENT")
	if et != nil {
		t.Error("LookupEffectType(NONEXISTENT) should return nil")
	}
}

func TestEffectRiskClass_E4EffectsRequireDualControl(t *testing.T) {
	e4Effects := []string{
		EffectTypeInfraDestroy,
		EffectTypeCICredentialAccess,
		EffectTypeSoftwarePublish,
		EffectTypeDataEgress,
	}
	for _, id := range e4Effects {
		et := LookupEffectType(id)
		if et == nil {
			t.Fatalf("E4 effect %s not found in catalog", id)
		}
		if et.DefaultApprovalLevel != "dual_control" {
			t.Errorf("E4 effect %s has approval level %s, want dual_control", id, et.DefaultApprovalLevel)
		}
		if !et.RequiresEvidence {
			t.Errorf("E4 effect %s must require evidence", id)
		}
	}
}
