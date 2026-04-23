package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultEffectCatalog_ReceiptSchemasExistAndMatchCatalog(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))

	catalog := DefaultEffectCatalog()
	for _, effect := range catalog.EffectTypes {
		schemaPath := filepath.Join(repoRoot, "protocols", "json-schemas", filepath.FromSlash(effect.ReceiptSchema))
		data, err := os.ReadFile(schemaPath)
		if err != nil {
			t.Fatalf("schema missing for %s at %s: %v", effect.TypeID, schemaPath, err)
		}

		var schema map[string]any
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatalf("schema for %s is invalid JSON: %v", effect.TypeID, err)
		}

		properties, ok := schema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("schema for %s missing properties object", effect.TypeID)
		}
		effectID, ok := properties["effect_id"].(map[string]any)
		if !ok {
			t.Fatalf("schema for %s missing effect_id property", effect.TypeID)
		}
		if effectID["const"] != effect.TypeID {
			t.Fatalf("schema for %s const = %v, want %s", effect.TypeID, effectID["const"], effect.TypeID)
		}

		xHelm, ok := schema["x-helm"].(map[string]any)
		if !ok {
			t.Fatalf("schema for %s missing x-helm metadata", effect.TypeID)
		}
		if xHelm["risk_class"] != EffectRiskClass(effect.TypeID) {
			t.Fatalf("schema risk_class for %s = %v, want %s", effect.TypeID, xHelm["risk_class"], EffectRiskClass(effect.TypeID))
		}
		if xHelm["approval_level"] != effect.DefaultApprovalLevel {
			t.Fatalf("schema approval_level for %s = %v, want %s", effect.TypeID, xHelm["approval_level"], effect.DefaultApprovalLevel)
		}
	}
}
