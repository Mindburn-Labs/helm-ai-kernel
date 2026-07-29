package contracts

import (
	"encoding/json"
	"testing"
)

func TestDenialCounterfactualMarshalRejectsAmbiguousShapes(t *testing.T) {
	tests := []struct {
		name     string
		value    DenialCounterfactual
		wantJSON string
	}{
		{"scalar with zero max", DenialCounterfactual{Field: "limit", Requested: 1}, `{"field":"limit","requested":1,"max":0}`},
		{"scalar with zero request", DenialCounterfactual{Field: "limit", Max: 1}, `{"field":"limit","requested":0,"max":1}`},
		{"zero scalar", DenialCounterfactual{Field: "limit"}, `{"field":"limit","requested":0,"max":0}`},
		{"capability", DenialCounterfactual{Field: "permission", Capability: "shell.operate"}, `{"field":"permission","capability":"shell.operate"}`},
		{"missing field", DenialCounterfactual{Capability: "shell.operate"}, ""},
		{"mixed", DenialCounterfactual{Field: "limit", Requested: 1, Capability: "shell.operate"}, ""},
		{"unknown capability", DenialCounterfactual{Field: "permission", Capability: "attacker.chosen"}, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := json.Marshal(test.value)
			if test.wantJSON == "" {
				if err == nil {
					t.Fatalf("json.Marshal() = %s, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if string(got) != test.wantJSON {
				t.Fatalf("json.Marshal() = %s, want %s", got, test.wantJSON)
			}
		})
	}
}
