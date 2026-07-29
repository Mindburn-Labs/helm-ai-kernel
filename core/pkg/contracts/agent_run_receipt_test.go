package contracts

import (
	"encoding/json"
	"testing"
)

func TestDenialCounterfactualMarshalRejectsAmbiguousShapes(t *testing.T) {
	zero, one := uint32(0), uint32(1)
	tests := []struct {
		name    string
		value   DenialCounterfactual
		wantErr bool
	}{
		{"scalar", DenialCounterfactual{Field: "limit", Requested: &one, Max: &zero}, false},
		{"capability", DenialCounterfactual{Field: "permission", Capability: "shell.operate"}, false},
		{"missing field", DenialCounterfactual{Capability: "shell.operate"}, true},
		{"field only", DenialCounterfactual{Field: "limit"}, true},
		{"requested only", DenialCounterfactual{Field: "limit", Requested: &one}, true},
		{"max only", DenialCounterfactual{Field: "limit", Max: &one}, true},
		{"mixed", DenialCounterfactual{Field: "limit", Requested: &one, Max: &zero, Capability: "shell.operate"}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := json.Marshal(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("json.Marshal() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
