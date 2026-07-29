package contracts

import (
	"encoding/json"
	"testing"
)

func TestDenialCounterfactualMarshalRejectsIncompleteShapes(t *testing.T) {
	tests := []struct {
		name     string
		value    DenialCounterfactual
		wantJSON string
	}{
		{"scalar", DenialCounterfactual{Field: "limit", Requested: 2, Max: 1}, `{"field":"limit","requested":2,"max":1}`},
		{"scalar with zero max", DenialCounterfactual{Field: "limit", Requested: 1}, ""},
		{"scalar with zero request", DenialCounterfactual{Field: "limit", Max: 1}, ""},
		{"zero scalar", DenialCounterfactual{Field: "limit"}, ""},
		{"scalar within bound", DenialCounterfactual{Field: "limit", Requested: 1, Max: 2}, ""},
		{"scalar at bound", DenialCounterfactual{Field: "limit", Requested: 1, Max: 1}, ""},
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

func TestDenialCounterfactualUnmarshalRejectsAmbiguousShapes(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"scalar", `{"field":"limit","requested":2,"max":1}`, false},
		{"zero scalar", `{"field":"limit","requested":0,"max":0}`, true},
		{"scalar within bound", `{"field":"limit","requested":1,"max":2}`, true},
		{"scalar at bound", `{"field":"limit","requested":1,"max":1}`, true},
		{"capability", `{"field":"permission","capability":"shell.operate"}`, false},
		{"field only", `{"field":"limit"}`, true},
		{"zero valued mixed", `{"field":"permission","capability":"shell.operate","requested":0}`, true},
		{"partial scalar", `{"field":"limit","requested":0}`, true},
		{"unknown capability", `{"field":"permission","capability":"attacker.chosen"}`, true},
		{"unknown field", `{"field":"limit","requested":0,"max":0,"extra":true}`, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got DenialCounterfactual
			err := json.Unmarshal([]byte(test.raw), &got)
			if test.wantErr {
				if err == nil {
					t.Fatalf("json.Unmarshal() = %+v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			reencoded, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			if string(reencoded) != test.raw {
				t.Fatalf("round trip = %s, want %s", reencoded, test.raw)
			}
		})
	}
}
