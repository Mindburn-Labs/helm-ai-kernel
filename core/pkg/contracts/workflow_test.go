package contracts

import (
	"testing"
	"time"
)

func TestWorkflowLayersDiamond(t *testing.T) {
	workflow := WorkflowDef{
		ID: "diamond",
		Steps: []WorkflowStep{
			{StepID: "research", Type: StepTypeDecision},
			{
				StepID:        "build-a",
				Type:          StepTypeDecision,
				InputBindings: map[string]string{"research": "research"},
			},
			{
				StepID:        "build-b",
				Type:          StepTypeDecision,
				InputBindings: map[string]string{"research": "research"},
			},
			{
				StepID:        "verify",
				Type:          StepTypeVerification,
				DependsOn:     []string{"build-a", "build-b"},
				InputBindings: map[string]string{"candidate_a": "build-a", "candidate_b": "build-b"},
				Verification:  &Verification{Type: "COMPARE"},
			},
		},
	}

	layers, err := WorkflowLayers(workflow)
	if err != nil {
		t.Fatalf("WorkflowLayers: %v", err)
	}
	want := [][]string{{"research"}, {"build-a", "build-b"}, {"verify"}}
	if len(layers) != len(want) {
		t.Fatalf("got %d layers, want %d", len(layers), len(want))
	}
	for i := range want {
		if len(layers[i]) != len(want[i]) {
			t.Fatalf("layer %d has %d steps, want %d", i, len(layers[i]), len(want[i]))
		}
		for j := range want[i] {
			if layers[i][j].StepID != want[i][j] {
				t.Errorf("layer %d step %d = %q, want %q", i, j, layers[i][j].StepID, want[i][j])
			}
		}
	}
}

func TestWorkflowLayersLegacyWorkflowRemainsSequential(t *testing.T) {
	workflow := WorkflowDef{
		ID: "legacy",
		Steps: []WorkflowStep{
			{StepID: "one", Type: StepTypeDecision},
			{StepID: "two", Type: StepTypeWait},
			{StepID: "three", Type: StepTypeDecision},
		},
	}

	layers, err := WorkflowLayers(workflow)
	if err != nil {
		t.Fatalf("WorkflowLayers: %v", err)
	}
	for i, want := range []string{"one", "two", "three"} {
		if len(layers[i]) != 1 || layers[i][0].StepID != want {
			t.Errorf("layer %d = %#v, want only %q", i, layers[i], want)
		}
	}
}

func TestWorkflowValidationRejectsInvalidGraphs(t *testing.T) {
	valid := WorkflowDef{
		ID: "valid",
		Steps: []WorkflowStep{
			{StepID: "start", Type: StepTypeDecision},
			{StepID: "finish", Type: StepTypeDecision, DependsOn: []string{"start"}},
		},
	}

	tests := []struct {
		name   string
		mutate func(*WorkflowDef)
	}{
		{"missing workflow id", func(workflow *WorkflowDef) { workflow.ID = "" }},
		{"non-canonical workflow id", func(workflow *WorkflowDef) { workflow.ID = " valid" }},
		{"missing steps", func(workflow *WorkflowDef) { workflow.Steps = nil }},
		{"missing step id", func(workflow *WorkflowDef) { workflow.Steps[0].StepID = "" }},
		{"non-canonical step id", func(workflow *WorkflowDef) { workflow.Steps[0].StepID = " start" }},
		{"duplicate step id", func(workflow *WorkflowDef) { workflow.Steps[1].StepID = "start" }},
		{"unknown step type", func(workflow *WorkflowDef) { workflow.Steps[0].Type = "CLAUDE" }},
		{"negative timeout", func(workflow *WorkflowDef) { workflow.Steps[0].Timeout = -time.Second }},
		{"effect without effect", func(workflow *WorkflowDef) { workflow.Steps[0].Type = StepTypeEffect }},
		{"verification without verification", func(workflow *WorkflowDef) { workflow.Steps[0].Type = StepTypeVerification }},
		{"unknown dependency", func(workflow *WorkflowDef) { workflow.Steps[1].DependsOn = []string{"missing"} }},
		{"self dependency", func(workflow *WorkflowDef) { workflow.Steps[1].DependsOn = []string{"finish"} }},
		{"duplicate dependency", func(workflow *WorkflowDef) { workflow.Steps[1].DependsOn = []string{"start", "start"} }},
		{"empty dependency", func(workflow *WorkflowDef) { workflow.Steps[1].DependsOn = []string{""} }},
		{"non-canonical dependency", func(workflow *WorkflowDef) { workflow.Steps[1].DependsOn = []string{"start "} }},
		{"empty input name", func(workflow *WorkflowDef) { workflow.Steps[1].InputBindings = map[string]string{"": "start"} }},
		{"non-canonical input name", func(workflow *WorkflowDef) { workflow.Steps[1].InputBindings = map[string]string{" input": "start"} }},
		{"empty input source", func(workflow *WorkflowDef) { workflow.Steps[1].InputBindings = map[string]string{"input": ""} }},
		{"non-canonical input source", func(workflow *WorkflowDef) { workflow.Steps[1].InputBindings = map[string]string{"input": " start"} }},
		{"cycle", func(workflow *WorkflowDef) { workflow.Steps[0].DependsOn = []string{"finish"} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow := valid
			workflow.Steps = append([]WorkflowStep(nil), valid.Steps...)
			tt.mutate(&workflow)
			if err := workflow.Validate(); err == nil {
				t.Error("Validate accepted an invalid workflow")
			}
		})
	}
}
