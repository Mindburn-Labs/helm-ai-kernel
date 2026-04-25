package conform_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
	"gopkg.in/yaml.v3"
)

type checklistYAML struct {
	Version string                          `yaml:"version"`
	Checks  map[string][]checklistCheckYAML `yaml:"checks"`
}

type checklistCheckYAML struct {
	ID       string `yaml:"id"`
	Required bool   `yaml:"required"`
}

// TestConformanceProfileChecklist verifies the retained conformance checklist
// remains parseable after removing the Node CLI profile manifest.
func TestConformanceProfileChecklist(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	checklistPath := filepath.Join(projectRoot, "tests", "conformance", "profile-v1", "checklist.yaml")

	data, err := os.ReadFile(checklistPath)
	if err != nil {
		t.Fatalf("read conformance checklist: %v", err)
	}

	var checklist checklistYAML
	if err := yaml.Unmarshal(data, &checklist); err != nil {
		t.Fatalf("parse conformance checklist: %v", err)
	}
	if checklist.Version == "" {
		t.Fatal("conformance checklist missing version")
	}

	requiredChecks := 0
	for group, checks := range checklist.Checks {
		if len(checks) == 0 {
			t.Fatalf("check group %q is empty", group)
		}
		for _, check := range checks {
			if check.ID == "" {
				t.Fatalf("check group %q has check without id", group)
			}
			if check.Required {
				requiredChecks++
			}
		}
	}
	if requiredChecks == 0 {
		t.Fatal("conformance checklist has no required checks")
	}

	for id, profile := range conform.Profiles() {
		if profile.ID != id {
			t.Fatalf("profile key %q does not match definition id %q", id, profile.ID)
		}
		if len(profile.RequiredGates) == 0 {
			t.Fatalf("profile %q has no required gates", id)
		}
	}
}
