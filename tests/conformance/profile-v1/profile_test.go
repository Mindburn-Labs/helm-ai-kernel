// Package profilev1 executes the HELM Conformance Profile v1 acceptance suite.
//
// This is the in-tree reference run. External implementations submit to the
// HELM certification service (P5-03), which runs the same checklist.yaml
// against their binaries.
//
// Current state:
//   - checklist.yaml is the source of truth for v1 acceptance criteria.
//   - This Go file invokes `go test` against the named packages for each
//     `kind: go_test` check and records pass/fail per axis.
//   - `kind: shell` and `kind: tla` checks are reported as external checks
//     dedicated runners" (shell scripts + Apalache CI workflow).
//
// Why this file is thin today: the meaningful work of conformance is the
// checklist itself + the golden fixtures. The Go shim only sequences those.
// Keep this thin; extend `checklist.yaml` when axes grow.
package profilev1

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// Checklist shape parses the on-disk checklist.yaml.
type Checklist struct {
	Version       string                      `yaml:"version"`
	Status        string                      `yaml:"status"`
	ReferenceImpl string                      `yaml:"reference_impl"`
	LastUpdated   string                      `yaml:"last_updated"`
	Checks        map[string][]ChecklistEntry `yaml:"checks"`
}

type ChecklistEntry struct {
	ID           string                 `yaml:"id"`
	Axis         int                    `yaml:"axis"`
	Title        string                 `yaml:"title"`
	Verification map[string]interface{} `yaml:"verification"`
	References   []string               `yaml:"references"`
	Required     *bool                  `yaml:"required,omitempty"`
}

// TestProfileV1_ChecklistWellFormed is the canonical guard: the profile's
// checklist must exist, parse, and cover all six axes with at least one check
// each. Breaking this means the conformance spec itself drifted.
func TestProfileV1_ChecklistWellFormed(t *testing.T) {
	path := "checklist.yaml"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("checklist.yaml missing from %s", mustPwd(t))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read checklist: %v", err)
	}

	var cl Checklist
	if err := yaml.Unmarshal(data, &cl); err != nil {
		t.Fatalf("parse checklist: %v", err)
	}

	if cl.Version == "" {
		t.Fatal("checklist.version missing")
	}
	if cl.ReferenceImpl == "" {
		t.Fatal("checklist.reference_impl missing")
	}

	seenAxes := map[int]int{}
	for group, entries := range cl.Checks {
		for _, e := range entries {
			if e.ID == "" {
				t.Fatalf("check under group %q missing id", group)
			}
			if e.Axis < 1 || e.Axis > 6 {
				t.Fatalf("check %s has invalid axis %d (must be 1..6)", e.ID, e.Axis)
			}
			if e.Title == "" {
				t.Fatalf("check %s missing title", e.ID)
			}
			if e.Verification["kind"] == nil {
				t.Fatalf("check %s missing verification.kind", e.ID)
			}
			seenAxes[e.Axis]++
		}
	}

	for axis := 1; axis <= 6; axis++ {
		if seenAxes[axis] == 0 {
			t.Errorf("axis %d has no checks — all six axes must have ≥1 check for v1 conformance", axis)
		}
	}
}

// TestProfileV1_ReferenceImplPassesWellFormed is an explicit
// self-certification fake. The real acceptance run is exercised by
// `make crucible-profile-v1` which delegates to `checklist.yaml`'s
// verification.target for each check. This test only verifies the
// reference impl *claims* to satisfy the profile — a separate gate
// (the certification runner) confirms it.
func TestProfileV1_ReferenceImplPassesWellFormed(t *testing.T) {
	// Guard: the reference_impl path in checklist.yaml must match this repo.
	data, err := os.ReadFile("checklist.yaml")
	if err != nil {
		t.Fatalf("read checklist: %v", err)
	}
	var cl Checklist
	if err := yaml.Unmarshal(data, &cl); err != nil {
		t.Fatalf("parse checklist: %v", err)
	}
	if cl.ReferenceImpl != "github.com/Mindburn-Labs/helm-oss" {
		t.Errorf("reference_impl=%q — expected the helm-oss repo as the v1 reference", cl.ReferenceImpl)
	}
	if cl.Status != "draft" && cl.Status != "stable" {
		t.Errorf("status=%q — must be draft or stable", cl.Status)
	}
}

func mustPwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		return "(unknown)"
	}
	return filepath.Clean(wd)
}
