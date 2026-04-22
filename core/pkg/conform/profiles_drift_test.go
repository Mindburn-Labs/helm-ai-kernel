package conform_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// profilesJSON mirrors the structure of profiles.json
type profilesJSON struct {
	Version  string                    `json:"version"`
	Profiles map[string]profileDefJSON `json:"profiles"`
}

type profileDefJSON struct {
	ID            string         `json:"id"`
	RequiredGates []string       `json:"required_gates"`
	Overrides     map[string]any `json:"overrides,omitempty"`
}

// TestProfilesDrift asserts that Go profile definitions stay in sync
// with the canonical profiles.json used by the TypeScript CLI.
//
// If this test fails, either:
//   - profiles.json was updated without updating profile.go, or
//   - profile.go was updated without updating profiles.json.
//
// Fix: update both sources to match, then re-run.
func TestProfilesDrift(t *testing.T) {
	// Locate profiles.json relative to this file
	// This test lives at core/pkg/conform/ — project root is 3 levels up
	_, thisFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	profilesPath := filepath.Join(projectRoot, "packages", "mindburn-helm-cli", "src", "profiles.json")

	data, err := os.ReadFile(profilesPath)
	if err != nil {
		t.Skipf("profiles.json not found at %s (expected in monorepo layout): %v", profilesPath, err)
	}

	var canonical profilesJSON
	if err := json.Unmarshal(data, &canonical); err != nil {
		t.Fatalf("cannot parse profiles.json: %v", err)
	}

	goProfiles := conform.Profiles()

	// Check every profile in profiles.json exists in Go
	for name, jsonDef := range canonical.Profiles {
		pid := conform.ProfileID(name)
		goDef, ok := goProfiles[pid]
		if !ok {
			t.Errorf("profile %q exists in profiles.json but not in Go Profiles()", name)
			continue
		}

		// Compare required gates (order-independent)
		jsonGates := sorted(jsonDef.RequiredGates)
		goGates := sorted(goDef.RequiredGates)

		if len(jsonGates) != len(goGates) {
			t.Errorf("profile %q: gate count mismatch — JSON=%d, Go=%d\n  JSON: %v\n  Go:   %v",
				name, len(jsonGates), len(goGates), jsonGates, goGates)
			continue
		}

		for i := range jsonGates {
			if jsonGates[i] != goGates[i] {
				t.Errorf("profile %q: gate mismatch at index %d — JSON=%q, Go=%q\n  JSON: %v\n  Go:   %v",
					name, i, jsonGates[i], goGates[i], jsonGates, goGates)
				break
			}
		}
	}

	// Check every profile in Go exists in profiles.json
	for pid := range goProfiles {
		if _, ok := canonical.Profiles[string(pid)]; !ok {
			t.Errorf("profile %q exists in Go Profiles() but not in profiles.json", pid)
		}
	}
}

func sorted(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}
