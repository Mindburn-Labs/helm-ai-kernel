package celcheck

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestValidateProductionPolicyPacks validates all HELM CEL policy packs.
// This test ensures that every .cel file in policies/packs/ is valid CEL.
func TestValidateProductionPolicyPacks(t *testing.T) {
	// Find policy packs directory by walking up from test source location.
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file location")
	}

	// Walk up from core/pkg/celcheck/ to repo root.
	dir := filepath.Dir(testFile)
	policyDir := ""
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "policies", "packs")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			policyDir = candidate
			break
		}
		dir = filepath.Dir(dir)
	}
	if policyDir == "" {
		t.Skip("policies/packs directory not found; skipping production validation")
	}

	results, err := ValidateDirectory(policyDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) == 0 {
		t.Fatal("no .cel files found in policy packs")
	}

	t.Logf("Validated %d CEL policy files", len(results))
	for _, r := range results {
		t.Run(filepath.Base(filepath.Dir(r.File))+"/"+filepath.Base(r.File), func(t *testing.T) {
			t.Logf("  File: %s — %d rules", r.File, r.Rules)
			if !r.Valid {
				for _, e := range r.Errors {
					t.Errorf("  ERROR: %s", e)
				}
			} else if len(r.Errors) > 0 {
				for _, e := range r.Errors {
					t.Logf("  WARNING: %s", e)
				}
			}
		})
	}
}
