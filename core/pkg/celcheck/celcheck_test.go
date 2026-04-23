package celcheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateFile_ValidCEL(t *testing.T) {
	// Create a temporary CEL file with valid compound expression.
	dir := t.TempDir()
	celFile := filepath.Join(dir, "test.cel")
	content := `// Test CEL policy pack

// Rule 1: deny dangerous effects
effect_level != "E4"

// Rule 2: require delegation for E3
&& !(effect_level == "E3" && delegation_depth == 0)

// Rule 3: budget check
&& budget_remaining > 0
`
	if err := os.WriteFile(celFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result := ValidateFile(celFile)
	if !result.Valid {
		t.Errorf("expected valid, got errors: %v", result.Errors)
	}
	if result.Rules < 2 {
		t.Errorf("expected at least 2 clauses, got %d", result.Rules)
	}
}

func TestValidateFile_InvalidCEL(t *testing.T) {
	dir := t.TempDir()
	celFile := filepath.Join(dir, "bad.cel")
	content := `// Bad CEL expression
effect_level ==== "E4"
`
	if err := os.WriteFile(celFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result := ValidateFile(celFile)
	if result.Valid {
		t.Error("expected invalid for broken CEL syntax")
	}
	if len(result.Errors) == 0 {
		t.Error("expected parse errors")
	}
}

func TestValidateFile_Missing(t *testing.T) {
	result := ValidateFile("/nonexistent/path.cel")
	if result.Valid {
		t.Error("expected invalid for missing file")
	}
}

func TestValidateDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.cel", "b.cel"} {
		content := `effect_level == "E4" && agent_id != ""`
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	results, err := ValidateDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if !r.Valid {
			t.Errorf("expected valid for %s, got errors: %v", r.File, r.Errors)
		}
	}
}

func TestValidateFile_MultiLine(t *testing.T) {
	dir := t.TempDir()
	celFile := filepath.Join(dir, "multiline.cel")
	content := `// Multi-line compound expression
!(effect == "E4"
  && !has(context.approval))

// Second clause  
&& !(tool == "delete"
  && delegation_depth > 3)
`
	if err := os.WriteFile(celFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result := ValidateFile(celFile)
	if !result.Valid {
		t.Errorf("expected valid multi-line, got errors: %v", result.Errors)
	}
}
