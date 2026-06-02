package conformance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTONActonGoldenValidationLoadsCases(t *testing.T) {
	ctx := &TestContext{Level: LevelL3, Category: "ton-acton"}

	if err := validateTONActonGoldenPacks(ctx); err != nil {
		t.Fatalf("validate TON Acton golden packs returned error: %v", err)
	}
	if ctx.Failed() {
		t.Fatalf("TON Acton validation recorded failures: %+v", ctx.Errors)
	}

	cases := loadTONActonGoldenCases(ctx)
	if len(cases) < 22 {
		t.Fatalf("expected at least 22 cases, got %d", len(cases))
	}
	if _, ok := cases["build_ok"]; !ok {
		t.Fatalf("build_ok case missing from loaded cases")
	}

	root, err := tonActonGoldenRoot()
	if err != nil || root == "" {
		t.Fatalf("tonActonGoldenRoot = %q, %v", root, err)
	}
}

func TestTONActonGoldenLoaderErrorBranches(t *testing.T) {
	missingRootCtx := &TestContext{}
	if cases := loadTONActonGoldenCasesFromRoot(missingRootCtx, filepath.Join(t.TempDir(), "missing")); cases != nil {
		t.Fatalf("missing root returned cases: %+v", cases)
	}
	if !missingRootCtx.Failed() || !strings.Contains(missingRootCtx.Errors[0], "read TON Acton golden root") {
		t.Fatalf("missing root errors = %+v, want read-root failure", missingRootCtx.Errors)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.txt"), []byte("ignored"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "missing_case_file"), 0o755); err != nil {
		t.Fatal(err)
	}
	badJSONDir := filepath.Join(root, "bad_json")
	if err := os.Mkdir(badJSONDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badJSONDir, "case.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	malformedDir := filepath.Join(root, "malformed_case")
	if err := os.Mkdir(malformedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(malformedDir, "case.json"), []byte(`{"case_id":"other_case"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := &TestContext{}
	cases := loadTONActonGoldenCasesFromRoot(ctx, root)
	if cases["other_case"] != "" {
		t.Fatalf("malformed case reason = %q, want empty reason code", cases["other_case"])
	}
	for _, want := range []string{
		"read missing_case_file",
		"decode bad_json",
		"malformed_case case_id mismatch",
		"malformed_case missing action_urn",
		"malformed_case missing expected_verdict or expected_status",
	} {
		if !hasTONActonError(ctx.Errors, want) {
			t.Fatalf("loader errors missing %q: %+v", want, ctx.Errors)
		}
	}

	countCtx := &TestContext{}
	validateTONActonGoldenCaseCount(countCtx, map[string]string{"one": ""})
	if !countCtx.Failed() || !strings.Contains(countCtx.Errors[0], "expected at least 22") {
		t.Fatalf("count validation errors = %+v, want count failure", countCtx.Errors)
	}
}

func TestTONActonGoldenRootResolutionFailure(t *testing.T) {
	previous := tonActonRuntimeCaller
	tonActonRuntimeCaller = func(int) (uintptr, string, int, bool) {
		return 0, "", 0, false
	}
	t.Cleanup(func() {
		tonActonRuntimeCaller = previous
	})

	if root, err := tonActonGoldenRoot(); err == nil || root != "" {
		t.Fatalf("tonActonGoldenRoot() = %q, %v, want empty root and error", root, err)
	}

	ctx := &TestContext{}
	if cases := loadTONActonGoldenCases(ctx); cases != nil {
		t.Fatalf("loadTONActonGoldenCases with unresolved root = %+v, want nil", cases)
	}
	if !ctx.Failed() || !strings.Contains(ctx.Errors[0], "cannot resolve conformance source path") {
		t.Fatalf("root resolution errors = %+v", ctx.Errors)
	}
}

func hasTONActonError(errors []string, want string) bool {
	for _, err := range errors {
		if strings.Contains(err, want) {
			return true
		}
	}
	return false
}
