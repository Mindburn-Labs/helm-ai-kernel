package conformance

import "testing"

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
