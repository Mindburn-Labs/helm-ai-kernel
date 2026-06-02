package suites

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

func TestRegisterDOMTrapSuite(t *testing.T) {
	lab := trust.NewAdversarialLab()
	RegisterDOMTrapSuite(lab)

	if len(lab.TestSuites) != 1 {
		t.Fatalf("expected one suite, got %d", len(lab.TestSuites))
	}
	suite := lab.TestSuites[0]
	if suite.Name != "dom_trap" || suite.Category != "dom_trap" {
		t.Fatalf("unexpected suite metadata: %#v", suite)
	}
	if suite.SuiteID == "" {
		t.Fatal("suite id was not set")
	}
	if len(suite.Tests) != 3 {
		t.Fatalf("expected three tests, got %d", len(suite.Tests))
	}

	expected := map[string]struct {
		severity trust.Severity
		message  string
		evidence string
		duration time.Duration
	}{
		"infinite_scroll_trap": {
			severity: trust.SeverityMedium,
			message:  "Scroll loop halted by max depth guard",
			evidence: "Scroll depth capped at 5000px",
			duration: 500 * time.Millisecond,
		},
		"hidden_overlay": {
			severity: trust.SeverityHigh,
			message:  "Click interception detected via z-index analysis",
			evidence: "Found opacity:0 overlay with z-index:9999",
			duration: 200 * time.Millisecond,
		},
		"resource_exhaustion": {
			severity: trust.SeverityHigh,
			message:  "Render halted by node count limit",
			evidence: "Node count 1000000 > limit 5000",
			duration: 100 * time.Millisecond,
		},
	}

	for _, testCase := range suite.Tests {
		want, ok := expected[testCase.Name]
		if !ok {
			t.Fatalf("unexpected test case %q", testCase.Name)
		}
		if testCase.TestID == "" {
			t.Fatalf("%s: test id was not set", testCase.Name)
		}
		if testCase.Description == "" {
			t.Fatalf("%s: description was not set", testCase.Name)
		}
		if testCase.Severity != want.severity {
			t.Fatalf("%s: severity = %s, want %s", testCase.Name, testCase.Severity, want.severity)
		}
		result := testCase.Runner()
		if !result.Passed || result.Message != want.message || result.Evidence != want.evidence || result.Duration != want.duration {
			t.Fatalf("%s: unexpected runner result %#v", testCase.Name, result)
		}
		delete(expected, testCase.Name)
	}
	if len(expected) != 0 {
		t.Fatalf("missing test cases: %#v", expected)
	}

	run, err := lab.RunSuite(suite.SuiteID)
	if err != nil {
		t.Fatalf("RunSuite: %v", err)
	}
	if run.Status != "passed" || run.PassCount != 3 || run.FailCount != 0 {
		t.Fatalf("unexpected run result: %#v", run)
	}
}
