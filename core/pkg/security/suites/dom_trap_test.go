package suites

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
)

func TestRegisterDOMTrapSuiteMetadata(t *testing.T) {
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
	}{
		"infinite_scroll_trap": {
			severity: trust.SeverityMedium,
		},
		"hidden_overlay": {
			severity: trust.SeverityHigh,
		},
		"resource_exhaustion": {
			severity: trust.SeverityHigh,
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
		if testCase.Runner == nil {
			t.Fatalf("%s: runner was not set", testCase.Name)
		}
		delete(expected, testCase.Name)
	}
	if len(expected) != 0 {
		t.Fatalf("missing test cases: %#v", expected)
	}
}

func TestRegisterDOMTrapSuiteFailsClosedWithoutBrowserEvidence(t *testing.T) {
	t.Setenv(domTrapEvidenceDirEnv, "")

	lab := trust.NewAdversarialLab()
	RegisterDOMTrapSuite(lab)

	suite := lab.TestSuites[0]
	for _, testCase := range suite.Tests {
		result := testCase.Runner()
		if result.Passed {
			t.Fatalf("%s: runner passed without browser evidence: %#v", testCase.Name, result)
		}
		if !strings.Contains(result.Message, "requires browser/CDP evidence artifact") {
			t.Fatalf("%s: unexpected message %q", testCase.Name, result.Message)
		}
		if !strings.Contains(result.Evidence, "non_certifying:missing_browser_evidence") {
			t.Fatalf("%s: unexpected evidence %q", testCase.Name, result.Evidence)
		}
	}

	run, err := lab.RunSuite(suite.SuiteID)
	if err != nil {
		t.Fatalf("RunSuite: %v", err)
	}
	if run.Status != "failed" || run.PassCount != 0 || run.FailCount != 3 {
		t.Fatalf("unexpected run result: %#v", run)
	}
}

func TestRegisterDOMTrapSuiteAcceptsBrowserEvidenceArtifacts(t *testing.T) {
	evidenceDir := t.TempDir()
	t.Setenv(domTrapEvidenceDirEnv, evidenceDir)

	traps := []string{"infinite_scroll_trap", "hidden_overlay", "resource_exhaustion"}
	for _, trap := range traps {
		writeDOMTrapEvidence(t, evidenceDir, domTrapEvidence{
			Trap:         trap,
			Browser:      "chromium-124",
			FixtureHash:  strings.Repeat("a", 64),
			ArtifactHash: "sha256:" + strings.Repeat("b", 64),
			Guard:        "max-depth",
			Observations: []string{"guard fired"},
			Passed:       true,
		})
	}

	lab := trust.NewAdversarialLab()
	RegisterDOMTrapSuite(lab)

	suite := lab.TestSuites[0]
	for _, testCase := range suite.Tests {
		result := testCase.Runner()
		if !result.Passed {
			t.Fatalf("%s: runner rejected valid browser evidence: %#v", testCase.Name, result)
		}
		if !strings.Contains(result.Evidence, "browser=chromium-124") ||
			!strings.Contains(result.Evidence, "artifact_hash=sha256:") ||
			!strings.Contains(result.Evidence, "observations=1") {
			t.Fatalf("%s: missing observable evidence fields: %q", testCase.Name, result.Evidence)
		}
	}

	run, err := lab.RunSuite(suite.SuiteID)
	if err != nil {
		t.Fatalf("RunSuite: %v", err)
	}
	if run.Status != "passed" || run.PassCount != 3 || run.FailCount != 0 {
		t.Fatalf("unexpected run result: %#v", run)
	}
}

func writeDOMTrapEvidence(t *testing.T, evidenceDir string, evidence domTrapEvidence) {
	t.Helper()

	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	path := filepath.Join(evidenceDir, evidence.Trap+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
}
