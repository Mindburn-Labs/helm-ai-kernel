package conformance

import (
	"testing"
)

// TestOWASP_LLM_Top10 runs the full OWASP LLM Top 10 conformance suite.
//
// Each subtest is named OWASP-LLMxx-NNN and maps to a specific OWASP category:
//   - LLM01: Prompt Injection
//   - LLM02: Insecure Output Handling
//   - LLM03: Training Data Poisoning
//   - LLM04: Model Denial of Service
//   - LLM05: Supply Chain Vulnerabilities
//   - LLM06: Sensitive Information Disclosure
//   - LLM07: Insecure Plugin Design
//   - LLM08: Excessive Agency
//   - LLM09: Overreliance
//   - LLM10: Model Theft
//
// Activated by: make test-owasp (runs -run "OWASP-")
func TestOWASP_LLM_Top10(t *testing.T) {
	suite := NewSuite()
	RegisterOWASPTests(suite)

	// Run all OWASP tests (they are registered as L3 = adversarial resilience)
	results := suite.Run(LevelL3)

	for _, r := range results {
		t.Run(r.TestID+"/"+r.Name, func(t *testing.T) {
			if !r.Passed {
				t.Fatalf("FAIL: %s [%s] — %s", r.TestID, r.Category, r.Error)
			}
			t.Logf("PASS: %s (%v)", r.TestID, r.Duration)
		})
	}

	// Summary
	passed := 0
	failed := 0
	for _, r := range results {
		if r.Passed {
			passed++
		} else {
			failed++
		}
	}
	t.Logf("OWASP LLM Top 10 Conformance: %d passed, %d failed, %d total", passed, failed, len(results))
}

// TestOWASP_LLM01_PromptInjection runs only LLM01 (Prompt Injection) tests.
func TestOWASP_LLM01_PromptInjection(t *testing.T) {
	suite := NewSuite()
	RegisterOWASPTests(suite)
	runOWASPCategory(t, suite, "owasp-llm01-prompt-injection")
}

// TestOWASP_LLM02_InsecureOutput runs only LLM02 (Insecure Output Handling) tests.
func TestOWASP_LLM02_InsecureOutput(t *testing.T) {
	suite := NewSuite()
	RegisterOWASPTests(suite)
	runOWASPCategory(t, suite, "owasp-llm02-insecure-output")
}

// TestOWASP_LLM03_TrainingData runs only LLM03 (Training Data Poisoning) tests.
func TestOWASP_LLM03_TrainingData(t *testing.T) {
	suite := NewSuite()
	RegisterOWASPTests(suite)
	runOWASPCategory(t, suite, "owasp-llm03-training-data")
}

// TestOWASP_LLM04_ModelDoS runs only LLM04 (Model Denial of Service) tests.
func TestOWASP_LLM04_ModelDoS(t *testing.T) {
	suite := NewSuite()
	RegisterOWASPTests(suite)
	runOWASPCategory(t, suite, "owasp-llm04-model-dos")
}

// TestOWASP_LLM05_SupplyChain runs only LLM05 (Supply Chain Vulnerabilities) tests.
func TestOWASP_LLM05_SupplyChain(t *testing.T) {
	suite := NewSuite()
	RegisterOWASPTests(suite)
	runOWASPCategory(t, suite, "owasp-llm05-supply-chain")
}

// TestOWASP_LLM06_SensitiveDisclosure runs only LLM06 (Sensitive Information Disclosure) tests.
func TestOWASP_LLM06_SensitiveDisclosure(t *testing.T) {
	suite := NewSuite()
	RegisterOWASPTests(suite)
	runOWASPCategory(t, suite, "owasp-llm06-sensitive-disclosure")
}

// TestOWASP_LLM07_InsecurePlugin runs only LLM07 (Insecure Plugin Design) tests.
func TestOWASP_LLM07_InsecurePlugin(t *testing.T) {
	suite := NewSuite()
	RegisterOWASPTests(suite)
	runOWASPCategory(t, suite, "owasp-llm07-insecure-plugin")
}

// TestOWASP_LLM08_ExcessiveAgency runs only LLM08 (Excessive Agency) tests.
func TestOWASP_LLM08_ExcessiveAgency(t *testing.T) {
	suite := NewSuite()
	RegisterOWASPTests(suite)
	runOWASPCategory(t, suite, "owasp-llm08-excessive-agency")
}

// TestOWASP_LLM09_Overreliance runs only LLM09 (Overreliance) tests.
func TestOWASP_LLM09_Overreliance(t *testing.T) {
	suite := NewSuite()
	RegisterOWASPTests(suite)
	runOWASPCategory(t, suite, "owasp-llm09-overreliance")
}

// TestOWASP_LLM10_ModelTheft runs only LLM10 (Model Theft) tests.
func TestOWASP_LLM10_ModelTheft(t *testing.T) {
	suite := NewSuite()
	RegisterOWASPTests(suite)
	runOWASPCategory(t, suite, "owasp-llm10-model-theft")
}

// runOWASPCategory runs all tests in a given OWASP category.
func runOWASPCategory(t *testing.T, suite *Suite, category string) {
	t.Helper()
	results := suite.Run(LevelL3)
	ran := 0
	for _, r := range results {
		if r.Category != category {
			continue
		}
		ran++
		t.Run(r.TestID, func(t *testing.T) {
			if !r.Passed {
				t.Fatalf("FAIL: %s — %s", r.TestID, r.Error)
			}
			t.Logf("PASS: %s (%v)", r.TestID, r.Duration)
		})
	}
	if ran == 0 {
		t.Fatalf("no tests found for category %q", category)
	}
}
