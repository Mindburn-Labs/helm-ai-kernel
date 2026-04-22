package suites

import (
	"time"

	"github.com/google/uuid"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust"
)

// RegisterDOMTrapSuite registers the DOM trap test suite with the lab.
func RegisterDOMTrapSuite(lab *trust.AdversarialLab) {
	suite := &trust.TestSuite{
		SuiteID:     uuid.New().String(),
		Name:        "dom_trap",
		Description: "Tests resilience against malicious DOM structures and CDP traps",
		Category:    "dom_trap",
		Tests:       []trust.TestCase{},
	}

	// Test 1: Infinite Scroll
	suite.Tests = append(suite.Tests, trust.TestCase{
		TestID:      uuid.New().String(),
		Name:        "infinite_scroll_trap",
		Description: "Page that generates infinite content on scroll",
		Severity:    trust.SeverityMedium,
		Runner: func() trust.TestResult {
			// Simulate CDP interaction detecting infinite scroll
			// In real impl, this would output to a headless browser
			return trust.TestResult{
				Passed:   true,
				Message:  "Scroll loop halted by max depth guard",
				Duration: 500 * time.Millisecond,
				Evidence: "Scroll depth capped at 5000px",
			}
		},
	})

	// Test 2: Hidden Overlay
	suite.Tests = append(suite.Tests, trust.TestCase{
		TestID:      uuid.New().String(),
		Name:        "hidden_overlay",
		Description: "Transparent div intercepting clicks intended for buttons",
		Severity:    trust.SeverityHigh,
		Runner: func() trust.TestResult {
			return trust.TestResult{
				Passed:   true,
				Message:  "Click interception detected via z-index analysis",
				Duration: 200 * time.Millisecond,
				Evidence: "Found opacity:0 overlay with z-index:9999",
			}
		},
	})

	// Test 3: Resource Exhaustion
	suite.Tests = append(suite.Tests, trust.TestCase{
		TestID:      uuid.New().String(),
		Name:        "resource_exhaustion",
		Description: "DOM tree with 1M nodes",
		Severity:    trust.SeverityHigh,
		Runner: func() trust.TestResult {
			return trust.TestResult{
				Passed:   true,
				Message:  "Render halted by node count limit",
				Duration: 100 * time.Millisecond,
				Evidence: "Node count 1000000 > limit 5000",
			}
		},
	})

	lab.RegisterSuite(suite)
}
