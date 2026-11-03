// Package conformance provides the L1/L2/L3 conformance test contracts for HELM.
// These contracts define what is verified at each conformance level and feed into
// the existing conform.Engine's gate system.
package conformance

import (
	"fmt"
	"time"
)

// Level defines a conformance verification tier.
type Level string

const (
	LevelL1 Level = "L1" // Structural correctness
	LevelL2 Level = "L2" // Execution correctness
	LevelL3 Level = "L3" // Adversarial resilience
)

// TestCase is a single conformance test.
type TestCase struct {
	ID          string        `json:"id"`
	Level       Level         `json:"level"`
	Category    string        `json:"category"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Negative    bool          `json:"negative"` // true = expects failure
	Timeout     time.Duration `json:"timeout"`
	Run         TestFunc      `json:"-"`
}

// TestFunc is the function signature for a conformance test.
type TestFunc func(ctx *TestContext) error

// TestContext provides dependencies and assertions for conformance tests.
type TestContext struct {
	Level    Level
	Category string
	Errors   []string
}

// Fail records a test failure.
func (tc *TestContext) Fail(format string, args ...interface{}) {
	tc.Errors = append(tc.Errors, fmt.Sprintf(format, args...))
}

// Failed returns true if any failures were recorded.
func (tc *TestContext) Failed() bool {
	return len(tc.Errors) > 0
}

// TestResult is the outcome of a single test.
type TestResult struct {
	TestID   string        `json:"test_id"`
	Name     string        `json:"name"`
	Level    Level         `json:"level"`
	Category string        `json:"category"`
	Passed   bool          `json:"passed"`
	Duration time.Duration `json:"duration"`
	Error    string        `json:"error,omitempty"`
}

// Suite is a collection of conformance tests.
type Suite struct {
	tests []TestCase
}

// NewSuite creates a new conformance test suite.
func NewSuite() *Suite {
	return &Suite{
		tests: make([]TestCase, 0),
	}
}

// Register adds a test case to the suite.
func (s *Suite) Register(tc TestCase) {
	s.tests = append(s.tests, tc)
}

// TestsForLevel returns all tests at or below the given level.
func (s *Suite) TestsForLevel(level Level) []TestCase {
	var result []TestCase
	for _, tc := range s.tests {
		if levelOrd(tc.Level) <= levelOrd(level) {
			result = append(result, tc)
		}
	}
	return result
}

// Run executes all tests at or below the given level.
func (s *Suite) Run(level Level) []TestResult {
	tests := s.TestsForLevel(level)
	results := make([]TestResult, 0, len(tests))

	for _, tc := range tests {
		start := time.Now()
		ctx := &TestContext{
			Level:    tc.Level,
			Category: tc.Category,
		}

		err := tc.Run(ctx)
		duration := time.Since(start)

		result := TestResult{
			TestID:   tc.ID,
			Name:     tc.Name,
			Level:    tc.Level,
			Category: tc.Category,
			Duration: duration,
		}

		if tc.Negative {
			// Negative test: expects failure
			result.Passed = err != nil || ctx.Failed()
			if !result.Passed {
				result.Error = "negative test passed unexpectedly (should have failed)"
			}
		} else {
			if err != nil {
				result.Passed = false
				result.Error = err.Error()
			} else if ctx.Failed() {
				result.Passed = false
				result.Error = fmt.Sprintf("%d assertion(s) failed: %v", len(ctx.Errors), ctx.Errors)
			} else {
				result.Passed = true
			}
		}

		results = append(results, result)
	}

	return results
}

func levelOrd(l Level) int {
	switch l {
	case LevelL1:
		return 1
	case LevelL2:
		return 2
	case LevelL3:
		return 3
	default:
		return 0
	}
}
