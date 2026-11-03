// Package kernel_test contains cross-runtime equivalence tests for HELM determinism.
// These tests verify that implementations produce identical results across scenarios.
package kernel_test

// CrossRuntimeTestVector represents a test vector for cross-runtime verification.
type CrossRuntimeTestVector struct {
	Name           string
	Input          any
	ExpectedOutput string // Expected canonical output
}
