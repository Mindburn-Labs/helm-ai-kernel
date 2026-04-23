// Package scenarios implements the 6 canonical incident scenario tests
// specified in the HELM OSS Canonical Implementation Plan.
//
// Each scenario constructs a realistic threat, exercises the enforcement
// stack, and asserts: deny verdict, specific reason code, and receipted denial.
//
// These tests are the trust proof for HELM OSS enforcement claims.
package scenarios

import "time"

// Convenience duration constants for tests.
const (
	_ms  = time.Millisecond
	_sec = time.Second
)
