package sandbox

import (
	"context"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
)

// FaultConfig controls injectable faults for adversarial conformance testing.
// When a field is true, the corresponding actuator operation degrades or fails
// in a way that mirrors real production failure modes.
type FaultConfig struct {
	// PreflightAuthFail simulates auth misconfiguration → preflight DENY.
	PreflightAuthFail bool

	// PreflightEgressDegraded simulates egress enforcement unavailable → preflight DENY.
	PreflightEgressDegraded bool

	// ExecNetworkError simulates a network error during Exec.
	ExecNetworkError bool

	// ExecMalformedResult simulates a malformed/partial response from provider.
	ExecMalformedResult bool

	// ExecTimeoutAmbiguous simulates a timeout where completion is unknown.
	ExecTimeoutAmbiguous bool

	// ResumeSpecMismatch simulates a resume where the sandbox spec has changed.
	ResumeSpecMismatch bool
}

// InjectFault sets the active fault configuration for the mock actuator.
// Only one fault config should be active at a time.
func (m *MockActuator) InjectFault(cfg FaultConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.faults = &cfg
}

// ClearFaults removes all injected faults.
func (m *MockActuator) ClearFaults() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.faults = nil
}

// ── Fault-aware overrides ───────────────────────────────────────

// faultPreflight returns a failing preflight report if auth or egress faults are active.
func (m *MockActuator) faultPreflight() (*actuators.PreflightReport, bool) {
	if m.faults == nil {
		return nil, false
	}

	var checks []actuators.PreflightCheck

	if m.faults.PreflightAuthFail {
		checks = append(checks, actuators.PreflightCheck{
			Name:     "auth_configured",
			Passed:   false,
			Required: true,
			Reason:   "FAULT: API key not configured",
		})
	}

	if m.faults.PreflightEgressDegraded {
		checks = append(checks, actuators.PreflightCheck{
			Name:     "egress_strict_mode",
			Passed:   false,
			Required: true,
			Reason:   "FAULT: egress enforcement degraded to DNS-only",
		})
	}

	if len(checks) == 0 {
		return nil, false
	}

	return &actuators.PreflightReport{
		Provider:     "mock",
		StrictPassed: false,
		Checks:       checks,
		CheckedAt:    m.clock(),
	}, true
}

// ── Error types for ambiguous outcomes ──────────────────────────

// ErrExecAmbiguous represents a timeout where completion status is unknown.
// Callers MUST NOT retry without reconciliation.
var ErrExecAmbiguous = fmt.Errorf("sandbox: exec outcome ambiguous — timeout with unknown completion state")

// ErrExecNetworkFailure represents a network error during execution.
var ErrExecNetworkFailure = fmt.Errorf("sandbox: network error during exec")

// ErrExecMalformedResponse represents a provider returning invalid data.
var ErrExecMalformedResponse = fmt.Errorf("sandbox: provider returned malformed response")

// ErrResumeSpecMismatch is returned when resume detects a changed sandbox spec.
var ErrResumeSpecMismatch = fmt.Errorf("sandbox: resume denied — sandbox spec hash mismatch")

// faultExec checks if an exec fault should fire.
func (m *MockActuator) faultExec() error {
	if m.faults == nil {
		return nil
	}
	if m.faults.ExecNetworkError {
		return ErrExecNetworkFailure
	}
	if m.faults.ExecMalformedResult {
		return ErrExecMalformedResponse
	}
	if m.faults.ExecTimeoutAmbiguous {
		return ErrExecAmbiguous
	}
	return nil
}

// faultResume checks if a resume fault should fire.
func (m *MockActuator) faultResume() error {
	if m.faults == nil {
		return nil
	}
	if m.faults.ResumeSpecMismatch {
		return ErrResumeSpecMismatch
	}
	return nil
}

// PreflightWithFaults is the fault-aware preflight. The base mock Preflight
// calls this internally.
func (m *MockActuator) preflightWithFaults(_ context.Context) (*actuators.PreflightReport, error) {
	if report, faulted := m.faultPreflight(); faulted {
		return report, nil
	}
	return &actuators.PreflightReport{
		Provider:     "mock",
		StrictPassed: true,
		Checks: []actuators.PreflightCheck{
			{Name: "mock_connectivity", Passed: true, Required: true, Reason: "mock always passes"},
			{Name: "mock_auth", Passed: true, Required: true, Reason: "mock does not require auth"},
		},
		CheckedAt: m.clock(),
	}, nil
}
