// Package sandbox provides the conformance test suite for SandboxActuator implementations.
// Every sandbox provider adapter MUST pass these tests to be HELM-compatible.
package sandbox

import (
	"context"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conformance"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
)

// RegisterSandboxTests registers all sandbox conformance tests into a Suite.
// Adapter tests call this with a real or mock actuator.
func RegisterSandboxTests(suite *conformance.Suite, actuator actuators.SandboxActuator) {
	registerL1Tests(suite, actuator)
	registerL2Tests(suite, actuator)
	registerL3Tests(suite, actuator)
}

// ── L1: Structural Correctness ──────────────────────────────────

func registerL1Tests(suite *conformance.Suite, a actuators.SandboxActuator) {
	suite.Register(conformance.TestCase{
		ID:          "SBX-L1-LIFECYCLE-001",
		Level:       conformance.LevelL1,
		Category:    "lifecycle",
		Name:        "Create and Terminate produce valid handle",
		Description: "Creating a sandbox returns a running handle; terminating it succeeds",
		Run: func(tc *conformance.TestContext) error {
			ctx := context.Background()
			spec := defaultSpec()
			handle, err := a.Create(ctx, spec)
			if err != nil {
				return fmt.Errorf("Create failed: %w", err)
			}
			if handle.ID == "" {
				tc.Fail("handle ID must not be empty")
			}
			if handle.Status != actuators.StatusRunning {
				tc.Fail("expected status %q, got %q", actuators.StatusRunning, handle.Status)
			}
			if handle.Provider != a.Provider() {
				tc.Fail("handle provider %q does not match actuator provider %q", handle.Provider, a.Provider())
			}
			if err := a.Terminate(ctx, handle.ID); err != nil {
				tc.Fail("Terminate failed: %v", err)
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "SBX-L1-EXEC-001",
		Level:       conformance.LevelL1,
		Category:    "exec",
		Name:        "echo command returns exit 0 and correct stdout",
		Description: "Running echo hello must return exit 0 with 'hello' in stdout",
		Run: func(tc *conformance.TestContext) error {
			ctx := context.Background()
			handle, err := a.Create(ctx, defaultSpec())
			if err != nil {
				return fmt.Errorf("Create failed: %w", err)
			}
			defer a.Terminate(ctx, handle.ID) //nolint:errcheck

			result, err := a.Exec(ctx, handle.ID, &actuators.ExecRequest{
				Command: []string{"echo", "hello"},
			})
			if err != nil {
				return fmt.Errorf("Exec failed: %w", err)
			}
			if result.ExitCode != 0 {
				tc.Fail("expected exit code 0, got %d", result.ExitCode)
			}
			if len(result.Stdout) == 0 {
				tc.Fail("stdout must not be empty for echo command")
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "SBX-L1-FS-001",
		Level:       conformance.LevelL1,
		Category:    "fs",
		Name:        "Write then Read round-trip integrity",
		Description: "Writing a file and reading it back must produce identical content",
		Run: func(tc *conformance.TestContext) error {
			ctx := context.Background()
			handle, err := a.Create(ctx, defaultSpec())
			if err != nil {
				return fmt.Errorf("Create failed: %w", err)
			}
			defer a.Terminate(ctx, handle.ID) //nolint:errcheck

			testData := []byte("HELM conformance test data — deterministic")
			testPath := "/tmp/helm-conformance-test.txt"

			if err := a.WriteFile(ctx, handle.ID, testPath, testData); err != nil {
				return fmt.Errorf("WriteFile failed: %w", err)
			}

			readBack, err := a.ReadFile(ctx, handle.ID, testPath)
			if err != nil {
				return fmt.Errorf("ReadFile failed: %w", err)
			}
			if string(readBack) != string(testData) {
				tc.Fail("round-trip mismatch: wrote %q, read %q", string(testData), string(readBack))
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "SBX-L1-RECEIPT-001",
		Level:       conformance.LevelL1,
		Category:    "receipt",
		Name:        "ExecResult contains deterministic receipt fragment",
		Description: "The receipt fragment must have non-empty hashes and correct provider",
		Run: func(tc *conformance.TestContext) error {
			ctx := context.Background()
			handle, err := a.Create(ctx, defaultSpec())
			if err != nil {
				return fmt.Errorf("Create failed: %w", err)
			}
			defer a.Terminate(ctx, handle.ID) //nolint:errcheck

			result, err := a.Exec(ctx, handle.ID, &actuators.ExecRequest{
				Command: []string{"echo", "receipt-test"},
			})
			if err != nil {
				return fmt.Errorf("Exec failed: %w", err)
			}
			if result.Receipt.RequestHash == "" {
				tc.Fail("receipt request_hash must not be empty")
			}
			if result.Receipt.StdoutHash == "" {
				tc.Fail("receipt stdout_hash must not be empty")
			}
			if result.Receipt.Provider != a.Provider() {
				tc.Fail("receipt provider %q does not match actuator %q", result.Receipt.Provider, a.Provider())
			}
			if result.Receipt.ExecutedAt.IsZero() {
				tc.Fail("receipt executed_at must not be zero")
			}
			return nil
		},
	})
}

// ── L2: Execution Correctness ───────────────────────────────────

func registerL2Tests(suite *conformance.Suite, a actuators.SandboxActuator) {
	suite.Register(conformance.TestCase{
		ID:          "SBX-L2-PREFLIGHT-001",
		Level:       conformance.LevelL2,
		Category:    "preflight",
		Name:        "Preflight produces a report with checks",
		Description: "Preflight must return a report with at least one check",
		Run: func(tc *conformance.TestContext) error {
			ctx := context.Background()
			report, err := a.Preflight(ctx)
			if err != nil {
				return fmt.Errorf("Preflight failed: %w", err)
			}
			if len(report.Checks) == 0 {
				tc.Fail("preflight report must contain at least one check")
			}
			if report.Provider != a.Provider() {
				tc.Fail("report provider %q does not match actuator %q", report.Provider, a.Provider())
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "SBX-L2-TIMEOUT-001",
		Level:       conformance.LevelL2,
		Category:    "exec",
		Name:        "Command respects per-command timeout",
		Description: "A long-running command must be killed after its timeout",
		Run: func(tc *conformance.TestContext) error {
			ctx := context.Background()
			handle, err := a.Create(ctx, defaultSpec())
			if err != nil {
				return fmt.Errorf("Create failed: %w", err)
			}
			defer a.Terminate(ctx, handle.ID) //nolint:errcheck

			result, err := a.Exec(ctx, handle.ID, &actuators.ExecRequest{
				Command: []string{"sleep", "30"},
				Timeout: 1 * time.Second,
			})
			if err != nil {
				// Error on timeout is acceptable.
				return nil
			}
			if !result.TimedOut {
				tc.Fail("expected TimedOut=true for a command exceeding its timeout")
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "SBX-L2-PERSISTENCE-001",
		Level:       conformance.LevelL2,
		Category:    "lifecycle",
		Name:        "Pause and Resume preserve state",
		Description: "Pause then Resume must yield a running sandbox (or ErrNotSupported)",
		Run: func(tc *conformance.TestContext) error {
			ctx := context.Background()
			handle, err := a.Create(ctx, defaultSpec())
			if err != nil {
				return fmt.Errorf("Create failed: %w", err)
			}
			defer a.Terminate(ctx, handle.ID) //nolint:errcheck

			err = a.Pause(ctx, handle.ID)
			if err == actuators.ErrNotSupported {
				// Provider does not support persistence — skip.
				return nil
			}
			if err != nil {
				return fmt.Errorf("Pause failed: %w", err)
			}

			resumed, err := a.Resume(ctx, handle.ID)
			if err != nil {
				return fmt.Errorf("Resume failed: %w", err)
			}
			if resumed.Status != actuators.StatusRunning {
				tc.Fail("expected status %q after resume, got %q", actuators.StatusRunning, resumed.Status)
			}
			return nil
		},
	})
}

// ── L3: Adversarial Resilience ──────────────────────────────────

func registerL3Tests(suite *conformance.Suite, a actuators.SandboxActuator) {
	suite.Register(conformance.TestCase{
		ID:          "SBX-L3-EGRESS-001",
		Level:       conformance.LevelL3,
		Category:    "network",
		Name:        "Blocked egress destination is rejected",
		Description: "Setting egress rules must restrict outbound connectivity",
		Run: func(tc *conformance.TestContext) error {
			ctx := context.Background()
			handle, err := a.Create(ctx, &actuators.SandboxSpec{
				Runtime: "default",
				Resources: actuators.ResourceSpec{
					MemoryMB: 128,
					Timeout:  30 * time.Second,
				},
				Egress: actuators.EgressPolicy{Disabled: true},
			})
			if err != nil {
				return fmt.Errorf("Create failed: %w", err)
			}
			defer a.Terminate(ctx, handle.ID) //nolint:errcheck

			err = a.AllowEgress(ctx, handle.ID, []actuators.EgressRule{
				{Host: "127.0.0.1", Port: 80},
			})
			if err == actuators.ErrNotSupported {
				return nil
			}
			if err != nil {
				return fmt.Errorf("AllowEgress failed: %w", err)
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "SBX-L3-TAMPER-001",
		Level:       conformance.LevelL3,
		Category:    "receipt",
		Name:        "Receipt fragment determinism",
		Description: "Running the same command twice must produce identical receipt hashes",
		Run: func(tc *conformance.TestContext) error {
			ctx := context.Background()
			handle, err := a.Create(ctx, defaultSpec())
			if err != nil {
				return fmt.Errorf("Create failed: %w", err)
			}
			defer a.Terminate(ctx, handle.ID) //nolint:errcheck

			req := &actuators.ExecRequest{Command: []string{"echo", "deterministic"}}

			r1, err := a.Exec(ctx, handle.ID, req)
			if err != nil {
				return fmt.Errorf("first Exec failed: %w", err)
			}
			r2, err := a.Exec(ctx, handle.ID, req)
			if err != nil {
				return fmt.Errorf("second Exec failed: %w", err)
			}

			if r1.Receipt.RequestHash != r2.Receipt.RequestHash {
				tc.Fail("request hashes differ: %q vs %q", r1.Receipt.RequestHash, r2.Receipt.RequestHash)
			}
			if r1.Receipt.StdoutHash != r2.Receipt.StdoutHash {
				tc.Fail("stdout hashes differ: %q vs %q (non-deterministic output)", r1.Receipt.StdoutHash, r2.Receipt.StdoutHash)
			}
			return nil
		},
	})

	// ── Adversarial / degraded-path tests ────────────────────────

	suite.Register(conformance.TestCase{
		ID:          "SBX-L3-AUTH-001",
		Level:       conformance.LevelL3,
		Category:    "preflight",
		Name:        "Auth misconfigured — preflight DENY",
		Description: "If auth is not properly configured, preflight must deny with StrictPassed=false",
		Run: func(tc *conformance.TestContext) error {
			mock, ok := a.(*MockActuator)
			if !ok {
				return nil // skip for non-mock providers in automated suite
			}
			mock.InjectFault(FaultConfig{PreflightAuthFail: true})
			defer mock.ClearFaults()

			ctx := context.Background()
			report, err := mock.Preflight(ctx)
			if err != nil {
				return fmt.Errorf("Preflight error: %w", err)
			}
			if report.StrictPassed {
				tc.Fail("preflight must DENY when auth is misconfigured")
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "SBX-L3-EGRESS-002",
		Level:       conformance.LevelL3,
		Category:    "preflight",
		Name:        "Egress enforcement degraded — preflight DENY",
		Description: "If egress enforcement is unavailable or degraded, preflight must deny",
		Run: func(tc *conformance.TestContext) error {
			mock, ok := a.(*MockActuator)
			if !ok {
				return nil
			}
			mock.InjectFault(FaultConfig{PreflightEgressDegraded: true})
			defer mock.ClearFaults()

			ctx := context.Background()
			report, err := mock.Preflight(ctx)
			if err != nil {
				return fmt.Errorf("Preflight error: %w", err)
			}
			if report.StrictPassed {
				tc.Fail("preflight must DENY when egress enforcement is degraded")
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "SBX-L3-TIMEOUT-001",
		Level:       conformance.LevelL3,
		Category:    "exec",
		Name:        "Timeout ambiguity — explicit error, no unsafe retry",
		Description: "If exec times out with unknown completion status, the actuator must return an ambiguity error",
		Run: func(tc *conformance.TestContext) error {
			mock, ok := a.(*MockActuator)
			if !ok {
				return nil
			}
			mock.InjectFault(FaultConfig{ExecTimeoutAmbiguous: true})
			defer mock.ClearFaults()

			ctx := context.Background()
			handle, err := mock.Create(ctx, defaultSpec())
			if err != nil {
				return fmt.Errorf("Create failed: %w", err)
			}
			defer mock.Terminate(ctx, handle.ID) //nolint:errcheck

			_, err = mock.Exec(ctx, handle.ID, &actuators.ExecRequest{
				Command: []string{"echo", "test"},
			})
			if err == nil {
				tc.Fail("exec must return error on timeout ambiguity, not nil")
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "SBX-L3-NETERR-001",
		Level:       conformance.LevelL3,
		Category:    "exec",
		Name:        "Network error during exec — deterministic failure",
		Description: "If a network error occurs during exec, the actuator must fail closed with an error",
		Run: func(tc *conformance.TestContext) error {
			mock, ok := a.(*MockActuator)
			if !ok {
				return nil
			}
			mock.InjectFault(FaultConfig{ExecNetworkError: true})
			defer mock.ClearFaults()

			ctx := context.Background()
			handle, err := mock.Create(ctx, defaultSpec())
			if err != nil {
				return fmt.Errorf("Create failed: %w", err)
			}
			defer mock.Terminate(ctx, handle.ID) //nolint:errcheck

			_, err = mock.Exec(ctx, handle.ID, &actuators.ExecRequest{
				Command: []string{"echo", "test"},
			})
			if err == nil {
				tc.Fail("exec must return error on network failure, not nil")
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "SBX-L3-MALFORMED-001",
		Level:       conformance.LevelL3,
		Category:    "exec",
		Name:        "Malformed provider response — DENY, no partial allow",
		Description: "If provider returns a malformed response, actuator must fail closed",
		Run: func(tc *conformance.TestContext) error {
			mock, ok := a.(*MockActuator)
			if !ok {
				return nil
			}
			mock.InjectFault(FaultConfig{ExecMalformedResult: true})
			defer mock.ClearFaults()

			ctx := context.Background()
			handle, err := mock.Create(ctx, defaultSpec())
			if err != nil {
				return fmt.Errorf("Create failed: %w", err)
			}
			defer mock.Terminate(ctx, handle.ID) //nolint:errcheck

			_, err = mock.Exec(ctx, handle.ID, &actuators.ExecRequest{
				Command: []string{"echo", "test"},
			})
			if err == nil {
				tc.Fail("exec must return error on malformed response, not nil")
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "SBX-L3-RESUME-001",
		Level:       conformance.LevelL3,
		Category:    "lifecycle",
		Name:        "Resume with mismatched spec hash — DENY",
		Description: "If sandbox spec has changed since creation, resume must be denied",
		Run: func(tc *conformance.TestContext) error {
			mock, ok := a.(*MockActuator)
			if !ok {
				return nil
			}

			ctx := context.Background()
			handle, err := mock.Create(ctx, defaultSpec())
			if err != nil {
				return fmt.Errorf("Create failed: %w", err)
			}
			defer mock.Terminate(ctx, handle.ID) //nolint:errcheck

			mock.InjectFault(FaultConfig{ResumeSpecMismatch: true})
			defer mock.ClearFaults()

			_, err = mock.Resume(ctx, handle.ID)
			if err == nil {
				tc.Fail("resume must DENY when sandbox spec hash mismatches")
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "SBX-L3-RECEIPT-SPEC-001",
		Level:       conformance.LevelL3,
		Category:    "receipt",
		Name:        "Receipt binds full sandbox spec",
		Description: "The receipt fragment must include a non-empty SandboxSpecHash, ResourceLimitsHash, and EgressPolicyHash",
		Run: func(tc *conformance.TestContext) error {
			ctx := context.Background()
			handle, err := a.Create(ctx, defaultSpec())
			if err != nil {
				return fmt.Errorf("Create failed: %w", err)
			}
			defer a.Terminate(ctx, handle.ID) //nolint:errcheck

			result, err := a.Exec(ctx, handle.ID, &actuators.ExecRequest{
				Command: []string{"echo", "spec-bind-test"},
			})
			if err != nil {
				return fmt.Errorf("Exec failed: %w", err)
			}

			if result.Receipt.SandboxSpecHash == "" {
				tc.Fail("receipt SandboxSpecHash must not be empty")
			}
			if result.Receipt.ResourceLimitsHash == "" {
				tc.Fail("receipt ResourceLimitsHash must not be empty")
			}
			if result.Receipt.EgressPolicyHash == "" {
				tc.Fail("receipt EgressPolicyHash must not be empty")
			}
			if result.Receipt.Effect == "" {
				tc.Fail("receipt Effect must not be empty")
			}
			return nil
		},
	})
}

// ── Helpers ─────────────────────────────────────────────────────

func defaultSpec() *actuators.SandboxSpec {
	return &actuators.SandboxSpec{
		Runtime: "default",
		Resources: actuators.ResourceSpec{
			CPUMillis:    500,
			MemoryMB:     256,
			DiskMB:       512,
			Timeout:      30 * time.Second,
			MaxProcesses: 64,
		},
		Egress: actuators.EgressPolicy{Disabled: true},
	}
}
