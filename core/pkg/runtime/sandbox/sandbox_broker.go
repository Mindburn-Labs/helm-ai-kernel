package sandbox

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effectgraph"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/lease"
	pkg_sandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

// SandboxRunner is the interface for executing work in a sandbox.
// This mirrors sandbox.Runner but avoids circular imports.
type SandboxRunner interface {
	Run(spec *pkg_sandbox.SandboxSpec) (*pkg_sandbox.Result, *pkg_sandbox.ExecutionReceipt, error)
	Validate(spec *pkg_sandbox.SandboxSpec) error
}

// PreparedExecution bundles everything needed to run in a sandbox.
type PreparedExecution struct {
	// Lease is the execution lease governing this run.
	Lease *lease.ExecutionLease

	// Spec is the sandbox specification.
	Spec *pkg_sandbox.SandboxSpec

	// Verdict is the approved step verdict.
	Verdict *effectgraph.NodeVerdict

	// Tokens lists scoped token IDs issued for this execution.
	Tokens []string

	// PreparedAt is when the execution was prepared.
	PreparedAt time.Time
}

// SandboxBroker mediates between approved effect graphs and execution backends.
// It manages lease activation, credential issuance, sandbox specification
// construction, and execution orchestration.
type SandboxBroker struct {
	mu         sync.RWMutex
	credBroker *CredentialBroker
	leases     lease.LeaseManager
	runners    map[string]SandboxRunner // backend name → runner
	clock      func() time.Time
}

// NewSandboxBroker creates a broker with the given dependencies.
func NewSandboxBroker(
	credBroker *CredentialBroker,
	leases lease.LeaseManager,
) *SandboxBroker {
	return &SandboxBroker{
		credBroker: credBroker,
		leases:     leases,
		runners:    make(map[string]SandboxRunner),
		clock:      time.Now,
	}
}

// WithClock overrides the clock for testing.
func (b *SandboxBroker) WithClock(clock func() time.Time) *SandboxBroker {
	b.clock = clock
	return b
}

// RegisterRunner adds a sandbox runner backend.
func (b *SandboxBroker) RegisterRunner(name string, runner SandboxRunner) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.runners[name] = runner
}

// PrepareExecution builds everything needed for a sandbox run.
// It activates the lease, issues credentials, and constructs the SandboxSpec.
func (b *SandboxBroker) PrepareExecution(
	ctx context.Context,
	execLease *lease.ExecutionLease,
	verdict *effectgraph.NodeVerdict,
) (*PreparedExecution, error) {
	if execLease == nil {
		return nil, fmt.Errorf("lease is nil")
	}
	if verdict == nil || verdict.Profile == nil {
		return nil, fmt.Errorf("verdict or profile is nil")
	}

	// Verify runner exists.
	b.mu.RLock()
	_, hasRunner := b.runners[execLease.Backend]
	b.mu.RUnlock()
	if !hasRunner {
		return nil, fmt.Errorf("no runner registered for backend %q", execLease.Backend)
	}

	// Verify the verdict's profile backend matches the lease backend.
	if verdict.Profile.Backend != execLease.Backend {
		return nil, fmt.Errorf("backend mismatch: lease=%q verdict=%q", execLease.Backend, verdict.Profile.Backend)
	}

	// Activate lease.
	sandboxID := fmt.Sprintf("sbx-%s-%d", execLease.Backend, b.clock().UnixNano())
	if err := b.leases.Activate(ctx, execLease.LeaseID, sandboxID); err != nil {
		return nil, fmt.Errorf("activate lease: %w", err)
	}

	// Issue scoped credentials.
	var tokenIDs []string
	for _, binding := range execLease.SecretBindings {
		token, err := b.credBroker.IssueToken(TokenRequest{
			SandboxID:       sandboxID,
			RequestedScopes: binding.Scopes,
			TTLSeconds:      int(execLease.TTL.Seconds()),
		})
		if err != nil {
			// Best effort: revoke already-issued tokens and lease.
			for _, tid := range tokenIDs {
				_ = b.credBroker.RevokeToken(tid)
			}
			_ = b.leases.Revoke(ctx, execLease.LeaseID, fmt.Sprintf("credential issuance failed: %v", err))
			return nil, fmt.Errorf("issue credential for %s: %w", binding.SecretRef, err)
		}
		tokenIDs = append(tokenIDs, token.TokenID)
	}

	// Build sandbox spec.
	spec := &pkg_sandbox.SandboxSpec{
		WorkDir: execLease.WorkspacePath,
		Network: buildNetworkPolicy(verdict.Profile),
		Limits:  buildResourceLimits(verdict.Profile),
	}
	if execLease.TemplateRef != "" {
		spec.Image = execLease.TemplateRef
	}

	return &PreparedExecution{
		Lease:      execLease,
		Spec:       spec,
		Verdict:    verdict,
		Tokens:     tokenIDs,
		PreparedAt: b.clock(),
	}, nil
}

// Execute runs prepared work in the appropriate sandbox.
// On completion (success or failure), it revokes credentials and completes the lease.
func (b *SandboxBroker) Execute(
	ctx context.Context,
	prepared *PreparedExecution,
) (*pkg_sandbox.Result, *pkg_sandbox.ExecutionReceipt, error) {
	b.mu.RLock()
	runner, ok := b.runners[prepared.Lease.Backend]
	b.mu.RUnlock()
	if !ok {
		return nil, nil, fmt.Errorf("no runner for backend %q", prepared.Lease.Backend)
	}

	// Validate spec before execution.
	if err := runner.Validate(prepared.Spec); err != nil {
		b.cleanup(ctx, prepared)
		return nil, nil, fmt.Errorf("validate sandbox spec: %w", err)
	}

	// Execute.
	result, receipt, err := runner.Run(prepared.Spec)

	// Always clean up regardless of outcome.
	b.cleanup(ctx, prepared)

	if err != nil {
		return result, receipt, fmt.Errorf("sandbox execution: %w", err)
	}
	return result, receipt, nil
}

// cleanup revokes tokens and completes the lease.
// Errors are logged but not returned — cleanup is best-effort.
func (b *SandboxBroker) cleanup(ctx context.Context, prepared *PreparedExecution) {
	// Revoke all issued tokens.
	for _, tokenID := range prepared.Tokens {
		if err := b.credBroker.RevokeToken(tokenID); err != nil {
			slog.Warn("failed to revoke scoped token during cleanup",
				"token_id", tokenID,
				"lease_id", prepared.Lease.LeaseID,
				"error", err,
			)
		}
	}

	// Complete the lease.
	if err := b.leases.Complete(ctx, prepared.Lease.LeaseID); err != nil {
		slog.Warn("failed to complete lease during cleanup",
			"lease_id", prepared.Lease.LeaseID,
			"error", err,
		)
	}
}

// buildNetworkPolicy constructs a network policy from an execution profile.
func buildNetworkPolicy(profile *effectgraph.ExecutionProfile) pkg_sandbox.NetworkPolicy {
	if profile.NetworkPolicy != nil {
		return *profile.NetworkPolicy
	}
	// Default: deny all networking for safety.
	switch profile.ProfileName {
	case "read-only":
		return pkg_sandbox.NetworkPolicy{Disabled: true}
	case "workspace-write":
		return pkg_sandbox.NetworkPolicy{Disabled: true}
	case "net-limited":
		return pkg_sandbox.NetworkPolicy{
			Disabled:   false,
			DNSAllowed: true,
			// EgressAllowlist must be configured per-step.
		}
	default:
		return pkg_sandbox.NetworkPolicy{Disabled: true}
	}
}

// buildResourceLimits constructs resource limits from an execution profile.
func buildResourceLimits(profile *effectgraph.ExecutionProfile) pkg_sandbox.ResourceLimits {
	if profile.Limits != nil {
		return *profile.Limits
	}
	// Sensible defaults by profile.
	switch profile.ProfileName {
	case "read-only":
		return pkg_sandbox.ResourceLimits{
			CPUMillis:    500,
			MemoryMB:     256,
			DiskMB:       100,
			Timeout:      5 * time.Minute,
			MaxProcesses: 10,
		}
	case "workspace-write":
		return pkg_sandbox.ResourceLimits{
			CPUMillis:    1000,
			MemoryMB:     512,
			DiskMB:       500,
			Timeout:      15 * time.Minute,
			MaxProcesses: 50,
		}
	case "build-runner", "net-limited":
		return pkg_sandbox.ResourceLimits{
			CPUMillis:    2000,
			MemoryMB:     1024,
			DiskMB:       2000,
			Timeout:      30 * time.Minute,
			MaxProcesses: 100,
		}
	default:
		return pkg_sandbox.ResourceLimits{
			CPUMillis:    500,
			MemoryMB:     256,
			DiskMB:       100,
			Timeout:      5 * time.Minute,
			MaxProcesses: 10,
		}
	}
}
