package sandbox

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effectgraph"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/intentcompiler"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/lease"
	pkg_sandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

// SandboxRunner is the interface for executing work in a sandbox.
// This mirrors sandbox.Runner but avoids circular imports.
type SandboxRunner interface {
	Run(spec *pkg_sandbox.SandboxSpec) (*pkg_sandbox.Result, *pkg_sandbox.ExecutionReceipt, error)
	Validate(spec *pkg_sandbox.SandboxSpec) error
}

// SandboxCredentialMaterial is ephemeral broker-to-runner material. It must
// never be serialized, logged, returned through PreparedExecution, or retained
// after the run. The binding metadata is signed through the lease; only the
// short-lived bearer value is minted after authorization.
type SandboxCredentialMaterial struct {
	SecretRef   string   `json:"-"`
	MountPath   string   `json:"-"`
	EnvVar      string   `json:"-"`
	Scopes      []string `json:"-"`
	BearerToken string   `json:"-"`
}

// SandboxCredentialRunner is required for leases with secret bindings. It
// keeps bearer material inside the broker-to-runner boundary instead of
// exposing it to the caller that holds PreparedExecution.
type SandboxCredentialRunner interface {
	SandboxRunner
	RunWithCredentials(spec *pkg_sandbox.SandboxSpec, credentials []SandboxCredentialMaterial) (*pkg_sandbox.Result, *pkg_sandbox.ExecutionReceipt, error)
}

// AuthorizationVerifier verifies the source-owned Kernel decision and the
// derived execution intent before any sandbox lease or credential side effect.
type AuthorizationVerifier interface {
	VerifyDecision(decision *contracts.DecisionRecord) (bool, error)
	VerifyIntent(intent *contracts.AuthorizedExecutionIntent) (bool, error)
}

const (
	// SandboxExecutionDecisionContextKey is the Guardian decision-context field
	// produced from PlanStep.Params["sandbox_execution"]. The signed value binds
	// the complete runner spec and exact immutable lease identity before the
	// lease is activated or credentials are issued.
	SandboxExecutionDecisionContextKey = "param.sandbox_execution"

	SandboxExecutionAuthorizationSchemaVersion = "sandbox_execution_authorization.v1"
)

// PreparedExecution bundles everything needed to run in a sandbox.
type PreparedExecution struct {
	// Lease is the execution lease governing this run.
	Lease *lease.ExecutionLease

	// Spec is the sandbox specification.
	Spec *pkg_sandbox.SandboxSpec

	// Verdict is the approved step verdict.
	Verdict *effectgraph.NodeVerdict

	// TokenIDs lists scoped token IDs issued for cleanup and audit.
	TokenIDs []string

	// PreparedAt is when the execution was prepared.
	PreparedAt time.Time
}

// SandboxWorkload is the caller-supplied executable material that must be
// present before lease activation, credential issuance, and preparation
// sealing. Policy-owned image, work directory, network, limits, runtime class,
// mounts, and warm-lease fields are deliberately not caller-configurable here.
type SandboxWorkload struct {
	Command []string          `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
	// Detached is reserved for a future durable supervisor that can retain the
	// lease and credentials until the background process is proven stopped.
	// PrepareExecutionWithWorkload currently rejects true fail-closed.
	Detached bool `json:"detached,omitempty"`
}

// SandboxLeaseAuthorization is the immutable, secret-free identity of one
// source-owned execution lease. Lifecycle fields that necessarily change when
// the lease is activated are excluded; LeaseID and every field that selects or
// constrains execution remain signed.
type SandboxLeaseAuthorization struct {
	LeaseID          string                `json:"lease_id"`
	RunID            string                `json:"run_id"`
	WorkspacePath    string                `json:"workspace_path"`
	TemplateRef      string                `json:"template_ref"`
	Backend          string                `json:"backend"`
	ProfileName      string                `json:"profile_name"`
	NetworkPolicyRef string                `json:"network_policy_ref,omitempty"`
	SecretBindings   []lease.SecretBinding `json:"secret_bindings"`
	TTL              time.Duration         `json:"ttl"`
	EffectGraphHash  string                `json:"effect_graph_hash"`
	CreatedAt        time.Time             `json:"created_at"`
	ExpiresAt        time.Time             `json:"expires_at"`
}

// SandboxExecutionAuthorization is the complete decision payload required for
// preparation. Spec includes the image, command, arguments, environment,
// workspace, network policy, limits, mounts, runtime class, and warm-lease
// configuration. Lease binds that spec to one exact source-owned allocation.
type SandboxExecutionAuthorization struct {
	SchemaVersion string                    `json:"schema_version"`
	SandboxID     string                    `json:"sandbox_id"`
	Lease         SandboxLeaseAuthorization `json:"lease"`
	Spec          pkg_sandbox.SandboxSpec   `json:"spec"`
}

// preparedExecutionRecord is broker-owned execution state. Execute uses this
// immutable snapshot rather than caller-mutable PreparedExecution fields after
// it has proved the exact returned pointer and fingerprint are still current.
type preparedExecutionRecord struct {
	fingerprint   string
	backend       string
	leaseID       string
	sandboxID     string
	runner        SandboxRunner
	authorization SandboxExecutionAuthorization
	spec          pkg_sandbox.SandboxSpec
	tokenIDs      []string
	credentials   []SandboxCredentialMaterial
}

// SandboxBroker mediates between approved effect graphs and execution backends.
// It manages lease activation, credential issuance, sandbox specification
// construction, and execution orchestration.
type SandboxBroker struct {
	mu         sync.RWMutex
	credBroker *CredentialBroker
	leases     lease.LeaseManager
	verifier   AuthorizationVerifier
	runners    map[string]SandboxRunner // backend name → runner
	prepared   map[*PreparedExecution]preparedExecutionRecord
	clock      func() time.Time
}

// WithAuthorizationVerifier installs the Kernel trust-root verifier. A broker
// without one remains fail-closed at preparation.
func (b *SandboxBroker) WithAuthorizationVerifier(verifier AuthorizationVerifier) *SandboxBroker {
	b.verifier = verifier
	return b
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
		prepared:   make(map[*PreparedExecution]preparedExecutionRecord),
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

// PrepareExecution is the deprecated implicit-workload entrypoint. It fails
// closed because an executable command must be bound before preparation is
// sealed. Call PrepareExecutionWithWorkload instead.
func (b *SandboxBroker) PrepareExecution(
	ctx context.Context,
	execLease *lease.ExecutionLease,
	verdict *effectgraph.NodeVerdict,
) (*PreparedExecution, error) {
	return nil, fmt.Errorf("explicit sandbox workload is required; use PrepareExecutionWithWorkload")
}

// PrepareExecutionWithWorkload builds everything needed for a sandbox run.
// It validates executable material before activating the lease, issuing
// credentials, and sealing the complete SandboxSpec.
func (b *SandboxBroker) PrepareExecutionWithWorkload(
	ctx context.Context,
	execLease *lease.ExecutionLease,
	verdict *effectgraph.NodeVerdict,
	workload *SandboxWorkload,
) (*PreparedExecution, error) {
	if execLease == nil {
		return nil, fmt.Errorf("lease is nil")
	}
	if verdict == nil || verdict.Profile == nil {
		return nil, fmt.Errorf("verdict or profile is nil")
	}
	if verdict.Decision == nil || verdict.Decision.Verdict != string(contracts.VerdictAllow) || verdict.Intent == nil {
		return nil, fmt.Errorf("verdict is not backed by an ALLOW decision and execution intent")
	}
	if !executableSandboxProfile(verdict.Profile.ProfileName) {
		return nil, fmt.Errorf("sandbox profile %q is not executable", verdict.Profile.ProfileName)
	}
	if err := validateSandboxWorkload(workload); err != nil {
		return nil, err
	}
	// Establish signature trust before resolving a caller-selected lease ID.
	// This prevents unsigned inputs from using the lease store as an oracle.
	if err := b.verifySandboxAuthority(verdict); err != nil {
		return nil, err
	}
	sourceLease, err := b.resolvePendingLease(ctx, execLease)
	if err != nil {
		return nil, err
	}
	authorization, err := BuildSandboxExecutionAuthorization(sourceLease, verdict.Profile, workload)
	if err != nil {
		return nil, err
	}
	if err := verifySandboxExecutionDecisionBinding(verdict.Decision, authorization); err != nil {
		return nil, err
	}

	// Verify runner exists.
	b.mu.RLock()
	runner, hasRunner := b.runners[sourceLease.Backend]
	b.mu.RUnlock()
	if !hasRunner || runner == nil {
		return nil, fmt.Errorf("no runner registered for backend %q", sourceLease.Backend)
	}
	if len(sourceLease.SecretBindings) > 0 {
		if _, ok := runner.(SandboxCredentialRunner); !ok {
			return nil, fmt.Errorf("runner for backend %q cannot receive broker-sealed credentials", sourceLease.Backend)
		}
	}

	// Activate the exact sandbox instance already derived from the immutable
	// lease and bound by the signed decision.
	sandboxID := authorization.SandboxID
	if err := b.leases.Activate(ctx, sourceLease.LeaseID, sandboxID); err != nil {
		return nil, fmt.Errorf("activate lease: %w", err)
	}

	// Issue scoped credentials.
	var tokenIDs []string
	var credentials []SandboxCredentialMaterial
	for _, binding := range sourceLease.SecretBindings {
		token, err := b.credBroker.IssueToken(TokenRequest{
			SandboxID:       sandboxID,
			RequestedScopes: binding.Scopes,
			TTLSeconds:      int(sourceLease.TTL.Seconds()),
		})
		if err != nil {
			// Best effort: revoke already-issued tokens and lease.
			for _, tid := range tokenIDs {
				_ = b.credBroker.RevokeToken(tid)
			}
			_ = b.leases.Revoke(ctx, sourceLease.LeaseID, fmt.Sprintf("credential issuance failed: %v", err))
			return nil, fmt.Errorf("issue credential for %s: %w", binding.SecretRef, err)
		}
		tokenIDs = append(tokenIDs, token.TokenID)
		credentials = append(credentials, SandboxCredentialMaterial{
			SecretRef:   binding.SecretRef,
			MountPath:   binding.MountPath,
			EnvVar:      binding.EnvVar,
			Scopes:      append([]string(nil), binding.Scopes...),
			BearerToken: token.BearerToken,
		})
	}

	// Use the byte-equivalent spec that was already bound by the signed
	// decision. No runtime field is filled from unsigned inputs after this point.
	spec := cloneSandboxSpec(&authorization.Spec)

	prepared := &PreparedExecution{
		Lease:      cloneExecutionLease(sourceLease),
		Spec:       &spec,
		Verdict:    verdict,
		TokenIDs:   tokenIDs,
		PreparedAt: b.clock(),
	}
	fingerprint, err := preparedExecutionFingerprint(prepared)
	if err != nil {
		for _, tokenID := range tokenIDs {
			_ = b.credBroker.RevokeToken(tokenID)
		}
		_ = b.leases.Revoke(ctx, sourceLease.LeaseID, fmt.Sprintf("seal prepared execution: %v", err))
		return nil, fmt.Errorf("seal prepared execution: %w", err)
	}
	b.mu.Lock()
	b.prepared[prepared] = preparedExecutionRecord{
		fingerprint:   fingerprint,
		backend:       sourceLease.Backend,
		leaseID:       sourceLease.LeaseID,
		sandboxID:     sandboxID,
		runner:        runner,
		authorization: cloneSandboxExecutionAuthorization(authorization),
		spec:          cloneSandboxSpec(&spec),
		tokenIDs:      append([]string(nil), tokenIDs...),
		credentials:   cloneSandboxCredentialMaterial(credentials),
	}
	b.mu.Unlock()
	return prepared, nil
}

func (b *SandboxBroker) resolvePendingLease(ctx context.Context, execLease *lease.ExecutionLease) (*lease.ExecutionLease, error) {
	current, err := b.leases.Get(ctx, execLease.LeaseID)
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox execution lease: %w", err)
	}
	if current == nil || current.Status != lease.LeaseStatusPending {
		return nil, fmt.Errorf("sandbox execution lease is missing or not pending")
	}
	currentHash, err := canonicalize.CanonicalHash(current)
	if err != nil {
		return nil, fmt.Errorf("canonicalize source-owned sandbox lease: %w", err)
	}
	requestedHash, err := canonicalize.CanonicalHash(execLease)
	if err != nil {
		return nil, fmt.Errorf("canonicalize requested sandbox lease: %w", err)
	}
	if currentHash != requestedHash {
		return nil, fmt.Errorf("sandbox execution lease does not match source-owned state")
	}
	return current, nil
}

// BuildSandboxExecutionAuthorization constructs the complete, secret-free
// value that the Kernel must sign before this broker may activate a lease. The
// same function is used at dispatch, preventing a producer/consumer split in
// how the runtime spec or lease identity is canonicalized.
func BuildSandboxExecutionAuthorization(execLease *lease.ExecutionLease, profile *effectgraph.ExecutionProfile, workload *SandboxWorkload) (SandboxExecutionAuthorization, error) {
	if execLease == nil {
		return SandboxExecutionAuthorization{}, fmt.Errorf("lease is nil")
	}
	if profile == nil {
		return SandboxExecutionAuthorization{}, fmt.Errorf("sandbox execution profile is nil")
	}
	if err := validateSandboxWorkload(workload); err != nil {
		return SandboxExecutionAuthorization{}, err
	}
	if execLease.LeaseID == "" || execLease.TemplateRef == "" {
		return SandboxExecutionAuthorization{}, fmt.Errorf("lease identity and template reference are required")
	}
	if profile.Backend != execLease.Backend {
		return SandboxExecutionAuthorization{}, fmt.Errorf("backend mismatch: lease=%q verdict=%q", execLease.Backend, profile.Backend)
	}
	if profile.ProfileName != execLease.ProfileName {
		return SandboxExecutionAuthorization{}, fmt.Errorf("profile mismatch: lease=%q verdict=%q", execLease.ProfileName, profile.ProfileName)
	}
	if !executableSandboxProfile(profile.ProfileName) {
		return SandboxExecutionAuthorization{}, fmt.Errorf("sandbox profile %q is not executable", profile.ProfileName)
	}

	spec := pkg_sandbox.SandboxSpec{
		Image:    execLease.TemplateRef,
		Command:  append([]string(nil), workload.Command...),
		Args:     append([]string(nil), workload.Args...),
		Env:      cloneStringMap(workload.Env),
		Labels:   cloneStringMap(workload.Labels),
		Detached: workload.Detached,
		WorkDir:  execLease.WorkspacePath,
		Network:  buildNetworkPolicy(profile),
		Limits:   buildResourceLimits(profile),
	}
	leaseAuthorization := sandboxLeaseAuthorization(execLease)
	leaseHash, err := canonicalize.CanonicalHash(leaseAuthorization)
	if err != nil {
		return SandboxExecutionAuthorization{}, fmt.Errorf("derive sandbox instance identity: %w", err)
	}
	return SandboxExecutionAuthorization{
		SchemaVersion: SandboxExecutionAuthorizationSchemaVersion,
		SandboxID:     "sbx-" + leaseHash,
		Lease:         leaseAuthorization,
		Spec:          spec,
	}, nil
}

func (b *SandboxBroker) verifySandboxAuthority(verdict *effectgraph.NodeVerdict) error {
	decision := verdict.Decision
	intent := verdict.Intent
	if b.verifier == nil {
		return fmt.Errorf("sandbox authorization verifier is required")
	}
	if decision.ID == "" || intent.DecisionID != decision.ID {
		return fmt.Errorf("sandbox execution intent does not bind the decision")
	}
	if decision.EffectDigest == "" || intent.EffectDigestHash != decision.EffectDigest {
		return fmt.Errorf("sandbox execution intent does not bind the decision effect digest")
	}
	if decision.Action == "" || intent.AllowedTool != decision.Action {
		return fmt.Errorf("sandbox execution intent does not bind the allowed tool")
	}
	now := b.clock()
	if intent.IssuedAt.After(now) || intent.ExpiresAt.IsZero() || !now.Before(intent.ExpiresAt) {
		return fmt.Errorf("sandbox execution intent is not currently valid")
	}
	verified, err := b.verifier.VerifyDecision(decision)
	if err != nil {
		return fmt.Errorf("sandbox decision signature verification failed: %w", err)
	}
	if !verified {
		return fmt.Errorf("sandbox decision signature verification failed")
	}
	verified, err = b.verifier.VerifyIntent(intent)
	if err != nil {
		return fmt.Errorf("sandbox execution intent signature verification failed: %w", err)
	}
	if !verified {
		return fmt.Errorf("sandbox execution intent signature verification failed")
	}
	return nil
}

func verifySandboxExecutionDecisionBinding(decision *contracts.DecisionRecord, expected SandboxExecutionAuthorization) error {
	authorizedExecution, ok := decision.InputContext[SandboxExecutionDecisionContextKey]
	if !ok || authorizedExecution == nil {
		return fmt.Errorf("sandbox decision does not contain a complete execution authorization")
	}
	authorizedHash, err := canonicalize.CanonicalHash(authorizedExecution)
	if err != nil {
		return fmt.Errorf("canonicalize authorized sandbox execution: %w", err)
	}
	expectedHash, err := canonicalize.CanonicalHash(expected)
	if err != nil {
		return fmt.Errorf("canonicalize requested sandbox execution: %w", err)
	}
	if authorizedHash != expectedHash {
		return fmt.Errorf("sandbox execution spec or lease does not match the signed decision context")
	}
	return nil
}

func validateSandboxWorkload(workload *SandboxWorkload) error {
	if workload == nil || len(workload.Command) == 0 || workload.Command[0] == "" {
		return fmt.Errorf("sandbox workload requires an explicit command")
	}
	if workload.Detached {
		return fmt.Errorf("detached sandbox execution requires a durable lifecycle supervisor and is not supported")
	}
	for _, part := range workload.Command {
		if part == "" {
			return fmt.Errorf("sandbox workload command cannot contain empty elements")
		}
	}
	for key := range workload.Env {
		if key == "" {
			return fmt.Errorf("sandbox workload environment variable name is empty")
		}
	}
	for key := range workload.Labels {
		if key == "" {
			return fmt.Errorf("sandbox workload label name is empty")
		}
	}
	return nil
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func executableSandboxProfile(profile string) bool {
	switch profile {
	case intentcompiler.ProfileReadOnly,
		intentcompiler.ProfileWorkspaceWrite,
		intentcompiler.ProfileBuildRunner,
		intentcompiler.ProfileNetLimited:
		return true
	default:
		return false
	}
}

// Execute runs prepared work in the appropriate sandbox.
// On completion (success or failure), it revokes credentials and completes the lease.
func (b *SandboxBroker) Execute(
	ctx context.Context,
	prepared *PreparedExecution,
) (*pkg_sandbox.Result, *pkg_sandbox.ExecutionReceipt, error) {
	record, err := b.claimPreparedExecution(ctx, prepared)
	if err != nil {
		return nil, nil, err
	}

	runner := record.runner
	if runner == nil {
		cleanup := b.cleanupRecord(ctx, record)
		return nil, nil, fmt.Errorf("no runner for backend %q (cleanup=%s)", record.backend, cleanup.Status)
	}

	// Validate spec before execution.
	if err := runner.Validate(&record.spec); err != nil {
		b.cleanupRecord(ctx, record)
		return nil, nil, fmt.Errorf("validate sandbox spec: %w", err)
	}

	// Execute. Bearer material crosses only the broker-to-runner interface and
	// is never present in the caller-visible PreparedExecution or signed spec.
	var result *pkg_sandbox.Result
	var receipt *pkg_sandbox.ExecutionReceipt
	if len(record.credentials) > 0 {
		credentialRunner, ok := runner.(SandboxCredentialRunner)
		if !ok {
			cleanup := b.cleanupRecord(ctx, record)
			return nil, nil, fmt.Errorf("runner for backend %q lost credential capability (cleanup=%s)", record.backend, cleanup.Status)
		}
		result, receipt, err = credentialRunner.RunWithCredentials(&record.spec, cloneSandboxCredentialMaterial(record.credentials))
	} else {
		result, receipt, err = runner.Run(&record.spec)
	}
	clearSandboxCredentialMaterial(record.credentials)

	// Always clean up regardless of outcome.
	cleanup := b.cleanupRecord(ctx, record)
	applyCleanupStatus(result, receipt, cleanup)

	if err != nil {
		return result, receipt, fmt.Errorf("sandbox execution: %w", err)
	}
	return result, receipt, nil
}

// claimPreparedExecution atomically consumes one exact broker-prepared object.
// A caller-constructed value, a copied value, a mutated value, or a replay is
// rejected before runner lookup or validation.
func (b *SandboxBroker) claimPreparedExecution(ctx context.Context, prepared *PreparedExecution) (preparedExecutionRecord, error) {
	if prepared == nil {
		return preparedExecutionRecord{}, fmt.Errorf("prepared execution is incomplete")
	}
	b.mu.Lock()
	record, ok := b.prepared[prepared]
	if ok {
		delete(b.prepared, prepared)
	}
	b.mu.Unlock()
	if !ok {
		return preparedExecutionRecord{}, fmt.Errorf("execution was not prepared by this broker or was already consumed")
	}
	if err := validatePreparedExecutionAuthority(prepared, b.clock()); err != nil {
		cleanup := b.cleanupRecord(ctx, record)
		return preparedExecutionRecord{}, fmt.Errorf("%w (cleanup=%s)", err, cleanup.Status)
	}

	fingerprint, err := preparedExecutionFingerprint(prepared)
	if err != nil || fingerprint != record.fingerprint {
		cleanup := b.cleanupRecord(ctx, record)
		if err != nil {
			return preparedExecutionRecord{}, fmt.Errorf("canonicalize prepared execution for dispatch: %w (cleanup=%s)", err, cleanup.Status)
		}
		return preparedExecutionRecord{}, fmt.Errorf("prepared execution changed after authorization (cleanup=%s)", cleanup.Status)
	}
	// Re-resolve the trust root immediately before the runner boundary so key
	// revocation or intent expiry after preparation cannot be ignored.
	if err := b.verifySandboxAuthority(prepared.Verdict); err != nil {
		cleanup := b.cleanupRecord(ctx, record)
		return preparedExecutionRecord{}, fmt.Errorf("prepared execution authority is no longer valid: %w (cleanup=%s)", err, cleanup.Status)
	}
	if err := verifySandboxExecutionDecisionBinding(prepared.Verdict.Decision, record.authorization); err != nil {
		cleanup := b.cleanupRecord(ctx, record)
		return preparedExecutionRecord{}, fmt.Errorf("prepared execution decision binding is no longer valid: %w (cleanup=%s)", err, cleanup.Status)
	}
	currentLease, err := b.leases.Get(ctx, record.leaseID)
	if err != nil {
		cleanup := b.cleanupRecord(ctx, record)
		return preparedExecutionRecord{}, fmt.Errorf("resolve prepared execution lease: %w (cleanup=%s)", err, cleanup.Status)
	}
	if currentLease == nil {
		cleanup := b.cleanupRecord(ctx, record)
		return preparedExecutionRecord{}, fmt.Errorf("prepared execution lease is missing (cleanup=%s)", cleanup.Status)
	}
	if currentLease.Status != lease.LeaseStatusActive || currentLease.SandboxID != record.sandboxID || !b.clock().Before(currentLease.ExpiresAt) {
		cleanup := b.cleanupRecord(ctx, record)
		return preparedExecutionRecord{}, fmt.Errorf("prepared execution lease is stale or changed (cleanup=%s)", cleanup.Status)
	}
	currentLeaseHash, err := canonicalize.CanonicalHash(sandboxLeaseAuthorization(currentLease))
	if err != nil {
		cleanup := b.cleanupRecord(ctx, record)
		return preparedExecutionRecord{}, fmt.Errorf("canonicalize current prepared execution lease: %w (cleanup=%s)", err, cleanup.Status)
	}
	authorizedLeaseHash, err := canonicalize.CanonicalHash(record.authorization.Lease)
	if err != nil || currentLeaseHash != authorizedLeaseHash {
		cleanup := b.cleanupRecord(ctx, record)
		if err != nil {
			return preparedExecutionRecord{}, fmt.Errorf("canonicalize authorized prepared execution lease: %w (cleanup=%s)", err, cleanup.Status)
		}
		return preparedExecutionRecord{}, fmt.Errorf("prepared execution lease identity changed after authorization (cleanup=%s)", cleanup.Status)
	}
	return record, nil
}

func validatePreparedExecutionAuthority(prepared *PreparedExecution, now time.Time) error {
	if prepared == nil || prepared.Lease == nil || prepared.Spec == nil || prepared.Verdict == nil || prepared.Verdict.Profile == nil {
		return fmt.Errorf("prepared execution is incomplete")
	}
	if prepared.Verdict.Decision == nil || prepared.Verdict.Decision.Verdict != string(contracts.VerdictAllow) || prepared.Verdict.Intent == nil {
		return fmt.Errorf("prepared execution is not backed by an ALLOW decision and execution intent")
	}
	if !executableSandboxProfile(prepared.Verdict.Profile.ProfileName) {
		return fmt.Errorf("sandbox profile %q is not executable", prepared.Verdict.Profile.ProfileName)
	}
	if prepared.Verdict.Profile.Backend != prepared.Lease.Backend {
		return fmt.Errorf("backend mismatch: lease=%q verdict=%q", prepared.Lease.Backend, prepared.Verdict.Profile.Backend)
	}
	if prepared.Verdict.Profile.ProfileName != prepared.Lease.ProfileName {
		return fmt.Errorf("profile mismatch: lease=%q verdict=%q", prepared.Lease.ProfileName, prepared.Verdict.Profile.ProfileName)
	}
	if prepared.Verdict.Intent.IssuedAt.After(now) || prepared.Verdict.Intent.ExpiresAt.IsZero() || !now.Before(prepared.Verdict.Intent.ExpiresAt) {
		return fmt.Errorf("prepared execution intent is not currently valid")
	}
	return nil
}

func preparedExecutionFingerprint(prepared *PreparedExecution) (string, error) {
	return canonicalize.CanonicalHash(prepared)
}

func sandboxLeaseAuthorization(execLease *lease.ExecutionLease) SandboxLeaseAuthorization {
	secretBindings := make([]lease.SecretBinding, len(execLease.SecretBindings))
	for index, binding := range execLease.SecretBindings {
		secretBindings[index] = binding
		secretBindings[index].Scopes = append([]string(nil), binding.Scopes...)
	}
	return SandboxLeaseAuthorization{
		LeaseID:          execLease.LeaseID,
		RunID:            execLease.RunID,
		WorkspacePath:    execLease.WorkspacePath,
		TemplateRef:      execLease.TemplateRef,
		Backend:          execLease.Backend,
		ProfileName:      execLease.ProfileName,
		NetworkPolicyRef: execLease.NetworkPolicyRef,
		SecretBindings:   secretBindings,
		TTL:              execLease.TTL,
		EffectGraphHash:  execLease.EffectGraphHash,
		CreatedAt:        execLease.CreatedAt,
		ExpiresAt:        execLease.ExpiresAt,
	}
}

func cloneExecutionLease(execLease *lease.ExecutionLease) *lease.ExecutionLease {
	if execLease == nil {
		return nil
	}
	cloned := *execLease
	cloned.SecretBindings = make([]lease.SecretBinding, len(execLease.SecretBindings))
	for index, binding := range execLease.SecretBindings {
		cloned.SecretBindings[index] = binding
		cloned.SecretBindings[index].Scopes = append([]string(nil), binding.Scopes...)
	}
	return &cloned
}

func cloneSandboxExecutionAuthorization(authorization SandboxExecutionAuthorization) SandboxExecutionAuthorization {
	cloned := authorization
	cloned.Lease.SecretBindings = make([]lease.SecretBinding, len(authorization.Lease.SecretBindings))
	for index, binding := range authorization.Lease.SecretBindings {
		cloned.Lease.SecretBindings[index] = binding
		cloned.Lease.SecretBindings[index].Scopes = append([]string(nil), binding.Scopes...)
	}
	cloned.Spec = cloneSandboxSpec(&authorization.Spec)
	return cloned
}

func cloneSandboxCredentialMaterial(credentials []SandboxCredentialMaterial) []SandboxCredentialMaterial {
	cloned := make([]SandboxCredentialMaterial, len(credentials))
	for index, credential := range credentials {
		cloned[index] = credential
		cloned[index].Scopes = append([]string(nil), credential.Scopes...)
	}
	return cloned
}

func clearSandboxCredentialMaterial(credentials []SandboxCredentialMaterial) {
	for index := range credentials {
		credentials[index].BearerToken = ""
		credentials[index].Scopes = nil
	}
}

func cloneSandboxSpec(spec *pkg_sandbox.SandboxSpec) pkg_sandbox.SandboxSpec {
	cloned := *spec
	cloned.Command = append([]string(nil), spec.Command...)
	cloned.Args = append([]string(nil), spec.Args...)
	cloned.Mounts = append([]pkg_sandbox.Mount(nil), spec.Mounts...)
	cloned.Network.EgressAllowlist = append([]string(nil), spec.Network.EgressAllowlist...)
	if spec.Env != nil {
		cloned.Env = make(map[string]string, len(spec.Env))
		for key, value := range spec.Env {
			cloned.Env[key] = value
		}
	}
	if spec.Labels != nil {
		cloned.Labels = make(map[string]string, len(spec.Labels))
		for key, value := range spec.Labels {
			cloned.Labels[key] = value
		}
	}
	if spec.WarmLeaseConfig != nil {
		warmLease := *spec.WarmLeaseConfig
		cloned.WarmLeaseConfig = &warmLease
	}
	return cloned
}

// cleanup revokes tokens and completes the lease.
func (b *SandboxBroker) cleanupRecord(ctx context.Context, prepared preparedExecutionRecord) pkg_sandbox.CleanupStatus {
	defer clearSandboxCredentialMaterial(prepared.credentials)
	var revokeErrors []string

	// Revoke all issued tokens.
	for _, tokenID := range prepared.tokenIDs {
		if err := b.credBroker.RevokeToken(tokenID); err != nil {
			revokeErrors = append(revokeErrors, fmt.Sprintf("revoke token %s: %v", tokenID, err))
			slog.Warn("failed to revoke scoped token during cleanup",
				"token_id", tokenID,
				"lease_id", prepared.leaseID,
				"error", err,
			)
		}
	}

	// Complete the lease.
	completeErr := b.leases.Complete(ctx, prepared.leaseID)
	if completeErr != nil {
		slog.Warn("failed to complete lease during cleanup",
			"lease_id", prepared.leaseID,
			"error", completeErr,
		)
	}

	switch {
	case completeErr != nil && len(revokeErrors) > 0:
		return pkg_sandbox.CleanupStatus{
			Status: "error",
			Errors: append(revokeErrors, fmt.Sprintf("complete lease %s: %v", prepared.leaseID, completeErr)),
		}
	case completeErr != nil:
		return pkg_sandbox.CleanupStatus{
			Status: "unknown",
			Errors: []string{fmt.Sprintf("complete lease %s: %v", prepared.leaseID, completeErr)},
		}
	case len(revokeErrors) > 0:
		return pkg_sandbox.CleanupStatus{
			Status: "degraded",
			Errors: revokeErrors,
		}
	default:
		return pkg_sandbox.CleanupStatus{Status: "ok"}
	}
}

func applyCleanupStatus(result *pkg_sandbox.Result, receipt *pkg_sandbox.ExecutionReceipt, cleanup pkg_sandbox.CleanupStatus) {
	if result != nil {
		result.Cleanup = cleanup
	}
	if receipt != nil {
		receipt.Result.Cleanup = cleanup
	}
}

// buildNetworkPolicy constructs a network policy from an execution profile.
func buildNetworkPolicy(profile *effectgraph.ExecutionProfile) pkg_sandbox.NetworkPolicy {
	if profile.NetworkPolicy != nil {
		policy := *profile.NetworkPolicy
		policy.EgressAllowlist = append([]string(nil), profile.NetworkPolicy.EgressAllowlist...)
		return policy
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
