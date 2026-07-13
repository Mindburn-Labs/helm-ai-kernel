package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effectdigest"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/interfaces"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/manifest"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receipts/policies"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/safedep"
)

// UsageMeter is an optional interface for recording execution usage events.
// Implementations may be injected for commercial metering; the canonical
// standard operates correctly with a nil meter.
type UsageMeter interface {
	Record(ctx context.Context, event UsageEvent) error
}

// UsageEvent represents an execution usage event for optional metering.
type UsageEvent struct {
	TenantID  string         `json:"tenant_id"`
	EventType string         `json:"event_type"`
	Quantity  int64          `json:"quantity"`
	Timestamp time.Time      `json:"timestamp"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// Executor runs an effect if and only if it has a valid, notarized decision AND an execution intent.
type Executor interface {
	Execute(ctx context.Context, effect *contracts.Effect, decision *contracts.DecisionRecord, intent *contracts.AuthorizedExecutionIntent) (*contracts.Receipt, *interfaces.Artifact, error)
}

// OutputSchemaRegistry provides tool output schemas for drift detection.
type OutputSchemaRegistry interface {
	LookupOutput(toolName string) *manifest.ToolOutputSchema
}

type SafeDepGate interface {
	Gate(ctx context.Context, req safedep.GateRequest) (safedep.GateResult, error)
}

// SafeExecutor enforces strict gating and authorized execution.
// Per Section 1.4: Receipt policy enforcement is fail-closed.
// Per KERNEL_TCB §3: uses injected authority clock, never wall-clock time.Now().
type SafeExecutor struct {
	verifier             crypto.Verifier
	signer               crypto.Signer
	driver               ToolDriver
	receiptStore         ReceiptStore
	artifactStore        artifacts.Store
	outboxStore          OutboxStore
	currentPhenotypeHash string
	AuditLog             crypto.AuditLog
	policyEnforcer       *policies.PolicyEnforcer
	meter                UsageMeter
	outputSchemaRegistry OutputSchemaRegistry
	safeDepGate          SafeDepGate
	safeDepResolver      safedep.AuthorityResolver
	safeDepRequired      bool
	clock                func() time.Time // Authority clock (KERNEL_TCB §3)
}

// NewSafeExecutor creates a new SafeExecutor.
// Uses an injected authority clock (KERNEL_TCB §3).
func NewSafeExecutor(verifier crypto.Verifier, signer crypto.Signer, driver ToolDriver, store ReceiptStore, artStore artifacts.Store, outbox OutboxStore, phenotypeHash string, auditLog crypto.AuditLog, meter UsageMeter, outputRegistry OutputSchemaRegistry, clock func() time.Time) *SafeExecutor {
	if clock == nil {
		clock = time.Now // Fallback for safety, though strictly should be provided
	}
	return &SafeExecutor{
		verifier:             verifier,
		signer:               signer,
		driver:               driver,
		receiptStore:         store,
		artifactStore:        artStore,
		outboxStore:          outbox,
		currentPhenotypeHash: phenotypeHash,
		AuditLog:             auditLog,
		policyEnforcer:       policies.NewPolicyEnforcer(true), // Strict mode enabled
		meter:                meter,
		outputSchemaRegistry: outputRegistry,
		safeDepGate:          safedep.NewController(safedep.ControllerConfig{Clock: clock}),
		safeDepRequired:      true,
		clock:                clock,
	}
}

// WithClock overrides the clock for deterministic testing and production authority clock injection.
// Per KERNEL_TCB §3: the kernel MUST NOT use wall-clock time.Now().
func (e *SafeExecutor) WithClock(clock func() time.Time) *SafeExecutor {
	e.clock = clock
	return e
}

func (e *SafeExecutor) WithSafeDepGate(gate SafeDepGate) *SafeExecutor {
	e.safeDepGate = gate
	e.safeDepRequired = true
	return e
}

// WithSafeDepAuthorityResolver configures the server-owned source of Safe
// Deprecation authority. A resolver or gate configured without the other
// fails closed at the effect boundary rather than falling back to decision
// InputContext.
func (e *SafeExecutor) WithSafeDepAuthorityResolver(resolver safedep.AuthorityResolver) *SafeExecutor {
	e.safeDepResolver = resolver
	e.safeDepRequired = true
	return e
}

// Execute returns the Receipt (proof) and the Tool Result (Artifact), or error.
func (e *SafeExecutor) Execute(ctx context.Context, effect *contracts.Effect, decision *contracts.DecisionRecord, intent *contracts.AuthorizedExecutionIntent) (*contracts.Receipt, *interfaces.Artifact, error) {
	// 0. Pre-flight Checks
	if decision == nil {
		return nil, nil, errors.New("execution blocked: missing decision")
	}

	// 1. Gating & Verification
	if err := e.validateGating(decision, intent, effect); err != nil {
		return nil, nil, err
	}

	// Idempotency lookup is deliberately after signature and binding checks.
	// A caller cannot learn or replay a prior receipt by presenting an
	// unverified decision ID.
	if receipt, ok := e.checkIdempotency(ctx, intent.ID); ok {
		artifact := &interfaces.Artifact{
			SchemaID:    "system/execution-status",
			ContentType: "application/json",
			Digest:      receipt.OutputHash,
			Preview:     fmt.Sprintf("Already executed. Receipt: %s", receipt.ReceiptID),
		}
		return receipt, artifact, nil
	}

	// 2. Snapshot Verification
	blobHash, err := e.verifySnapshot(ctx, decision)
	if err != nil {
		return nil, nil, err
	}

	// 3. Execution Prep
	toolName, ok := effect.Params["tool_name"].(string)
	if !ok {
		// Fallback: Use intent AllowedTool
		if intent.AllowedTool != "" {
			toolName = intent.AllowedTool
		} else {
			return nil, nil, errors.New("tool_name missing in params")
		}
	}
	if intent.AllowedTool != "" && intent.AllowedTool != toolName {
		return nil, nil, fmt.Errorf("intent violation: allowed_tool '%s' does not match requested '%s'", intent.AllowedTool, toolName)
	}

	safeDepResult, err := e.gateSafeDep(ctx, decision, effect, toolName)
	if err != nil {
		return nil, nil, err
	}

	// 4. Tool verification
	// Check against dynamic policy enforcer
	if !e.policyEnforcer.IsToolAllowed(toolName) {
		return nil, nil, fmt.Errorf("policy violation: tool '%s' is prohibited by active regulation", toolName)
	}

	// 5. Atomically reserve this signed intent before the external driver. A
	// receipt lookup alone cannot prevent two executors from both observing a
	// missing receipt and dispatching an irreversible effect concurrently.
	if e.outboxStore == nil {
		return nil, nil, errors.New("execution blocked: durable outbox claim store is required")
	}
	claim, err := e.outboxStore.Claim(ctx, effect, intent)
	if err != nil {
		return nil, nil, fmt.Errorf("execution blocked: claim durable outbox reservation: %w", err)
	}
	switch claim.State {
	case OutboxClaimed:
		// This executor owns the sole dispatch reservation.
	case OutboxCompleted:
		return nil, nil, fmt.Errorf("execution blocked: outbox marks intent %q complete but no matching execution receipt exists", intent.ID)
	case OutboxInProgress:
		return nil, nil, fmt.Errorf("execution blocked: intent %q already has an active or ambiguous dispatch claim", intent.ID)
	case OutboxPending:
		return nil, nil, fmt.Errorf("execution blocked: intent %q is pending asynchronous dispatch and cannot be executed directly", intent.ID)
	default:
		return nil, nil, fmt.Errorf("execution blocked: unsupported outbox claim state %q", claim.State)
	}

	// 5. Dispatch
	// Used to be e.mcpClient.Call(toolName, effect.Params)
	result, err := e.driver.Execute(ctx, toolName, effect.Params)
	if err != nil {
		return nil, nil, err
	}

	// 5.5 Validate connector output against pinned schema (fail-closed on drift)
	if e.outputSchemaRegistry != nil {
		if outSchema := e.outputSchemaRegistry.LookupOutput(toolName); outSchema != nil {
			outResult, outErr := manifest.ValidateAndCanonicalizeToolOutput(outSchema, result)
			if outErr != nil {
				return nil, nil, fmt.Errorf("ERR_CONNECTOR_CONTRACT_DRIFT: %w", outErr)
			}
			effect.OutputHash = outResult.OutputHash
		}
	}

	schemaID := "application/json"
	if _, ok := result.(string); ok {
		schemaID = "text/plain"
	}

	artifact, err := canonicalize.Canonicalize(schemaID, result)
	if err != nil {
		// If canonicalization fails, we treat it as an execution error (fail-safe)
		// Or we could wrap it in an error artifact. For high-assurance, fail.
		return nil, nil, fmt.Errorf("output canonicalization failed: %w", err)
	}

	// 7. Store Output in CAS
	if e.artifactStore != nil {
		// We store the canonical bytes. The Store will return the hash.
		// We trust Store's hash matches artifact.Digest (both are SHA-256).
		storedHash, err := e.artifactStore.Store(ctx, artifact.CanonicalBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to persist output artifact: %w", err)
		}
		// Verify consistency (paranoid check)
		if storedHash != artifact.Digest {
			return nil, nil, fmt.Errorf("store integrity violation: calculated %s != stored %s", artifact.Digest, storedHash)
		}
	}
	// If no artifactStore, artifact.Digest is still valid (in-memory only e.g. tests)

	// 8. Persistence, Metering & Audit
	// Fail-closed: if receipt signing fails, execution is considered failed.
	receipt, err := e.createReceipt(ctx, decision, intent, effect, toolName, blobHash, artifact.Digest, safeDepResult)
	if err != nil {
		return nil, nil, fmt.Errorf("receipt creation failed: %w", err)
	}
	if err := e.finalizeExecution(ctx, decision, intent, toolName); err != nil {
		return nil, nil, err
	}

	// Metering
	if e.meter != nil {
		tenantID := decision.TenantID
		if tenantID == "" {
			tenantID = "system"
		}
		if err := e.meter.Record(ctx, UsageEvent{
			TenantID:  tenantID,
			EventType: "execution",
			Quantity:  1,
			Timestamp: e.clock(),
			Metadata: map[string]any{
				"tool":        toolName,
				"decision_id": decision.ID,
			},
		}); err != nil {
			// Metering errors are non-fatal but logged to audit trail
			if e.AuditLog != nil {
				_ = e.AuditLog.Append("executor", "metering_error", map[string]interface{}{
					"decision_id": decision.ID,
					"error":       err.Error(),
				})
			}
		}
	}

	return receipt, artifact, nil
}

func executionReceiptID(intentID string) string {
	return "rcpt-exec-" + intentID
}

func (e *SafeExecutor) checkIdempotency(ctx context.Context, intentID string) (*contracts.Receipt, bool) {
	if e.receiptStore != nil {
		if receipt, err := e.receiptStore.GetByReceiptID(ctx, executionReceiptID(intentID)); err == nil && receipt != nil &&
			receipt.Type == contracts.ReceiptTypeExecution && receipt.ExternalReferenceID == intentID {
			return receipt, true
		}
	}
	return nil, false
}

// gateSafeDep resolves hazard authority from a server-owned source. It never
// reads DecisionRecord.InputContext: that map is explanatory data and may have
// originated with the caller before the decision was signed.
func (e *SafeExecutor) gateSafeDep(ctx context.Context, decision *contracts.DecisionRecord, effect *contracts.Effect, toolName string) (*safedep.GateResult, error) {
	if !e.safeDepRequired {
		return nil, nil
	}
	if e.safeDepGate == nil || e.safeDepResolver == nil {
		return nil, fmt.Errorf("%w: %s: safe deprecation authority resolver and gate are required", safedep.ErrDispatchBlocked, contracts.ReasonAttestationResultRequired)
	}

	req, err := e.safeDepResolver.Resolve(ctx, safedep.AuthorityRequest{
		TenantID:         decision.TenantID,
		WorkspaceID:      decision.WorkspaceID,
		SessionID:        decision.SessionID,
		SubjectID:        decision.SubjectID,
		DecisionID:       decision.ID,
		EffectDigestHash: decision.EffectDigest,
		EffectType:       effect.EffectType,
		Action:           decision.Action,
		ToolName:         toolName,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", safedep.ErrDispatchBlocked, contracts.ReasonAttestationResultRequired, err)
	}
	// The resolver may only provide SafeDep authority inputs. The execution
	// identity always comes from the signed decision/effect tuple.
	req.Intent = nil
	req.DecisionID = decision.ID
	// EffectID is not part of the canonical effect digest and is therefore not
	// an authority input. Do not expose it to a gate implementation.
	req.EffectID = ""
	req.EffectType = effect.EffectType
	req.Action = decision.Action
	req.ToolName = toolName
	if req.ConnectorID == "" {
		req.ConnectorID = toolName
	}

	gateResult, err := e.safeDepGate.Gate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", safedep.ErrDispatchBlocked, err)
	}
	if !gateResult.DispatchAllowed {
		reason := gateResult.Reason
		if reason == "" {
			reason = string(gateResult.ReasonCode)
		}
		return nil, fmt.Errorf("%w: %s", safedep.ErrDispatchBlocked, reason)
	}
	return &gateResult, nil
}

func (e *SafeExecutor) validateGating(decision *contracts.DecisionRecord, intent *contracts.AuthorizedExecutionIntent, effect *contracts.Effect) error {
	if decision == nil {
		return errors.New("execution blocked: missing decision")
	}
	if err := crypto.RequireExecutableDecisionSignature(decision); err != nil {
		return fmt.Errorf("execution blocked: %w", err)
	}
	if effect == nil {
		return errors.New("execution blocked: missing effect")
	}
	if intent == nil {
		return errors.New("execution blocked: missing execution intent")
	}
	// A governed effect must never be dispatched if the executor cannot emit a
	// signed receipt. Check this before the driver so a missing signer cannot
	// turn into an already-completed but unauditable effect.
	if e.signer == nil {
		return errors.New("execution blocked: receipt signer unavailable")
	}
	// Verification must be available before the executor considers any durable
	// reservation. A nil verifier used to panic after the early checks, which
	// made a malformed composition look like an execution failure instead of a
	// deterministic fail-closed refusal.
	if e.verifier == nil {
		return errors.New("execution blocked: signature verifier unavailable")
	}
	// A claim is itself durable authority state. Validate the driver before a
	// claim so a misconfigured executor cannot leave an otherwise valid intent
	// ambiguously CLAIMED without ever being capable of dispatching it.
	if e.driver == nil {
		return errors.New("execution blocked: tool driver unavailable")
	}
	// Causal evidence is a precondition to dispatch, not a best-effort
	// afterthought. A driver must never run if this executor cannot atomically
	// persist the signed execution receipt in the decision's bound session.
	if e.receiptStore == nil {
		return errors.New("execution blocked: receipt store unavailable")
	}
	if strings.TrimSpace(decision.SessionID) == "" {
		return errors.New("execution blocked: signed decision session_id is required for causal receipt persistence")
	}
	if err := crypto.RequireExecutableIntentSignature(intent); err != nil {
		return fmt.Errorf("execution blocked: %w", err)
	}
	if intent.DecisionID != decision.ID {
		return fmt.Errorf("intent mismatch: intent.decision_id %s != decision.id %s", intent.DecisionID, decision.ID)
	}
	effectDigest, err := canonicalEffectDigest(effect)
	if err != nil {
		return fmt.Errorf("execution blocked: canonical effect digest: %w", err)
	}
	if decision.EffectDigest == "" {
		return errors.New("execution blocked: decision missing effect digest")
	}
	if decision.EffectDigest != effectDigest {
		return fmt.Errorf("execution blocked: effect digest mismatch (decision=%s, runtime=%s)", decision.EffectDigest, effectDigest)
	}
	if intent.EffectDigestHash == "" {
		return errors.New("execution blocked: intent missing effect digest hash")
	}
	if intent.EffectDigestHash != effectDigest {
		return fmt.Errorf("execution blocked: intent effect digest mismatch (intent=%s, runtime=%s)", intent.EffectDigestHash, effectDigest)
	}

	// 1. Verify Decision Signature (Provenance)
	if valid, err := e.verifier.VerifyDecision(decision); err != nil || !valid {
		return fmt.Errorf("execution blocked: invalid decision signature: %w", err)
	}

	// 2. Verify Intent Signature (Authorization)
	if valid, err := e.verifier.VerifyIntent(intent); err != nil || !valid {
		return fmt.Errorf("execution blocked: invalid intent signature: %w", err)
	}

	// 3. Verify Verdict (canonical: ALLOW per contracts/verdict.go)
	if decision.Verdict != string(contracts.VerdictAllow) {
		return fmt.Errorf("execution blocked: decision verdict is %s (reason: %s)", decision.Verdict, decision.Reason)
	}

	// 4. Expiration Check
	// The validity window is half-open: an intent is no longer executable at
	// its exact expiry instant.
	if !e.clock().Before(intent.ExpiresAt) {
		return fmt.Errorf("execution blocked: intent expired at %s", intent.ExpiresAt)
	}

	return nil
}

func canonicalEffectDigest(effect *contracts.Effect) (string, error) {
	return effectdigest.Canonical(effect)
}

type effectDigestEnvelope struct {
	EffectType     string                `json:"effect_type"`
	Params         map[string]any        `json:"params,omitempty"`
	IdempotencyKey string                `json:"idempotency_key,omitempty"`
	Irreversible   bool                  `json:"irreversible,omitempty"`
	ArgsHash       string                `json:"args_hash,omitempty"`
	OutputHash     string                `json:"output_hash,omitempty"`
	Taint          []string              `json:"taint,omitempty"`
	Compensation   *effectDigestEnvelope `json:"compensation,omitempty"`
}

func effectDigestEnvelopeFrom(effect *contracts.Effect) *effectDigestEnvelope {
	if effect == nil {
		return nil
	}
	return &effectDigestEnvelope{
		EffectType:     effect.EffectType,
		Params:         effect.Params,
		IdempotencyKey: effect.IdempotencyKey,
		Irreversible:   effect.Irreversible,
		ArgsHash:       effect.ArgsHash,
		OutputHash:     effect.OutputHash,
		Taint:          contracts.NormalizeTaintLabels(effect.Taint),
		Compensation:   effectDigestEnvelopeFrom(effect.Compensation),
	}
}

func (e *SafeExecutor) verifySnapshot(ctx context.Context, decision *contracts.DecisionRecord) (string, error) {
	var blobHash string
	if decision.Snapshot != "" && e.artifactStore != nil {
		h, err := e.artifactStore.Store(ctx, []byte(decision.Snapshot))
		if err != nil {
			return "", fmt.Errorf("failed to store snapshot artifact: %w", err)
		}
		blobHash = h

		if blobHash != decision.PhenotypeHash {
			return "", fmt.Errorf("phenotype mismatch: snapshot hash %s != decision hash %s", blobHash, decision.PhenotypeHash)
		}
	}
	if e.currentPhenotypeHash != "" && decision.PhenotypeHash != "" {
		if decision.PhenotypeHash != e.currentPhenotypeHash {
			return "", fmt.Errorf("execution blocked: phenotype mismatch (decision=%s, current=%s)", decision.PhenotypeHash, e.currentPhenotypeHash)
		}
	}
	return blobHash, nil
}

func (e *SafeExecutor) createReceipt(ctx context.Context, decision *contracts.DecisionRecord, intent *contracts.AuthorizedExecutionIntent, effect *contracts.Effect, toolName string, blobHash string, outputHash string, safeDepResult *safedep.GateResult) (*contracts.Receipt, error) {
	if e.signer == nil {
		return nil, errors.New("receipt signer unavailable")
	}
	if e.receiptStore == nil {
		return nil, errors.New("receipt store unavailable")
	}
	chainSessionID := decision.SessionID
	if chainSessionID == "" {
		return nil, errors.New("execution blocked: signed decision session_id is required for causal receipt persistence")
	}

	var persisted *contracts.Receipt
	err := e.receiptStore.AppendCausal(ctx, chainSessionID, func(_ *contracts.Receipt, lamportClock uint64, prevHash string) (*contracts.Receipt, error) {
		receipt := &contracts.Receipt{
			Type:                contracts.ReceiptTypeExecution,
			ReceiptID:           executionReceiptID(intent.ID),
			DecisionID:          decision.ID,
			EffectID:            effect.EffectID,
			ExternalReferenceID: intent.ID,
			Status:              "SUCCESS",
			BlobHash:            blobHash,
			OutputHash:          outputHash,
			ExecutorID:          decision.SubjectID,
			EffectType:          effect.EffectType,
			ToolName:            toolName,
			IdempotencyKey:      intent.IdempotencyKey,
			SessionID:           chainSessionID,
			IssuedAt:            intent.IssuedAt,
			ArgsHash:            effect.ArgsHash, // PEP boundary hash bound into signed receipt
			Timestamp:           e.clock(),
			PrevHash:            prevHash,
			LamportClock:        lamportClock,
		}
		if safeDepResult != nil && safeDepResult.Classification.HazardCode != "" {
			receipt.SafeDepState = string(safeDepResult.Classification.State)
			receipt.SafeDepReasonCode = string(safeDepResult.ReasonCode)
			if safeDepResult.ActivationReceipt != nil {
				receipt.EmergencyActivationID = safeDepResult.ActivationReceipt.ActivationID
				receipt.EmergencyDelegationSessionID = safeDepResult.ActivationReceipt.DelegationSessionID
				receipt.EmergencyScopeHash = safeDepResult.EmergencyScopeHash
			}
		}
		// Sign only after every causal and session field is assigned under the
		// store lock. The store validates but never mutates signed fields after
		// this point.
		if err := e.signer.SignReceipt(receipt); err != nil {
			return nil, fmt.Errorf("fail-closed: receipt signing failed: %w", err)
		}
		persisted = receipt
		return receipt, nil
	})
	if err != nil {
		return nil, fmt.Errorf("fail-closed: receipt persistence failed: %w", err)
	}
	if persisted == nil {
		return nil, errors.New("fail-closed: receipt store completed without a receipt")
	}
	return persisted, nil
}

func (e *SafeExecutor) finalizeExecution(ctx context.Context, decision *contracts.DecisionRecord, intent *contracts.AuthorizedExecutionIntent, toolName string) error {
	if e.outboxStore != nil {
		if err := e.outboxStore.MarkDone(ctx, intent.ID); err != nil {
			return fmt.Errorf("fail-closed: outbox mark-done failed: %w", err)
		}
	}
	if e.AuditLog != nil {
		_ = e.AuditLog.Append("executor", "execute_effect", map[string]interface{}{
			"decision_id": decision.ID,
			"tool":        toolName,
			"status":      "SUCCESS",
		})
	}
	return nil
}

// Match interfaces for compiler output
type CompilerPolicy interface {
	GetProhibitedTools() []string
}

// ApplyCompilerPolicy updates the internal policy enforcer with constraints mainly from the Compiler.
// This allows dynamic regulation to be injected into the SafeExecutor.
func (e *SafeExecutor) ApplyCompilerPolicy(policy CompilerPolicy) {
	if policy != nil {
		e.policyEnforcer.SetProhibitedTools(policy.GetProhibitedTools())
	}
}
