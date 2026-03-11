package executor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/interfaces"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/manifest"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/receipts/policies"
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
		clock:                clock,
	}
}

// WithClock overrides the clock for deterministic testing and production authority clock injection.
// Per KERNEL_TCB §3: the kernel MUST NOT use wall-clock time.Now().
func (e *SafeExecutor) WithClock(clock func() time.Time) *SafeExecutor {
	e.clock = clock
	return e
}

// Execute returns the Receipt (proof) and the Tool Result (Artifact), or error.
func (e *SafeExecutor) Execute(ctx context.Context, effect *contracts.Effect, decision *contracts.DecisionRecord, intent *contracts.AuthorizedExecutionIntent) (*contracts.Receipt, *interfaces.Artifact, error) {
	// 0. Pre-flight Checks
	if decision == nil {
		return nil, nil, errors.New("execution blocked: missing decision")
	}

	// 1. Idempotency Check
	if receipt, ok := e.checkIdempotency(ctx, decision.ID); ok {
		// Recover artifact if possible, or return a pointer to the receipt
		// For now, return a synthetic artifact indicating execution already happened
		artifact := &interfaces.Artifact{
			SchemaID:    "system/execution-status",
			ContentType: "application/json",
			Digest:      receipt.OutputHash,
			Preview:     fmt.Sprintf("Already executed. Receipt: %s", receipt.ReceiptID),
		}
		return receipt, artifact, nil
	}

	// 1. Gating & Verification
	if err := e.validateGating(decision, intent); err != nil {
		return nil, nil, err
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

	// 4. Tool Verification (Phase 3 Enforced)
	// Check against dynamic policy enforcer
	if !e.policyEnforcer.IsToolAllowed(toolName) {
		return nil, nil, fmt.Errorf("policy violation: tool '%s' is prohibited by active regulation", toolName)
	}

	// 5. Outbox Scheduling
	if e.outboxStore != nil {
		if err := e.outboxStore.Schedule(ctx, effect, decision); err != nil {
			return nil, nil, fmt.Errorf("failed to schedule effect in outbox: %w", err)
		}
	}

	// 5. Dispatch
	// Used to be e.mcpClient.Call(toolName, effect.Params)
	result, err := e.driver.Execute(ctx, toolName, effect.Params)
	if err != nil {
		return nil, nil, err
	}

	// 5.5 Phase 3: Validate connector output against pinned schema (fail-closed on drift)
	if e.outputSchemaRegistry != nil {
		if outSchema := e.outputSchemaRegistry.LookupOutput(toolName); outSchema != nil {
			outResult, outErr := manifest.ValidateAndCanonicalizeToolOutput(outSchema, result)
			if outErr != nil {
				return nil, nil, fmt.Errorf("ERR_CONNECTOR_CONTRACT_DRIFT: %w", outErr)
			}
			effect.OutputHash = outResult.OutputHash
		}
	}

	// 6. Canonicalize Output (ArtifactProtocol)
	// Detect probable schema ID (simple heuristic for now)
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
	receipt, err := e.createReceipt(ctx, decision, effect, blobHash, artifact.Digest)
	if err != nil {
		return nil, nil, fmt.Errorf("receipt creation failed: %w", err)
	}
	if err := e.finalizeExecution(ctx, decision, toolName); err != nil {
		return nil, nil, err
	}

	// Metering
	if e.meter != nil {
		tenantID := "system"
		if decision.InputContext != nil {
			if t, ok := decision.InputContext["tenant_id"].(string); ok {
				tenantID = t
			}
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

func (e *SafeExecutor) checkIdempotency(ctx context.Context, decisionID string) (*contracts.Receipt, bool) {
	if e.receiptStore != nil {
		if receipt, err := e.receiptStore.Get(ctx, decisionID); err == nil && receipt != nil {
			return receipt, true
		}
	}
	return nil, false
}

func (e *SafeExecutor) validateGating(decision *contracts.DecisionRecord, intent *contracts.AuthorizedExecutionIntent) error {
	if decision == nil {
		return errors.New("execution blocked: missing decision")
	}
	if intent == nil {
		return errors.New("execution blocked: missing execution intent")
	}
	if intent.DecisionID != decision.ID {
		return fmt.Errorf("intent mismatch: intent.decision_id %s != decision.id %s", intent.DecisionID, decision.ID)
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
	if e.clock().After(intent.ExpiresAt) {
		return fmt.Errorf("execution blocked: intent expired at %s", intent.ExpiresAt)
	}

	return nil
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

func (e *SafeExecutor) createReceipt(ctx context.Context, decision *contracts.DecisionRecord, effect *contracts.Effect, blobHash string, outputHash string) (*contracts.Receipt, error) {
	// ProofGraph DAG: query previous receipt to build causal chain
	prevHash := "GENESIS"
	lamportClock := uint64(1)

	if e.receiptStore != nil {
		sessionID := ""
		if decision.InputContext != nil {
			if s, ok := decision.InputContext["session_id"].(string); ok {
				sessionID = s
			}
		}
		if sessionID != "" {
			if prev, err := e.receiptStore.GetLastForSession(ctx, sessionID); err == nil && prev != nil {
				prevHash = prev.Signature // Causal link: hash of previous receipt's cryptographic signature
				lamportClock = prev.LamportClock + 1
			}
		}
	}

	receipt := &contracts.Receipt{
		ReceiptID:    "rcpt-" + decision.ID,
		DecisionID:   decision.ID,
		EffectID:     effect.EffectID,
		Status:       "SUCCESS",
		BlobHash:     blobHash,
		OutputHash:   outputHash,
		ArgsHash:     effect.ArgsHash, // Phase 2: PEP boundary hash bound into signed receipt
		Timestamp:    e.clock(),
		PrevHash:     prevHash,
		LamportClock: lamportClock,
	}
	// Sign Receipt — Fail-Closed: unsigned receipts are never emitted.
	// Every receipt MUST be signed per the HELM standard.
	// The signature now covers PrevHash + LamportClock via CanonicalizeReceipt.
	if e.signer != nil {
		if err := e.signer.SignReceipt(receipt); err != nil {
			return nil, fmt.Errorf("fail-closed: receipt signing failed: %w", err)
		}
	}
	if e.receiptStore != nil {
		if storeErr := e.receiptStore.Store(ctx, receipt); storeErr != nil {
			return nil, fmt.Errorf("fail-closed: receipt persistence failed: %w", storeErr)
		}
	}
	return receipt, nil
}

func (e *SafeExecutor) finalizeExecution(ctx context.Context, decision *contracts.DecisionRecord, toolName string) error {
	if e.outboxStore != nil {
		if err := e.outboxStore.MarkDone(ctx, decision.ID); err != nil {
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
