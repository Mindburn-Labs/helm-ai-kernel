package executor

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/interfaces"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/manifest"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receipts/policies"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/safedep"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
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
	return e
}

// Execute returns the Receipt (proof) and the Tool Result (Artifact), or error.
func (e *SafeExecutor) Execute(ctx context.Context, effect *contracts.Effect, decision *contracts.DecisionRecord, intent *contracts.AuthorizedExecutionIntent) (*contracts.Receipt, *interfaces.Artifact, error) {
	// 0. Pre-flight Checks
	if decision == nil {
		return nil, nil, errors.New("execution blocked: missing decision")
	}

	// 1. Gating & Verification.
	//
	// This MUST precede the idempotency lookup. The lookup keys on decision.ID
	// alone, so running it first meant an unsigned DecisionRecord carrying
	// nothing but a known ID returned (receipt, artifact, nil) — a success
	// return plus a genuine signed receipt — without the decision signature,
	// intent signature, effect digest, verdict or authority window ever being
	// examined (F-09).
	if err := e.validateGating(decision, intent, effect); err != nil {
		return nil, nil, err
	}

	// 2. Idempotency Check — only after the caller has proven it was entitled
	// to ask about this decision at all.
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

	var safeDepResult *safedep.GateResult
	req := safedep.GateRequestFromContext(decision.InputContext)
	if e.safeDepGate == nil {
		return nil, nil, fmt.Errorf("%w: %s: safe deprecation gate unavailable", safedep.ErrDispatchBlocked, contracts.ReasonAttestationResultRequired)
	}
	req.Intent = intent
	req.DecisionID = decision.ID
	req.EffectID = effect.EffectID
	req.EffectType = effect.EffectType
	req.Action = decision.Action
	req.ToolName = toolName
	if req.ConnectorID == "" {
		req.ConnectorID = toolName
	}
	gateResult, err := e.safeDepGate.Gate(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", safedep.ErrDispatchBlocked, err)
	}
	if !gateResult.DispatchAllowed {
		reason := gateResult.Reason
		if reason == "" {
			reason = string(gateResult.ReasonCode)
		}
		return nil, nil, fmt.Errorf("%w: %s", safedep.ErrDispatchBlocked, reason)
	}
	safeDepResult = &gateResult

	// 4. Tool verification
	// Check against dynamic policy enforcer
	if !e.policyEnforcer.IsToolAllowed(toolName) {
		return nil, nil, fmt.Errorf("policy violation: tool '%s' is prohibited by active regulation", toolName)
	}

	// 5. Outbox Scheduling
	if e.outboxStore != nil {
		if err := e.outboxStore.Schedule(ctx, effect, intent); err != nil {
			return nil, nil, fmt.Errorf("failed to schedule effect in outbox: %w", err)
		}
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
	receipt, err := e.createReceipt(ctx, decision, intent, effect, blobHash, artifact.Digest, safeDepResult)
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

func (e *SafeExecutor) validateGating(decision *contracts.DecisionRecord, intent *contracts.AuthorizedExecutionIntent, effect *contracts.Effect) error {
	if decision == nil {
		return errors.New("execution blocked: missing decision")
	}
	if strings.TrimSpace(decision.ID) == "" {
		return errors.New("execution blocked: missing decision id")
	}
	if effect == nil {
		return errors.New("execution blocked: missing effect")
	}
	if intent == nil {
		return errors.New("execution blocked: missing execution intent")
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

	// An executor with no verifier cannot establish provenance for anything.
	// Without this guard the calls below dereference a nil interface and panic,
	// which on the enforcement path is a crash where a refusal belongs — and a
	// panic recovered upstream reads as a transient fault rather than a denied
	// execution. Fail closed instead.
	if isNilVerifier(e.verifier) {
		return errors.New("execution blocked: no signature verifier configured")
	}

	// 1. Verify Decision Signature (Provenance)
	//
	// A verifier reports a bad signature as (false, nil); an error means it could
	// not complete the check at all. Wrapping a nil err with %w rendered the
	// common case as "invalid decision signature: %!w(<nil>)", losing the
	// distinction between "the signature is wrong" and "verification failed to
	// run" exactly where a forensic reader needs it. Both still deny.
	if valid, err := e.verifier.VerifyDecision(decision); err != nil {
		return fmt.Errorf("execution blocked: decision signature verification failed: %w", err)
	} else if !valid {
		return errors.New("execution blocked: invalid decision signature")
	}

	// 2. Verify Intent Signature (Authorization)
	if valid, err := e.verifier.VerifyIntent(intent); err != nil {
		return fmt.Errorf("execution blocked: intent signature verification failed: %w", err)
	} else if !valid {
		return errors.New("execution blocked: invalid intent signature")
	}

	// 3. Verify Verdict (canonical: ALLOW per contracts/verdict.go)
	if decision.Verdict != string(contracts.VerdictAllow) {
		return fmt.Errorf("execution blocked: decision verdict is %s (reason: %s)", decision.Verdict, decision.Reason)
	}

	// 4. Signed authority-window check
	if err := intent.ValidateAt(e.clock()); err != nil {
		return fmt.Errorf("execution blocked: %w", err)
	}

	return nil
}

func canonicalEffectDigest(effect *contracts.Effect) (string, error) {
	return contracts.CanonicalEffectDigest(effect)
}

const standaloneReceiptSessionPrefix = "standalone:decision:"

// receiptSessionID returns the signed chain identity for an execution. A
// decision with no caller session is deliberately a standalone receipt group,
// keyed by its already-signed decision ID rather than the shared empty string.
func receiptSessionID(decision *contracts.DecisionRecord) (string, error) {
	if decision == nil {
		return "", errors.New("missing decision")
	}
	if decision.InputContext != nil {
		if value, ok := decision.InputContext["session_id"].(string); ok && strings.TrimSpace(value) != "" {
			return value, nil
		}
	}
	if strings.TrimSpace(decision.ID) == "" {
		return "", errors.New("missing decision id for standalone receipt session")
	}
	return standaloneReceiptSessionPrefix + decision.ID, nil
}

func receiptTenantID(decision *contracts.DecisionRecord) string {
	if decision == nil || decision.InputContext == nil {
		return ""
	}
	tenantID, _ := decision.InputContext["tenant_id"].(string)
	return strings.TrimSpace(tenantID)
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

func (e *SafeExecutor) createReceipt(ctx context.Context, decision *contracts.DecisionRecord, intent *contracts.AuthorizedExecutionIntent, effect *contracts.Effect, blobHash string, outputHash string, safeDepResult *safedep.GateResult) (*contracts.Receipt, error) {
	sessionID, err := receiptSessionID(decision)
	if err != nil {
		return nil, err
	}
	decisionHash, err := crypto.DecisionSemanticHash(decision)
	if err != nil {
		return nil, fmt.Errorf("derive semantic decision hash: %w", err)
	}
	tenantID := receiptTenantID(decision)
	timestamp := e.clock().UTC()
	if normalizer, ok := e.receiptStore.(receiptTimestampNormalizer); ok {
		timestamp = normalizer.NormalizeReceiptTimestamp(timestamp)
	}

	buildReceipt := func(lamportClock uint64, prevHash string, causal bool) (*contracts.Receipt, error) {
		receipt := &contracts.Receipt{
			ReceiptID:     "rcpt-" + decision.ID,
			DecisionID:    decision.ID,
			CorrelationID: decision.CorrelationID,
			EffectID:      effect.EffectID,
			Status:        "SUCCESS",
			BlobHash:      blobHash,
			OutputHash:    outputHash,
			DecisionHash:  decisionHash,
			ArgsHash:      effect.ArgsHash, // PEP boundary hash bound into signed receipt
			Timestamp:     timestamp,
			PrevHash:      prevHash,
			LamportClock:  lamportClock,
			Verdict:       decision.Verdict,
			ReasonCode:    decision.ReasonCode,
			PolicyHash:    decision.PolicyContentHash,
			SessionID:     sessionID,
		}
		if receipt.CorrelationID == "" {
			if corr, ok := tracing.GetCorrelationID(ctx); ok {
				receipt.CorrelationID = string(corr)
			}
		}
		if intent != nil {
			receipt.EmergencyActivationID = intent.EmergencyActivationID
			receipt.EmergencyDelegationSessionID = intent.EmergencyDelegationSessionID
			receipt.EmergencyScopeHash = intent.EmergencyScopeHash
		}
		if safeDepResult != nil && safeDepResult.Classification.HazardCode != "" {
			receipt.SafeDepState = string(safeDepResult.Classification.State)
			receipt.SafeDepReasonCode = string(safeDepResult.ReasonCode)
			if safeDepResult.ActivationReceipt != nil && receipt.EmergencyActivationID == "" {
				receipt.EmergencyActivationID = safeDepResult.ActivationReceipt.ActivationID
				receipt.EmergencyDelegationSessionID = safeDepResult.ActivationReceipt.DelegationSessionID
			}
		}
		if causal {
			// AppendCausal validates the signed V5 session scope after this
			// builder returns. Set the declared version before signing so no
			// signed field is mutated after the store assigns the chain position.
			receipt.SignatureVersion = contracts.ReceiptSignatureV5
		}
		// Sign Receipt — Fail-Closed: unsigned receipts are never emitted.
		// Every receipt MUST be signed per the HELM standard.
		// The signature now covers PrevHash + LamportClock via CanonicalizeReceipt.
		if e.signer != nil {
			if err := e.signer.SignReceipt(receipt); err != nil {
				return nil, fmt.Errorf("fail-closed: receipt signing failed: %w", err)
			}
		}
		return receipt, nil
	}

	// Durable stores can allocate the final predecessor and Lamport clock under
	// their transaction/session lock. Build and sign only after that assignment;
	// otherwise a concurrent execution could sign the same causal position.
	if tenantID != "" && e.receiptStore != nil {
		appender, ok := e.receiptStore.(tenantScopedCausalReceiptAppender)
		if !ok {
			return nil, errors.New("fail-closed: receipt store lacks tenant-scoped causal append")
		}
		var receipt *contracts.Receipt
		if err := appender.AppendCausalScoped(ctx, tenantID, sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
			built, buildErr := buildReceipt(lamport, prevHash, true)
			if buildErr != nil {
				return nil, buildErr
			}
			receipt = built
			return built, nil
		}); err != nil {
			return nil, fmt.Errorf("fail-closed: receipt persistence failed: %w", err)
		}
		if receipt == nil {
			return nil, errors.New("fail-closed: causal receipt store completed without building a receipt")
		}
		return receipt, nil
	}
	if appender, ok := e.receiptStore.(causalReceiptAppender); ok {
		var receipt *contracts.Receipt
		if err := appender.AppendCausal(ctx, sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
			built, buildErr := buildReceipt(lamport, prevHash, true)
			if buildErr != nil {
				return nil, buildErr
			}
			receipt = built
			return built, nil
		}); err != nil {
			return nil, fmt.Errorf("fail-closed: receipt persistence failed: %w", err)
		}
		if receipt == nil {
			return nil, errors.New("fail-closed: causal receipt store completed without building a receipt")
		}
		return receipt, nil
	}

	// Keep the legacy adapter path for minimal ReceiptStore implementations
	// that do not provide atomic causal allocation.
	prevHash := ""
	lamportClock := uint64(1)
	if e.receiptStore != nil {
		prev, err := e.receiptStore.GetLastForSession(ctx, sessionID)
		if err != nil {
			return nil, fmt.Errorf("load previous receipt for session %q: %w", sessionID, err)
		}
		if prev != nil {
			prevHash, err = contracts.ReceiptChainHash(prev)
			if err != nil {
				return nil, fmt.Errorf("hash previous receipt for session %q: %w", sessionID, err)
			}
			lamportClock = prev.LamportClock + 1
		}
	}
	receipt, err := buildReceipt(lamportClock, prevHash, false)
	if err != nil {
		return nil, err
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

// quantum_posture: this helper inspects only whether a verifier is present. It
// performs no cryptographic operation and makes no algorithm choice, so it is
// agnostic to the classical/post-quantum profile the injected verifier
// implements.
//
// isNilVerifier reports whether the verifier is absent, including the
// typed-nil case.
//
// A plain `e.verifier == nil` catches only a nil interface. An interface
// holding a nil *Ed25519Verifier is non-nil, so it passes that check and then
// panics when the method dereferences its receiver. That path is not
// hypothetical: it is reached as soon as the signature is well-formed enough to
// get past the earlier length checks, which is exactly what an attacker
// supplies.
//
// The reflect call runs once per execution, against an ed25519 verification
// that costs orders of magnitude more.
func isNilVerifier(v crypto.Verifier) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func:
		return rv.IsNil()
	default:
		return false
	}
}
