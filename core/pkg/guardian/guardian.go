package guardian

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	pkg_artifact "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/firewall"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/identity"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/safedep"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/threatscan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// BudgetGate enforces budget constraints on governed execution.
// This interface replaces the enterprise finance.Tracker with a minimal
// policy-scoped budget check suitable for the canonical standard.
type BudgetGate interface {
	// Check returns true if the cost is within budget.
	Check(budgetID string, cost BudgetCost) (bool, error)
	// Consume records consumption against the budget.
	Consume(budgetID string, cost BudgetCost) error
}

// BudgetCost represents the cost of a governed operation.
type BudgetCost struct {
	Requests int64 `json:"requests"`
}

// Clock provides authority time for the Guardian.
// Per KERNEL_TCB §3: the kernel MUST NOT use wall-clock time.Now().
// Inject an authority clock that derives time from the deterministic
// EnvSnap or a kernel-managed monotonic source.
type Clock interface {
	Now() time.Time
}

// Contextualizer attaches contextual metadata to decisions (Sequence 1.5)
type Contextualizer interface {
	GetContext(req DecisionRequest) (map[string]any, error)
}

// wallClock is the default clock (for backward compatibility during migration).
// Production code SHOULD inject a kernel authority clock instead.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

// GuardianOption configures optional dependencies for the Guardian.
type GuardianOption func(*Guardian)

// WithBudgetTracker injects a budget enforcement gate.
func WithBudgetTracker(t BudgetGate) GuardianOption { return func(g *Guardian) { g.tracker = t } }

// WithAuditLog injects an audit logger.
func WithAuditLog(l *AuditLog) GuardianOption { return func(g *Guardian) { g.auditLog = l } }

// WithTemporalGuardian injects a temporal replay protector.
func WithTemporalGuardian(tg *TemporalGuardian) GuardianOption {
	return func(g *Guardian) { g.temporal = tg }
}

// WithEnvFingerprint sets the boot-sequence environment fingerprint.
func WithEnvFingerprint(fp string) GuardianOption { return func(g *Guardian) { g.envFprint = fp } }

// WithPDP injects an external policy decision point.
func WithPDP(p pdp.PolicyDecisionPoint) GuardianOption { return func(g *Guardian) { g.pdp = p } }

// WithPolicySnapshots makes the Guardian resolve policy authority from an
// installed EffectivePolicySnapshot instead of static process state.
func WithPolicySnapshots(store policyreconcile.PolicySnapshotStore, scope policyreconcile.PolicyScope) GuardianOption {
	return func(g *Guardian) {
		g.snapshotStore = store
		g.snapshotScope = scope.Normalize()
	}
}

// WithComplianceChecker injects a compliance verifier phase.
func WithComplianceChecker(c ComplianceChecker) GuardianOption {
	return func(g *Guardian) { g.complianceChecker = c }
}

// WithFreezeController injects the global freeze kill-switch.
func WithFreezeController(fc *kernel.FreezeController) GuardianOption {
	return func(g *Guardian) { g.freezeCtrl = fc }
}

// WithAgentKillSwitch injects the per-agent kill switch.
func WithAgentKillSwitch(ks *kernel.AgentKillSwitch) GuardianOption {
	return func(g *Guardian) { g.agentKillSwitch = ks }
}

// WithContextGuard injects the environment mismatch detector.
func WithContextGuard(cg *kernel.ContextGuard) GuardianOption {
	return func(g *Guardian) { g.contextGuard = cg }
}

// WithIsolationChecker injects the identity isolation enforcer.
func WithIsolationChecker(ic *identity.IsolationChecker) GuardianOption {
	return func(g *Guardian) { g.isolationChecker = ic }
}

// WithEgressChecker injects the network egress firewall.
func WithEgressChecker(ec *firewall.EgressChecker) GuardianOption {
	return func(g *Guardian) { g.egressChecker = ec }
}

// WithThreatScanner injects the canonical threat scanner.
func WithThreatScanner(ts *threatscan.Scanner) GuardianOption {
	return func(g *Guardian) { g.threatScanner = ts }
}

// WithDelegationStore injects the delegation session store.
func WithDelegationStore(ds identity.DelegationStore) GuardianOption {
	return func(g *Guardian) { g.delegationStore = ds }
}

// WithBehavioralTrustScorer injects the dynamic behavioral trust scorer.
// When configured, the agent's trust score and tier are injected into
// the decision context as "trust_score" (float64 0.0-1.0) and "trust_tier"
// (string), allowing CEL policies to reference them.
func WithBehavioralTrustScorer(s *trust.BehavioralTrustScorer) GuardianOption {
	return func(g *Guardian) { g.behavioralScorer = s }
}

// WithPrivilegeResolver injects the privilege tier resolver.
func WithPrivilegeResolver(r PrivilegeResolver) GuardianOption {
	return func(g *Guardian) { g.privilegeResolver = r }
}

// WithClock injects a deterministic or authority clock.
func WithClock(c Clock) GuardianOption { return func(g *Guardian) { g.clock = c } }

// WithSessionRiskMemory injects the deterministic session trajectory gate.
func WithSessionRiskMemory(srm *SessionRiskMemory) GuardianOption {
	return func(g *Guardian) { g.sessionRiskMemory = srm }
}

// WithWarmLeaseManager injects the warm sandbox leasing manager.
func WithWarmLeaseManager(mgr *sandbox.WarmLeaseManager) GuardianOption {
	return func(g *Guardian) { g.warmLeaseMgr = mgr }
}

// WithZeroIDInterceptor injects a custom ZeroIDInterceptor.
func WithZeroIDInterceptor(z *ZeroIDInterceptor) GuardianOption {
	return func(g *Guardian) { g.zeroidInterceptor = z }
}

func WithSafeDepController(controller *safedep.Controller) GuardianOption {
	return func(g *Guardian) { g.safeDepController = controller }
}

// Guardian enforces the Proof Requirement Graph (PRG)
type Guardian struct {
	signer            crypto.Signer
	prg               *prg.Graph
	pe                *prg.PolicyEngine
	registry          *pkg_artifact.Registry
	clock             Clock
	tracker           BudgetGate
	auditLog          *AuditLog
	temporal          *TemporalGuardian
	envFprint         string                  // Boot-sequence fingerprint for DecisionRecords
	pdp               pdp.PolicyDecisionPoint // Optional pluggable policy backend
	snapshotStore     policyreconcile.PolicySnapshotStore
	snapshotScope     policyreconcile.PolicyScope
	complianceChecker ComplianceChecker            // Optional compliance pre-check
	freezeCtrl        *kernel.FreezeController     // Global kill-switch
	agentKillSwitch   *kernel.AgentKillSwitch      // Per-agent kill switch (§Phase E)
	contextGuard      *kernel.ContextGuard         // Environment mismatch detection
	isolationChecker  *identity.IsolationChecker   // Agent credential reuse detection
	egressChecker     *firewall.EgressChecker      // Network egress enforcement
	threatScanner     *threatscan.Scanner          // Canonical threat signal scanner
	delegationStore   identity.DelegationStore     // Delegation session store (§Gate 5)
	behavioralScorer  *trust.BehavioralTrustScorer // Dynamic behavioral trust scorer (MIN-82)
	privilegeResolver PrivilegeResolver            // Privilege tier resolver
	sessionRiskMemory *SessionRiskMemory           // Deterministic trajectory authorization gate
	otel              *OTelInstrumentation         // Optional OTel tracing & metrics
	warmLeaseMgr      *sandbox.WarmLeaseManager    // Warm lease manager for sandboxes
	zeroidInterceptor *ZeroIDInterceptor           // ZeroID identity validator
	safeDepController *safedep.Controller          // Safe Deprecation emergency release plane
	boundaryChain     []BoundaryInterceptor        // Cached request interceptors
}

// ZeroID returns the registered ZeroIDInterceptor.
func (g *Guardian) ZeroID() *ZeroIDInterceptor {
	return g.zeroidInterceptor
}

// NewGuardian creates a new Guardian instance. Optional dependencies can be injected
// using GuardianOption functions (e.g., WithBudgetTracker).
func NewGuardian(signer crypto.Signer, ruleGraph *prg.Graph, reg *pkg_artifact.Registry, opts ...GuardianOption) *Guardian {
	pe, prgErr := prg.NewPolicyEngine()
	if prgErr != nil {
		slog.Warn("[guardian] PRG policy engine init failed", "error", prgErr)
	}
	if ruleGraph == nil {
		ruleGraph = prg.NewGraph()
	}
	if pe != nil {
		if err := pe.WarmGraph(ruleGraph); err != nil {
			slog.Warn("[guardian] PRG warm compile failed", "error", err)
		}
	}

	g := &Guardian{
		signer:   signer,
		prg:      ruleGraph,
		pe:       pe,
		registry: reg,
	}

	for _, opt := range opts {
		opt(g)
	}

	if g.zeroidInterceptor == nil {
		g.zeroidInterceptor = NewZeroIDInterceptor(g, nil)
	}

	if g.clock == nil {
		g.clock = wallClock{}
	}
	g.boundaryChain = []BoundaryInterceptor{
		g.zeroidInterceptor,
		NewTemporalInterceptor(g),
		NewFreezeInterceptor(g),
		NewPDPInterceptor(g),
		NewTaintEgressInterceptor(g),
		NewSandboxAllocationInterceptor(g),
	}

	return g
}

// newDecisionID generates a cryptographically random decision ID.
// Uses crypto/rand to prevent ID collisions under concurrent load
// (replaces the previous time.UnixNano() approach).
func newDecisionID() string {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("guardian: crypto/rand failure: %v", err))
	}
	return "dec-" + hex.EncodeToString(b[:])
}

// SetBudgetTracker configures the budget enforcement gate.
// Deprecated: Use WithBudgetTracker GuardianOption in NewGuardian instead.
func (g *Guardian) SetBudgetTracker(t BudgetGate) {
	g.tracker = t
}

// SetAuditLog configures the persistent audit sink.
// Deprecated: Use WithAuditLog GuardianOption in NewGuardian instead.
func (g *Guardian) SetAuditLog(l *AuditLog) {
	g.auditLog = l
}

// SetTemporalGuardian provides non-repudiation replay protection.
// Deprecated: Use WithTemporalGuardian GuardianOption in NewGuardian instead.
func (g *Guardian) SetTemporalGuardian(tg *TemporalGuardian) {
	g.temporal = tg
}

// SetEnvFingerprint supplies the execution context fingerprint for proofs.
// Deprecated: Use WithEnvFingerprint GuardianOption in NewGuardian instead.
func (g *Guardian) SetEnvFingerprint(fp string) {
	g.envFprint = fp
}

// SetPolicyDecisionPoint injects an external policy backend.
// Deprecated: Use WithPDP GuardianOption in NewGuardian instead.
func (g *Guardian) SetPolicyDecisionPoint(p pdp.PolicyDecisionPoint) {
	g.pdp = p
}

// SetPolicySnapshots configures the active runtime policy snapshot store.
// Deprecated: Use WithPolicySnapshots GuardianOption in NewGuardian instead.
func (g *Guardian) SetPolicySnapshots(store policyreconcile.PolicySnapshotStore, scope policyreconcile.PolicyScope) {
	g.snapshotStore = store
	g.snapshotScope = scope.Normalize()
}

// SetComplianceChecker sets a compliance verifier.
// Deprecated: Use WithComplianceChecker GuardianOption in NewGuardian instead.
func (g *Guardian) SetComplianceChecker(c ComplianceChecker) {
	g.complianceChecker = c
}

// SetFreezeController injects the global kill-switch. Required for gate 2.
// Deprecated: Use WithFreezeController GuardianOption in NewGuardian instead.
func (g *Guardian) SetFreezeController(fc *kernel.FreezeController) {
	g.freezeCtrl = fc
}

// SetContextGuard injects the environment mismatch detector. Required for gate 3.
// Deprecated: Use WithContextGuard GuardianOption in NewGuardian instead.
func (g *Guardian) SetContextGuard(cg *kernel.ContextGuard) {
	g.contextGuard = cg
}

// SetIsolationChecker injects the credential reuse detector. Required for gate 4.
// Deprecated: Use WithIsolationChecker GuardianOption in NewGuardian instead.
func (g *Guardian) SetIsolationChecker(ic *identity.IsolationChecker) {
	g.isolationChecker = ic
}

// SetEgressChecker injects the network firewall policy enforcer. Required for gate 5.
// Deprecated: Use WithEgressChecker GuardianOption in NewGuardian instead.
func (g *Guardian) SetEgressChecker(ec *firewall.EgressChecker) {
	g.egressChecker = ec
}

// SetThreatScanner injects the canonical threat scanner.
// Deprecated: Use WithThreatScanner GuardianOption in NewGuardian instead.
func (g *Guardian) SetThreatScanner(ts *threatscan.Scanner) {
	g.threatScanner = ts
}

// SetDelegationStore provides the state engine for recursive decision linking.
// Required for complex multi-agent routing logic.
// Deprecated: Use WithDelegationStore GuardianOption in NewGuardian instead.
func (g *Guardian) SetDelegationStore(ds identity.DelegationStore) {
	g.delegationStore = ds
}

// SetSessionRiskMemory injects the deterministic session trajectory gate.
// Deprecated: Use WithSessionRiskMemory GuardianOption in NewGuardian instead.
func (g *Guardian) SetSessionRiskMemory(srm *SessionRiskMemory) {
	g.sessionRiskMemory = srm
}

func (g *Guardian) SetSafeDepController(controller *safedep.Controller) {
	g.safeDepController = controller
}

// SignDecision checks requirements and signs only if met
func (g *Guardian) SignDecision(ctx context.Context, decision *contracts.DecisionRecord, effect *contracts.Effect, evidenceHashes []string, intervention *contracts.InterventionMetadata) error {
	return g.signDecisionWithGraph(ctx, decision, effect, evidenceHashes, intervention, g.prg)
}

func (g *Guardian) signDecisionWithGraph(ctx context.Context, decision *contracts.DecisionRecord, effect *contracts.Effect, evidenceHashes []string, intervention *contracts.InterventionMetadata, ruleGraph *prg.Graph) error {
	// Bind the canonical effect digest before any signing path: the decision
	// signature covers EffectDigest (crypto.CanonicalizeDecision), and intent
	// issuance / execution verify the binding fail-closed. Without this, a
	// SignDecision caller signs an empty digest and can never issue intents.
	if decision.EffectDigest == "" {
		digest, err := canonicalEffectDigest(effect)
		if err != nil {
			return fmt.Errorf("canonicalize effect digest: %w", err)
		}
		decision.EffectDigest = digest
	}

	artifacts := make([]*pkg_artifact.ArtifactEnvelope, 0, len(evidenceHashes))
	for _, hash := range evidenceHashes {
		env, err := g.registry.GetArtifact(ctx, hash)
		if err != nil {
			return fmt.Errorf("failed to retrieve evidence %s: %w", hash, err)
		}
		artifacts = append(artifacts, env)
	}

	var actionID string
	if toolName, ok := effect.Params["tool_name"].(string); ok && toolName != "" {
		actionID = toolName
	} else {
		actionID = effect.EffectType
	}

	// Temporal intervention has priority over PRG validation.
	if intervention != nil && intervention.Type != contracts.InterventionNone {
		decision.Intervention = intervention
		// If interrupting or quarantining, strict verdict override
		if intervention.Type == contracts.InterventionInterrupt || intervention.Type == contracts.InterventionQuarantine {
			decision.Verdict = string(contracts.VerdictEscalate)
			decision.ReasonCode = string(contracts.ReasonTemporalIntervene)
			decision.Reason = fmt.Sprintf("Temporal Intervention: %s (%s)", intervention.Type, intervention.ReasonCode)
			return g.signer.SignDecision(decision)
		}
		// If Throttling, we likely still proceed to PRG validation but note the throttle
		// defaulting to recording it.
	}

	// 3.5 Budget Check (Finance Gate)
	if g.tracker != nil {
		// Attempt to resolve Budget ID from params
		if budgetID, ok := effect.Params["budget_id"].(string); ok && budgetID != "" {
			cost := BudgetCost{Requests: 1}

			allowed, err := g.tracker.Check(budgetID, cost)
			if err != nil {
				decision.Verdict = string(contracts.VerdictDeny)
				decision.ReasonCode = string(contracts.ReasonBudgetError)
				decision.Reason = fmt.Sprintf("Budget Error: %v", err)
				return g.signer.SignDecision(decision)
			}
			if !allowed {
				decision.Verdict = string(contracts.VerdictDeny)
				decision.ReasonCode = string(contracts.ReasonBudgetExceeded)
				decision.Reason = string(contracts.ReasonBudgetExceeded)
				return g.signer.SignDecision(decision)
			}

			if consumeErr := g.tracker.Consume(budgetID, cost); consumeErr != nil {
				// Log but don't fail — the Check already passed.
				slog.Warn("guardian: budget consume failed", "budget_id", budgetID, "error", consumeErr)
			}
		}
	}

	// AC-REG-10: EnvelopeCheck precedes every effect dispatch
	// Verify that the effect is properly enveloped (e.g. valid structure, allowed type)
	if err := g.checkEnvelope(effect); err != nil {
		decision.Verdict = string(contracts.VerdictDeny)
		decision.ReasonCode = string(contracts.ReasonEnvelopeInvalid)
		decision.Reason = fmt.Sprintf("Envelope Violation: %v", err)
		return g.signer.SignDecision(decision)
	}

	// 4. Validate against PRG
	if ruleGraph == nil {
		ruleGraph = prg.NewGraph()
	}
	rule, exists := ruleGraph.Rules[actionID]
	if !exists {
		decision.Verdict = string(contracts.VerdictDeny)
		decision.ReasonCode = string(contracts.ReasonNoPolicy)
		decision.Reason = fmt.Sprintf("%s: no policy defined for action %s", contracts.ReasonNoPolicy, actionID)
		return g.signer.SignDecision(decision)
	}

	// Prepare CEL input
	effectMap, _ := toMap(effect)
	input := map[string]interface{}{
		"action":    actionID,
		"effect":    effectMap,
		"artifacts": artifacts,
		"timestamp": g.clock.Now().Unix(),
		"taint":     contracts.NormalizeTaintLabels(effect.Taint),
	}

	valid, err := g.pe.EvaluateRequirementSet(rule, input)
	if err != nil {
		decision.Verdict = string(contracts.VerdictDeny)
		decision.ReasonCode = string(contracts.ReasonPRGEvalError)
		decision.Reason = fmt.Sprintf("PRG Evaluation Error: %v", err)
		return g.signer.SignDecision(decision)
	}

	if !valid {
		decision.Verdict = string(contracts.VerdictDeny)
		decision.ReasonCode = string(contracts.ReasonMissingRequirement)
		decision.Reason = string(contracts.ReasonMissingRequirement)
		g.recordBehavioralEvent(decision.SubjectID, trust.EventPolicyViolate, "PRG requirement not met")
		return g.signer.SignDecision(decision)
	}

	// 5. Pass -> Sign
	decision.Verdict = string(contracts.VerdictAllow)
	decision.ReasonCode = ""
	decision.RequirementSetHash = rule.Hash()
	decision.Timestamp = g.clock.Now() // Authority time (KERNEL_TCB §3)
	// Optionally link evidence hashes in the decision record (needs schema update)
	g.recordBehavioralEvent(decision.SubjectID, trust.EventPolicyComply, "PRG evaluation passed")

	return g.signer.SignDecision(decision)
}

// IssueExecutionIntent verifies a Decision and issues a signed Intent for the Executor.
func (g *Guardian) IssueExecutionIntent(ctx context.Context, decision *contracts.DecisionRecord, effect *contracts.Effect) (*contracts.AuthorizedExecutionIntent, error) {
	if decision == nil {
		return nil, fmt.Errorf("cannot issue intent without decision")
	}
	if effect == nil {
		return nil, fmt.Errorf("cannot issue intent without effect")
	}
	// 1. Verify Decision Structure
	if decision.Verdict != string(contracts.VerdictAllow) {
		return nil, fmt.Errorf("cannot issue intent for denied decision: %s", decision.Verdict)
	}

	// 2. Verify Decision Signature (using Kernel Key)
	verifier, ok := g.signer.(interface {
		VerifyDecision(d *contracts.DecisionRecord) (bool, error)
	})
	if !ok {
		return nil, fmt.Errorf("signer does not implement VerifyDecision")
	}
	if valid, err := verifier.VerifyDecision(decision); err != nil || !valid {
		return nil, fmt.Errorf("invalid decision signature: %w", err)
	}

	if g.snapshotStore != nil {
		scope := g.policyScopeFromContext(decision.InputContext)
		current, ok := g.snapshotStore.Get(scope)
		if !ok || current == nil {
			return nil, fmt.Errorf("%s: policy snapshot missing for %s", contracts.ReasonPolicyEpochChanged, scope.Key())
		}
		decisionEpoch, err := strconv.ParseUint(decision.PolicyEpoch, 10, 64)
		if err != nil || decision.PolicyContentHash == "" {
			return nil, fmt.Errorf("%s: decision missing policy hash/epoch binding", contracts.ReasonPolicyEpochChanged)
		}
		if current.PolicyHash != decision.PolicyContentHash || current.PolicyEpoch != decisionEpoch {
			return nil, fmt.Errorf("%s: decision policy %s/%d current %s/%d",
				contracts.ReasonPolicyEpochChanged,
				decision.PolicyContentHash,
				decisionEpoch,
				current.PolicyHash,
				current.PolicyEpoch,
			)
		}
	}

	effectDigest, err := canonicalEffectDigest(effect)
	if err != nil {
		return nil, fmt.Errorf("canonicalize effect digest: %w", err)
	}
	if decision.EffectDigest == "" {
		return nil, fmt.Errorf("decision missing effect digest")
	}
	if decision.EffectDigest != effectDigest {
		return nil, fmt.Errorf("effect digest mismatch: decision=%s requested=%s", decision.EffectDigest, effectDigest)
	}

	// Determine Allowed Tool (matching identification logic)
	var allowedTool string
	if tn, ok := effect.Params["tool_name"].(string); ok && tn != "" {
		allowedTool = tn
	} else {
		allowedTool = effect.EffectType
	}

	// 3. Create Intent
	now := g.clock.Now()

	intent := &contracts.AuthorizedExecutionIntent{
		ID:               "intent-" + decision.ID, // Deterministic ID
		DecisionID:       decision.ID,
		EffectDigestHash: effectDigest,
		IssuedAt:         now,
		ExpiresAt:        now.Add(5 * time.Minute),
		Signer:           "kernel",
		AllowedTool:      allowedTool,
		Taint:            contracts.NormalizeTaintLabels(effect.Taint),
	}
	if decision.InputContext != nil {
		if activationID, ok := decision.InputContext["safe_deprecation_activation_id"].(string); ok {
			intent.EmergencyActivationID = activationID
		}
		if sessionID, ok := decision.InputContext["safe_deprecation_delegation_session_id"].(string); ok {
			intent.EmergencyDelegationSessionID = sessionID
		}
		if scopeHash, ok := decision.InputContext["safe_deprecation_scope_hash"].(string); ok {
			intent.EmergencyScopeHash = scopeHash
		}
	}

	// 4. Sign Intent
	if err := g.signer.SignIntent(intent); err != nil {
		return nil, fmt.Errorf("failed to sign intent: %w", err)
	}

	return intent, nil
}

func canonicalEffectDigest(effect *contracts.Effect) (string, error) {
	if effect == nil {
		return "", fmt.Errorf("effect is nil")
	}
	effectBytes, err := canonicalize.JCS(effectDigestEnvelopeFrom(effect))
	if err != nil {
		return "", err
	}
	return canonicalize.HashBytes(effectBytes), nil
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

// recordBehavioralEvent records a trust score event if the behavioral scorer is configured.
// This is a fire-and-forget operation that does not affect the decision outcome.
func (g *Guardian) recordBehavioralEvent(principal string, eventType trust.ScoreEventType, reason string) {
	if g.behavioralScorer == nil || principal == "" {
		return
	}
	g.behavioralScorer.RecordEvent(principal, trust.ScoreEvent{
		EventType: eventType,
		Reason:    reason,
	})
}

// checkEnvelope validates the structural integrity of the Effect envelope.
func (g *Guardian) checkEnvelope(effect *contracts.Effect) error {
	if effect.EffectType == "" {
		return fmt.Errorf("missing effect type")
	}
	if effect.EffectID == "" {
		return fmt.Errorf("missing effect ID")
	}
	// Verify critical metadata presence
	// Soft requirement: timestamp presence for auditability
	// Legacy effects might miss it, so we don't enforce yet.
	_ = effect.Params["timestamp"]
	return nil
}

// --- High-Level Governance API ---

// Verdict constants are now canonical in contracts/verdict.go.
// These aliases are kept for backward compatibility during migration.
var (
	VerdictAllow     = string(contracts.VerdictAllow)
	VerdictBlock     = string(contracts.VerdictDeny)
	VerdictIntervene = string(contracts.VerdictEscalate)
	VerdictPending   = "PENDING" // No canonical constant — pending is a transient state
)

// DecisionRequest represents a request for a governance decision.
type DecisionRequest struct {
	Principal      string                 `json:"principal"`
	Action         string                 `json:"action"`
	Resource       string                 `json:"resource"` // Tool name or effect type
	Context        map[string]interface{} `json:"context"`
	SessionHistory []SessionAction        `json:"session_history,omitempty"`
}

// SessionAction represents a previous action in the current session.
// Per arXiv 2603.16586, path-based policies evaluate the full execution
// history, catching multi-step attack chains that stateless checks miss.
type SessionAction struct {
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	Verdict   string `json:"verdict"`   // ALLOW, DENY, ESCALATE
	Timestamp int64  `json:"timestamp"` // Unix milliseconds
}

// EvaluateDecision evaluates a request against the governance policy (PRG + Temporal).
// It constructs a DecisionRecord and returns it.
// When a PDP is configured, policy evaluation is delegated to it and the result
// is bound into the DecisionRecord for receipt chain verification.
func (g *Guardian) EvaluateDecision(ctx context.Context, req DecisionRequest) (*contracts.DecisionRecord, error) {
	ctx, span := otel.Tracer("helm.kernel").Start(ctx, "Guardian.EvaluateDecision")
	defer span.End()

	span.SetAttributes(
		attribute.String("action", req.Action),
		attribute.String("principal", req.Principal),
		attribute.String("resource", req.Resource),
	)

	activeGraph := g.prg
	activePDP := g.pdp
	var activeSnapshot *policyreconcile.EffectivePolicySnapshot

	// GOV-001: Content-addressed policy version derived from PRG rule hash.
	policyVersion := "v1.0.0" // fallback
	if g.prg != nil {
		if hash, err := g.prg.ContentHash(); err == nil && hash != "" {
			policyVersion = "sha256:" + hash
		}
	}
	if g.snapshotStore != nil {
		scope := g.policyScopeFromContext(req.Context)
		snapshot, ok := g.snapshotStore.Get(scope)
		if !ok || snapshot == nil {
			decision := &contracts.DecisionRecord{
				ID:            newDecisionID(),
				Timestamp:     g.clock.Now(),
				Verdict:       string(contracts.VerdictDeny),
				ReasonCode:    string(contracts.ReasonPolicyNotReady),
				Reason:        fmt.Sprintf("%s: no active policy snapshot for %s", contracts.ReasonPolicyNotReady, scope.Key()),
				InputContext:  req.Context,
				PolicyVersion: "unavailable",
			}
			if signErr := g.signer.SignDecision(decision); signErr != nil {
				return nil, fmt.Errorf("failed to sign policy-not-ready decision: %w", signErr)
			}
			return decision, nil
		}
		if snapshot.Validation.Status != "" && snapshot.Validation.Status != policyreconcile.StatusActive {
			decision := &contracts.DecisionRecord{
				ID:            newDecisionID(),
				Timestamp:     g.clock.Now(),
				Verdict:       string(contracts.VerdictDeny),
				ReasonCode:    string(contracts.ReasonPolicyNotReady),
				Reason:        fmt.Sprintf("%s: policy snapshot for %s is %s", contracts.ReasonPolicyNotReady, scope.Key(), snapshot.Validation.Status),
				InputContext:  req.Context,
				PolicyVersion: snapshot.PolicyHash,
			}
			bindRuntimePolicyDecision(decision, snapshot, snapshot.PolicyHash)
			if signErr := g.signer.SignDecision(decision); signErr != nil {
				return nil, fmt.Errorf("failed to sign policy-not-ready decision: %w", signErr)
			}
			return decision, nil
		}
		activeSnapshot = snapshot
		policyVersion = snapshot.PolicyHash
		if snapshot.Graph != nil {
			activeGraph = snapshot.Graph
		}
		if snapshot.PDP != nil {
			activePDP = snapshot.PDP
		}
	}

	if g.safeDepController != nil {
		signal := safedep.SignalFromContext(req.Context)
		if !signal.Empty() {
			classification, classErr := g.safeDepController.Classify(ctx, signal)
			if classErr != nil {
				return nil, classErr
			}
			if req.Context == nil {
				req.Context = make(map[string]interface{})
			}
			req.Context["safe_deprecation_state"] = string(classification.State)
			req.Context["safe_deprecation_reason_code"] = string(classification.ReasonCode)
			if classification.State == contracts.SafeDepTerminalFreeze ||
				(classification.State == contracts.SafeDepDeprecatedReadonly && !safedep.IsInspectionAction(req.Action, req.Resource)) {
				decision := &contracts.DecisionRecord{
					ID:            newDecisionID(),
					Timestamp:     g.clock.Now(),
					Verdict:       string(contracts.VerdictDeny),
					ReasonCode:    string(classification.ReasonCode),
					Reason:        fmt.Sprintf("%s: safe deprecation state %s blocks %s", classification.ReasonCode, classification.State, req.Action),
					InputContext:  req.Context,
					PolicyVersion: policyVersion,
				}
				bindRuntimePolicyDecision(decision, activeSnapshot, policyVersion)
				if signErr := g.signer.SignDecision(decision); signErr != nil {
					return nil, fmt.Errorf("failed to sign safe-deprecation decision: %w", signErr)
				}
				return decision, nil
			}
		}
	}

	// ── Session history enrichment (arXiv 2603.16586: path-aware policies) ──
	if len(req.SessionHistory) > 0 {
		if req.Context == nil {
			req.Context = make(map[string]interface{})
		}
		req.Context["session_history"] = req.SessionHistory
		req.Context["session_action_count"] = len(req.SessionHistory)

		denyCount := 0
		for _, sa := range req.SessionHistory {
			if sa.Verdict == "DENY" {
				denyCount++
			}
		}
		req.Context["session_deny_count"] = denyCount
	}

	var sessionRiskSnapshot *SessionRiskSnapshot
	if g.sessionRiskMemory != nil {
		snapshot := g.sessionRiskMemory.Evaluate(sessionRiskSessionID(req), req.SessionHistory, req)
		sessionRiskSnapshot = &snapshot
		if req.Context == nil {
			req.Context = make(map[string]interface{})
		}
		attachSessionRiskContext(req.Context, snapshot)
		span.SetAttributes(
			attribute.Float64("session_risk.score", snapshot.TrajectoryRiskScore),
			attribute.String("session_risk.centroid_hash", snapshot.SessionCentroidHash),
			attribute.Int("session_risk.window", snapshot.RiskAccumulationWindow),
		)
		if g.sessionRiskMemory.ShouldDeny(snapshot) {
			now := g.clock.Now()
			decision := &contracts.DecisionRecord{
				ID:                     newDecisionID(),
				Timestamp:              now,
				Verdict:                string(contracts.VerdictDeny),
				Reason:                 fmt.Sprintf("%s: trajectory risk %.4f over %d actions", contracts.ReasonSessionRiskDeny, snapshot.TrajectoryRiskScore, snapshot.RiskAccumulationWindow),
				ReasonCode:             string(contracts.ReasonSessionRiskDeny),
				InputContext:           req.Context,
				TrajectoryRiskScore:    snapshot.TrajectoryRiskScore,
				SessionCentroidHash:    snapshot.SessionCentroidHash,
				RiskAccumulationWindow: snapshot.RiskAccumulationWindow,
			}
			bindRuntimePolicyDecision(decision, activeSnapshot, policyVersion)
			if signErr := g.signer.SignDecision(decision); signErr != nil {
				return nil, fmt.Errorf("failed to sign session-risk decision: %w", signErr)
			}
			if g.auditLog != nil {
				decisionBytes, _ := canonicalize.JCS(decision)
				_, _ = g.auditLog.Append("guardian", "SESSION_RISK_DENY", decision.ID, string(decisionBytes))
			}
			g.recordBehavioralEvent(req.Principal, trust.EventPolicyViolate, "session risk memory denied")
			return decision, nil
		}
	}

	evalCtx := &EvaluationContext{
		Request:             req,
		ActiveSnapshot:      activeSnapshot,
		PolicyVersion:       policyVersion,
		ActiveGraph:         activeGraph,
		ActivePDP:           activePDP,
		SessionRiskSnapshot: sessionRiskSnapshot,
	}

	finalHandler := func(ctx context.Context, eCtx *EvaluationContext) (*contracts.DecisionRecord, error) {
		req := eCtx.Request

		// ── Behavioral trust score enrichment ──
		if g.behavioralScorer != nil {
			trustScore := g.behavioralScorer.GetScore(req.Principal)
			if req.Context == nil {
				req.Context = make(map[string]interface{})
			}
			req.Context["trust_score"] = trustScore.Normalized()
			req.Context["trust_tier"] = string(trustScore.Tier)

			span.SetAttributes(
				attribute.Float64("behavioral_trust.score", trustScore.Normalized()),
				attribute.String("behavioral_trust.tier", string(trustScore.Tier)),
			)
		}

		// ── Privilege tier enforcement ──
		if g.privilegeResolver != nil {
			assignedTier, tierErr := g.privilegeResolver.ResolveTier(ctx, req.Principal)
			if tierErr != nil {
				slog.Warn("[guardian] privilege tier resolution failed", "principal", req.Principal, "error", tierErr)
				assignedTier = TierRestricted
			}

			effectiveTier := assignedTier
			if g.behavioralScorer != nil {
				trustScore := g.behavioralScorer.GetScore(req.Principal)
				effectiveTier = EffectiveTier(assignedTier, trustScore.Tier)
			}

			requiredTier := RequiredTierForEffect(req.Action)
			if effectiveTier < requiredTier {
				now := g.clock.Now()
				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					ReasonCode: string(contracts.ReasonInsufficientPrivilege),
					Reason:     fmt.Sprintf("INSUFFICIENT_PRIVILEGE: agent tier %s < required %s for %s", effectiveTier, requiredTier, req.Action),
				}
				if signErr := g.signDecisionWithContext(decision, eCtx); signErr != nil {
					return nil, fmt.Errorf("failed to sign privilege-deny decision: %w", signErr)
				}
				span.SetAttributes(
					attribute.String("privilege.assigned", assignedTier.String()),
					attribute.String("privilege.effective", effectiveTier.String()),
					attribute.String("privilege.required", requiredTier.String()),
				)
				return decision, nil
			}

			if req.Context == nil {
				req.Context = make(map[string]interface{})
			}
			req.Context["privilege_tier"] = effectiveTier.String()

			span.SetAttributes(
				attribute.String("privilege.effective", effectiveTier.String()),
			)
		}

		// 1. Construct Effect from Request
		effect := &contracts.Effect{
			EffectID:   fmt.Sprintf("eff-%d", g.clock.Now().UnixNano()),
			EffectType: req.Action,
			Params:     req.Context,
			Taint:      contracts.TaintLabelsFromContext(req.Context),
		}
		if req.Action == "EXECUTE_TOOL" {
			if effect.Params == nil {
				effect.Params = make(map[string]interface{})
			}
			effect.Params["tool_name"] = req.Resource
		}

		// 2. Prepare Decision Record
		effectDigest, err := canonicalEffectDigest(effect)
		if err != nil {
			return nil, fmt.Errorf("canonicalize effect digest: %w", err)
		}

		envFP := g.envFprint
		if envFP == "" {
			envFP = "sha256:unconfigured"
		}

		decision := &contracts.DecisionRecord{
			ID:             newDecisionID(),
			Timestamp:      g.clock.Now(),
			Verdict:        string(contracts.VerdictDeny), // Default deny
			EffectDigest:   effectDigest,
			InputContext:   req.Context,
			EnvFingerprint: envFP,
			PolicyVersion:  eCtx.PolicyVersion,
		}
		bindRuntimePolicyDecision(decision, eCtx.ActiveSnapshot, eCtx.PolicyVersion)
		if eCtx.SessionRiskSnapshot != nil {
			decision.TrajectoryRiskScore = eCtx.SessionRiskSnapshot.TrajectoryRiskScore
			decision.SessionCentroidHash = eCtx.SessionRiskSnapshot.SessionCentroidHash
			decision.RiskAccumulationWindow = eCtx.SessionRiskSnapshot.RiskAccumulationWindow
		}

		if eCtx.ThreatScanResult != nil && eCtx.ThreatScanResult.FindingCount > 0 {
			if decision.InputContext == nil {
				decision.InputContext = make(map[string]any)
			}
			decision.InputContext["threat_scan"] = eCtx.ThreatScanResult.Ref()
		}

		if eCtx.PDPBackend != "" {
			decision.PolicyBackend = eCtx.PDPBackend
			decision.PolicyContentHash = eCtx.PDPHash
			decision.PolicyDecisionHash = eCtx.PDPDecisionHash
		}

		// 3.5: Compliance check
		if g.complianceChecker != nil {
			compResult, compErr := g.complianceChecker.CheckCompliance(ctx, req.Principal, req.Action, req.Context)
			if compErr != nil {
				decision.Verdict = string(contracts.VerdictDeny)
				decision.ReasonCode = "COMPLIANCE_ERROR"
				decision.Reason = fmt.Sprintf("compliance check error: %v", compErr)
				if signErr := g.signer.SignDecision(decision); signErr != nil {
					return nil, fmt.Errorf("failed to sign compliance-error decision: %w", signErr)
				}
				return decision, nil
			}
			if !compResult.Compliant {
				decision.Verdict = string(contracts.VerdictDeny)
				decision.ReasonCode = "COMPLIANCE_VIOLATION"
				decision.Reason = fmt.Sprintf("compliance violation: %s (obligations: %v)", compResult.Reason, compResult.ViolatedObligations)
				if signErr := g.signer.SignDecision(decision); signErr != nil {
					return nil, fmt.Errorf("failed to sign compliance-deny decision: %w", signErr)
				}
				g.recordBehavioralEvent(req.Principal, trust.EventPolicyViolate, "compliance violation")
				return decision, nil
			}
		}

		err = g.signDecisionWithGraph(ctx, decision, effect, []string{}, eCtx.Intervention, eCtx.ActiveGraph)
		if err != nil {
			return nil, err
		}

		if decision.Verdict == string(contracts.VerdictAllow) {
			g.recordBehavioralEvent(req.Principal, trust.EventPolicyComply, "decision allowed")
		} else if decision.Verdict == string(contracts.VerdictDeny) {
			g.recordBehavioralEvent(req.Principal, trust.EventPolicyViolate, "decision denied: "+decision.ReasonCode)
		}

		if g.auditLog != nil {
			decisionBytes, _ := canonicalize.JCS(decision)
			if _, logErr := g.auditLog.Append("guardian", "DECISION_MADE", decision.ID, string(decisionBytes)); logErr != nil {
				return nil, fmt.Errorf("audit failure for decision %s: %w", decision.ID, logErr)
			}
		}

		return decision, nil
	}

	chain := NewInterceptorChain(g.boundaryChain, finalHandler)

	return chain.Execute(ctx, evalCtx)
}

// responseToIntervention maps TemporalGuardian ResponseLevel to InterventionType.
func responseToIntervention(level ResponseLevel) contracts.InterventionType {
	switch level {
	case ResponseInterrupt:
		return contracts.InterventionInterrupt
	case ResponseQuarantine:
		return contracts.InterventionQuarantine
	case ResponseFailClosed:
		return contracts.InterventionQuarantine // FailClosed maps to strongest intervention
	default:
		return contracts.InterventionNone
	}
}

func (g *Guardian) policyScopeFromContext(ctx map[string]any) policyreconcile.PolicyScope {
	scope := g.snapshotScope.Normalize()
	if tenantID, ok := stringContextValue(ctx, "tenant_id", "tenantId", "tenant"); ok {
		scope.TenantID = tenantID
	}
	if workspaceID, ok := stringContextValue(ctx, "workspace_id", "workspaceId", "workspace"); ok {
		scope.WorkspaceID = workspaceID
	}
	return scope.Normalize()
}

func bindRuntimePolicyDecision(decision *contracts.DecisionRecord, snapshot *policyreconcile.EffectivePolicySnapshot, policyVersion string) {
	if decision == nil {
		return
	}
	if decision.PolicyVersion == "" {
		decision.PolicyVersion = policyVersion
	}
	if snapshot == nil {
		return
	}
	decision.PolicyBackend = string(pdp.BackendHELM)
	decision.PolicyContentHash = snapshot.PolicyHash
	decision.PolicyEpoch = strconv.FormatUint(snapshot.PolicyEpoch, 10)
}

func stringContextValue(ctx map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		if ctx == nil {
			return "", false
		}
		value, ok := ctx[key]
		if !ok {
			continue
		}
		text, ok := value.(string)
		if !ok {
			continue
		}
		text = strings.TrimSpace(text)
		if text != "" {
			return text, true
		}
	}
	return "", false
}

func taintTrackingEnabled() bool {
	v := strings.TrimSpace(os.Getenv("HELM_TAINT_TRACKING"))
	return v == "1" || strings.EqualFold(v, "true")
}

func taintedEgressDenied(ctx map[string]interface{}, labels []string) bool {
	if len(labels) == 0 || ctx == nil {
		return false
	}
	if approved, ok := ctx["allow_tainted_egress"].(bool); ok && approved {
		return false
	}
	destination, _ := ctx["destination"].(string)
	if strings.TrimSpace(destination) == "" {
		return false
	}
	return contracts.TaintContainsAny(labels, contracts.TaintPII, contracts.TaintCredential, contracts.TaintSecret)
}

func sessionRiskSessionID(req DecisionRequest) string {
	if req.Context != nil {
		if sid, ok := req.Context["session_id"].(string); ok && strings.TrimSpace(sid) != "" {
			return sid
		}
		if sid, ok := req.Context["delegation_session_id"].(string); ok && strings.TrimSpace(sid) != "" {
			return sid
		}
	}
	return req.Principal
}

func attachSessionRiskContext(ctx map[string]interface{}, snapshot SessionRiskSnapshot) {
	ctx["trajectory_risk_score"] = snapshot.TrajectoryRiskScore
	ctx["session_centroid_hash"] = snapshot.SessionCentroidHash
	ctx["risk_accumulation_window"] = snapshot.RiskAccumulationWindow
}

func toMap(v any) (map[string]interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// OutputScanResult describes the outcome of post-execution output scanning.
type OutputScanResult struct {
	// Clean is true if the output passed scanning without high-risk findings.
	Clean bool `json:"clean"`
	// Quarantined is true if the output was quarantined (high-risk findings detected).
	Quarantined bool `json:"quarantined"`
	// ScanResult is the underlying threat scan result.
	ScanResult *contracts.ThreatScanResult `json:"scan_result,omitempty"`
	// DecisionID links this scan to the governing decision.
	DecisionID string `json:"decision_id"`
}

// EvaluateOutput scans tool execution output for threats (OWASP Agentic #6: Output Validation).
// This complements EvaluateDecision (input validation) with post-execution output scanning.
// If high-risk findings are detected, the output is quarantined — callers MUST NOT forward
// quarantined output to end users or downstream agents without sanitization.
func (g *Guardian) EvaluateOutput(ctx context.Context, decisionID string, output string, trustLevel contracts.InputTrustLevel) (*OutputScanResult, error) {
	_, span := otel.Tracer("helm.kernel").Start(ctx, "Guardian.EvaluateOutput")
	defer span.End()

	span.SetAttributes(
		attribute.String("decision_id", decisionID),
		attribute.Int("output_length", len(output)),
	)

	result := &OutputScanResult{
		DecisionID: decisionID,
		Clean:      true,
	}

	if g.threatScanner == nil || output == "" {
		return result, nil
	}

	// Scan output with tool-output channel designation
	scanResult := g.threatScanner.ScanInput(output, contracts.SourceChannelToolOutput, trustLevel)
	result.ScanResult = scanResult

	// Quarantine if high-risk findings detected
	if scanResult.FindingCount > 0 && threatscan.ContainsHighRiskFindings(scanResult) {
		result.Clean = false
		result.Quarantined = true

		span.SetAttributes(
			attribute.Bool("quarantined", true),
			attribute.Int("finding_count", scanResult.FindingCount),
			attribute.String("max_severity", string(scanResult.MaxSeverity)),
		)

		if g.auditLog != nil {
			auditData, _ := canonicalize.JCS(result)
			_, _ = g.auditLog.Append("guardian", "OUTPUT_QUARANTINE", decisionID, string(auditData))
		}
	}

	return result, nil
}
