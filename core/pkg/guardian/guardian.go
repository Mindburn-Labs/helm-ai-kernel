package guardian

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	pkg_artifact "github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/firewall"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/pdp"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/threatscan"
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
func WithTemporalGuardian(tg *TemporalGuardian) GuardianOption { return func(g *Guardian) { g.temporal = tg } }

// WithEnvFingerprint sets the boot-sequence environment fingerprint.
func WithEnvFingerprint(fp string) GuardianOption { return func(g *Guardian) { g.envFprint = fp } }

// WithPDP injects an external policy decision point.
func WithPDP(p pdp.PolicyDecisionPoint) GuardianOption { return func(g *Guardian) { g.pdp = p } }

// WithComplianceChecker injects a compliance verifier phase.
func WithComplianceChecker(c ComplianceChecker) GuardianOption {
	return func(g *Guardian) { g.complianceChecker = c }
}

// WithFreezeController injects the global freeze kill-switch.
func WithFreezeController(fc *kernel.FreezeController) GuardianOption {
	return func(g *Guardian) { g.freezeCtrl = fc }
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

// WithClock injects a deterministic or authority clock.
func WithClock(c Clock) GuardianOption { return func(g *Guardian) { g.clock = c } }

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
	envFprint         string                     // Boot-sequence fingerprint for DecisionRecords
	pdp               pdp.PolicyDecisionPoint    // Optional pluggable policy backend
	complianceChecker ComplianceChecker          // Optional compliance pre-check
	freezeCtrl        *kernel.FreezeController   // Global kill-switch (§Phase 2)
	contextGuard      *kernel.ContextGuard       // Environment mismatch detection (§Phase 3)
	isolationChecker  *identity.IsolationChecker // Agent credential reuse detection (§Phase 4)
	egressChecker     *firewall.EgressChecker    // Network egress enforcement (§Phase 5)
	threatScanner     *threatscan.Scanner        // Canonical threat signal scanner (§Phase 6)
	delegationStore   identity.DelegationStore   // Delegation session store (§Gate 5)
}

// NewGuardian creates a new Guardian instance. Optional dependencies can be injected
// using GuardianOption functions (e.g., WithBudgetTracker).
func NewGuardian(signer crypto.Signer, ruleGraph *prg.Graph, reg *pkg_artifact.Registry, opts ...GuardianOption) *Guardian {
	pe, prgErr := prg.NewPolicyEngine()
	if prgErr != nil {
		slog.Warn("[guardian] PRG policy engine init failed", "error", prgErr)
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

	if g.clock == nil {
		g.clock = wallClock{}
	}

	return g
}

// newDecisionID generates a cryptographically random decision ID.
// Uses crypto/rand to prevent ID collisions under concurrent load
// (replaces the previous time.UnixNano() approach).
func newDecisionID() string {
	var b [16]byte
	_, _ = crand.Read(b[:])
	return "dec-" + hex.EncodeToString(b[:])
}

// SetBudgetTracker configures the budget enforcement gate (Phase 4.1).
// Deprecated: Use WithBudgetTracker GuardianOption in NewGuardian instead.
func (g *Guardian) SetBudgetTracker(t BudgetGate) {
	g.tracker = t
}

// SetAuditLog configures the persistent audit sink.
// Deprecated: Use WithAuditLog GuardianOption in NewGuardian instead.
func (g *Guardian) SetAuditLog(l *AuditLog) {
	g.auditLog = l
}

// SetTemporalGuardian provides non-repudiation replay protection (Phase 4.3).
// Deprecated: Use WithTemporalGuardian GuardianOption in NewGuardian instead.
func (g *Guardian) SetTemporalGuardian(tg *TemporalGuardian) {
	g.temporal = tg
}

// SetEnvFingerprint supplies the execution context fingerprint for proofs (Phase 3).
// Deprecated: Use WithEnvFingerprint GuardianOption in NewGuardian instead.
func (g *Guardian) SetEnvFingerprint(fp string) {
	g.envFprint = fp
}

// SetPolicyDecisionPoint injects an external policy backend (Phase 2 bridge).
// Deprecated: Use WithPDP GuardianOption in NewGuardian instead.
func (g *Guardian) SetPolicyDecisionPoint(p pdp.PolicyDecisionPoint) {
	g.pdp = p
}

// SetComplianceChecker sets a phase 1.2 verifier.
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

// SetThreatScanner injects the canonical threat scanner for phase 6 checking.
// Deprecated: Use WithThreatScanner GuardianOption in NewGuardian instead.
func (g *Guardian) SetThreatScanner(ts *threatscan.Scanner) {
	g.threatScanner = ts
}

// SetDelegationStore provides the state engine for recursive decision linking.
// Required for complex Multi-Agent routing logic (Phase 6).
// Deprecated: Use WithDelegationStore GuardianOption in NewGuardian instead.
func (g *Guardian) SetDelegationStore(ds identity.DelegationStore) {
	g.delegationStore = ds
}

// SignDecision checks requirements and signs only if met
func (g *Guardian) SignDecision(ctx context.Context, decision *contracts.DecisionRecord, effect *contracts.Effect, evidenceHashes []string, intervention *contracts.InterventionMetadata) error {
	// 1. Gather Artifacts
	artifacts := make([]*pkg_artifact.ArtifactEnvelope, 0, len(evidenceHashes))
	for _, hash := range evidenceHashes {
		env, err := g.registry.GetArtifact(ctx, hash)
		if err != nil {
			return fmt.Errorf("failed to retrieve evidence %s: %w", hash, err)
		}
		// In a real system, we'd verify validity here (registry.VerifyArtifact)
		// but assuming GetArtifact returns valid structure.
		artifacts = append(artifacts, env)
	}

	// 2. Determine Action ID
	// Prefer tool_name for tool execution, otherwise use Effect Type
	var actionID string
	if toolName, ok := effect.Params["tool_name"].(string); ok && toolName != "" {
		actionID = toolName
	} else {
		actionID = effect.EffectType
	}

	// 3. Handle Temporal Intervention (Priority over PRG)
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
			// FUTURE: Replace flat cost with CostEstimator based on EffectType/Params
			cost := BudgetCost{Requests: 1}

			// Check and Consume
			// Note: For strict correctness, we should Check here, then Consume ONLY if PRG passes.
			// However, preventing DoS via PRG computation (which is cheap compared to execution) implies early check.
			// Let's Check first.
			allowed, err := g.tracker.Check(budgetID, cost)
			if err != nil {
				// If checking fails (e.g. invalid budget ID), fail closed? Or open if just missing?
				// Fail closed for security.
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

			// If allowed, we reserve/consume.
			// In this synchronous MVP, we consume now.
			// Ideally rollback if PRG fails, but for requests counters it's fine.
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
	rule, exists := g.prg.Rules[actionID]
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
		return g.signer.SignDecision(decision)
	}

	// 5. Pass -> Sign
	decision.Verdict = string(contracts.VerdictAllow)
	decision.ReasonCode = ""
	decision.RequirementSetHash = rule.Hash()
	decision.Timestamp = g.clock.Now() // Authority time (KERNEL_TCB §3)
	// Optionally link evidence hashes in the decision record (needs schema update)

	return g.signer.SignDecision(decision)
}

// IssueExecutionIntent verifies a Decision and issues a signed Intent for the Executor.
func (g *Guardian) IssueExecutionIntent(ctx context.Context, decision *contracts.DecisionRecord, effect *contracts.Effect) (*contracts.AuthorizedExecutionIntent, error) {
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

	// Determine Allowed Tool (matching identification logic)
	var allowedTool string
	if tn, ok := effect.Params["tool_name"].(string); ok && tn != "" {
		allowedTool = tn
	} else {
		allowedTool = effect.EffectType
	}

	// 3. Create Intent
	// F4: Compute EffectDigestHash from canonicalized effect
	effectBytes, _ := canonicalize.JCS(effect)
	effectDigest := canonicalize.HashBytes(effectBytes)
	now := g.clock.Now()

	intent := &contracts.AuthorizedExecutionIntent{
		ID:               "intent-" + decision.ID, // Deterministic ID
		DecisionID:       decision.ID,
		EffectDigestHash: effectDigest,
		IssuedAt:         now,
		ExpiresAt:        now.Add(5 * time.Minute),
		Signer:           "kernel",
		AllowedTool:      allowedTool,
	}

	// 4. Sign Intent
	if err := g.signer.SignIntent(intent); err != nil {
		return nil, fmt.Errorf("failed to sign intent: %w", err)
	}

	return intent, nil
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
	Principal string                 `json:"principal"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"` // Tool name or effect type
	Context   map[string]interface{} `json:"context"`
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

	// ── Pre-PDP enforcement gates (fail-closed, checked before policy) ──

	// Gate 0: Global freeze check — if frozen, deny everything immediately
	if g.freezeCtrl != nil && g.freezeCtrl.IsFrozen() {
		now := g.clock.Now()
		decision := &contracts.DecisionRecord{
			ID:         newDecisionID(),
			Timestamp:  now,
			Verdict:    string(contracts.VerdictDeny),
			Reason:     string(contracts.ReasonSystemFrozen),
			ReasonCode: string(contracts.ReasonSystemFrozen),
		}
		_ = g.signer.SignDecision(decision)
		return decision, nil
	}

	// Gate 1: Context mismatch guard — deny if environment fingerprint changed
	if g.contextGuard != nil {
		if err := g.contextGuard.ValidateCurrent(); err != nil {
			now := g.clock.Now()
			decision := &contracts.DecisionRecord{
				ID:         newDecisionID(),
				Timestamp:  now,
				Verdict:    string(contracts.VerdictDeny),
				Reason:     fmt.Sprintf("CONTEXT_MISMATCH: %v", err),
				ReasonCode: string(contracts.ReasonContextMismatch),
			}
			_ = g.signer.SignDecision(decision)
			return decision, nil
		}
	}

	// Gate 2: Agent identity isolation — deny if credential reuse detected
	if g.isolationChecker != nil && req.Principal != "" {
		credHash := ""
		if ch, ok := req.Context["credential_hash"].(string); ok {
			credHash = ch
		}
		if credHash != "" {
			sessionID := ""
			if sid, ok := req.Context["session_id"].(string); ok {
				sessionID = sid
			}
			if err := g.isolationChecker.ValidateAgentIdentity(req.Principal, credHash, sessionID); err != nil {
				now := g.clock.Now()
				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					Reason:     fmt.Sprintf("IDENTITY_ISOLATION_VIOLATION: %v", err),
					ReasonCode: string(contracts.ReasonIdentityIsolationViolation),
				}
				_ = g.signer.SignDecision(decision)
				return decision, nil
			}
		}
	}

	// Gate 3: Egress control — deny if destination is blocked
	if g.egressChecker != nil {
		if dest, ok := req.Context["destination"].(string); ok && dest != "" {
			var payloadSize int64
			if ps, ok := req.Context["payload_size"].(float64); ok {
				payloadSize = int64(ps)
			}
			result := g.egressChecker.CheckEgress(dest, "https", payloadSize)
			if !result.Allowed {
				now := g.clock.Now()
				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					Reason:     fmt.Sprintf("DATA_EGRESS_BLOCKED: %s", result.ReasonCode),
					ReasonCode: string(contracts.ReasonDataEgressBlocked),
				}
				_ = g.signer.SignDecision(decision)
				return decision, nil
			}
		}
	}

	// ── End egress gate ──

	// Gate 4: Threat signal scan — scan untrusted textual inputs
	var scanResult *contracts.ThreatScanResult
	if g.threatScanner != nil {
		// Determine source channel and trust level from context
		channel := contracts.SourceChannelUnknown
		if ch, ok := req.Context["source_channel"].(string); ok {
			channel = contracts.SourceChannel(ch)
		}
		trustLevel := contracts.InputTrustInternalUnverified
		if tl, ok := req.Context["trust_level"].(string); ok {
			trustLevel = contracts.InputTrustLevel(tl)
		}

		// Extract text to scan from context
		var textToScan string
		if input, ok := req.Context["user_input"].(string); ok {
			textToScan = input
		} else if input, ok := req.Context["text"].(string); ok {
			textToScan = input
		} else if input, ok := req.Context["content"].(string); ok {
			textToScan = input
		}

		if textToScan != "" {
			scanResult = g.threatScanner.ScanInput(textToScan, channel, trustLevel)

			// Critical/High findings from tainted sources → deterministic deny
			if scanResult.FindingCount > 0 && trustLevel.IsTainted() && threatscan.ContainsHighRiskFindings(scanResult) {
				now := g.clock.Now()

				// Determine the most specific reason code
				reasonCode := contracts.ReasonTaintedInputDeny
				for _, f := range scanResult.Findings {
					switch f.Class {
					case contracts.ThreatClassPromptInjection:
						reasonCode = contracts.ReasonPromptInjectionDetected
					case contracts.ThreatClassUnicodeObfuscation:
						reasonCode = contracts.ReasonUnicodeObfuscationDetected
					case contracts.ThreatClassCredentialExposure:
						reasonCode = contracts.ReasonTaintedCredentialDeny
					case contracts.ThreatClassSoftwarePublish:
						reasonCode = contracts.ReasonTaintedPublishDeny
					case contracts.ThreatClassSuspiciousFetch:
						reasonCode = contracts.ReasonTaintedEgressDeny
					}
				}

				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					ReasonCode: string(reasonCode),
					Reason:     fmt.Sprintf("%s: %d findings (max=%s) from %s source", reasonCode, scanResult.FindingCount, scanResult.MaxSeverity, trustLevel),
					InputContext: map[string]any{
						"threat_scan": scanResult.Ref(),
					},
				}
				_ = g.signer.SignDecision(decision)
				if g.auditLog != nil {
					decisionBytes, _ := canonicalize.JCS(decision)
					_, _ = g.auditLog.Append("guardian", "THREAT_DENY", decision.ID, string(decisionBytes))
				}
				return decision, nil
			}
		}
	}

	// Gate 5: Delegation session validation — if principal is a delegate,
	// validate session and intersect capabilities with policy stack.
	// Expired/invalid/scope-violated → DENY with canonical reason code.
	// Per ARCHITECTURE.md §2.1: sessions compile into P2-equivalent narrowing.
	if g.delegationStore != nil {
		if sessionID, ok := req.Context["delegation_session_id"].(string); ok && sessionID != "" {
			now := g.clock.Now()

			// Load session from store
			session, loadErr := g.delegationStore.Load(sessionID)
			if loadErr != nil {
				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					Reason:     fmt.Sprintf("DELEGATION_INVALID: %v", loadErr),
					ReasonCode: string(contracts.ReasonDelegationInvalid),
				}
				_ = g.signer.SignDecision(decision)
				return decision, nil
			}
			if session == nil {
				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					Reason:     "DELEGATION_INVALID: session not found",
					ReasonCode: string(contracts.ReasonDelegationInvalid),
				}
				_ = g.signer.SignDecision(decision)
				return decision, nil
			}

			// Validate session (expiry, nonce, verifier, policy hash)
			verifier, _ := req.Context["delegation_verifier"].(string)
			nonceChecker := g.delegationStore.IsNonceUsed
			if validErr := identity.ValidateSession(session, verifier, now, nonceChecker); validErr != nil {
				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					Reason:     fmt.Sprintf("DELEGATION_INVALID: %v", validErr),
					ReasonCode: string(contracts.ReasonDelegationInvalid),
				}
				_ = g.signer.SignDecision(decision)
				return decision, nil
			}

			// Mark nonce as used (anti-replay)
			g.delegationStore.MarkNonceUsed(session.SessionNonce)

			// Scope check: is the requested tool/resource within session scope?
			if req.Resource != "" && !session.IsToolAllowed(req.Resource) {
				decision := &contracts.DecisionRecord{
					ID:         newDecisionID(),
					Timestamp:  now,
					Verdict:    string(contracts.VerdictDeny),
					Reason:     fmt.Sprintf("DELEGATION_SCOPE_VIOLATION: tool %q not in session scope", req.Resource),
					ReasonCode: string(contracts.ReasonDelegationScopeViolation),
				}
				_ = g.signer.SignDecision(decision)
				if g.auditLog != nil {
					decisionBytes, _ := canonicalize.JCS(decision)
					_, _ = g.auditLog.Append("guardian", "DELEGATION_SCOPE_DENY", decision.ID, string(decisionBytes))
				}
				return decision, nil
			}

			// Action scope check
			if req.Resource != "" && req.Action != "" && len(session.Capabilities) > 0 {
				if !session.IsActionAllowed(req.Resource, req.Action) {
					decision := &contracts.DecisionRecord{
						ID:         newDecisionID(),
						Timestamp:  now,
						Verdict:    string(contracts.VerdictDeny),
						Reason:     fmt.Sprintf("DELEGATION_SCOPE_VIOLATION: action %q on %q not granted", req.Action, req.Resource),
						ReasonCode: string(contracts.ReasonDelegationScopeViolation),
					}
					_ = g.signer.SignDecision(decision)
					if g.auditLog != nil {
						decisionBytes, _ := canonicalize.JCS(decision)
						_, _ = g.auditLog.Append("guardian", "DELEGATION_SCOPE_DENY", decision.ID, string(decisionBytes))
					}
					return decision, nil
				}
			}

			// Delegation validated — annotate context for downstream
			if req.Context == nil {
				req.Context = make(map[string]interface{})
			}
			req.Context["delegation_validated"] = true
			req.Context["delegation_delegator"] = session.DelegatorPrincipal
			req.Context["delegation_delegate"] = session.DelegatePrincipal

			span.SetAttributes(
				attribute.String("delegation.session_id", sessionID),
				attribute.String("delegation.delegator", session.DelegatorPrincipal),
				attribute.String("delegation.delegate", session.DelegatePrincipal),
			)
		}
	}

	// ── End pre-PDP gates ──

	// 1. Construct Effect from Request
	effect := &contracts.Effect{
		EffectID:   fmt.Sprintf("eff-%d", g.clock.Now().UnixNano()),
		EffectType: req.Action, // e.g. "EXECUTE_TOOL"
		Params:     req.Context,
	}
	// Add tool name to params if not present but resource is tool
	if req.Action == "EXECUTE_TOOL" {
		if effect.Params == nil {
			effect.Params = make(map[string]interface{})
		}
		effect.Params["tool_name"] = req.Resource
	}

	// 2. Prepare Decision Record
	// Calculate Effect Digest for binding
	effectBytes, _ := canonicalize.JCS(effect)
	effectDigest := canonicalize.HashBytes(effectBytes)

	// F5: Use configured EnvFingerprint instead of placeholder
	envFP := g.envFprint
	if envFP == "" {
		envFP = "sha256:unconfigured"
	}

	// GOV-001: Content-addressed policy version derived from PRG rule hash.
	// This ties each DecisionRecord to the exact policy state evaluated,
	// rather than a hardcoded semver string.
	policyVersion := "v1.0.0" // fallback
	if g.prg != nil {
		if hash, err := g.prg.ContentHash(); err == nil && hash != "" {
			policyVersion = "sha256:" + hash
		}
	}

	decision := &contracts.DecisionRecord{
		ID:             newDecisionID(),
		Timestamp:      g.clock.Now(),
		Verdict:        string(contracts.VerdictDeny), // Default deny
		EffectDigest:   effectDigest,
		InputContext:   req.Context,
		EnvFingerprint: envFP,
		PolicyVersion:  policyVersion,
	}

	// Attach threat scan results to decision context if available
	if scanResult != nil && scanResult.FindingCount > 0 {
		if decision.InputContext == nil {
			decision.InputContext = make(map[string]any)
		}
		decision.InputContext["threat_scan"] = scanResult.Ref()
	}

	// 2.5: Delegate to external PDP if configured (P0.1 competitive defense)
	if g.pdp != nil {
		pdpReq := &pdp.DecisionRequest{
			Principal: req.Principal,
			Action:    req.Action,
			Resource:  req.Resource,
			Context:   req.Context,
			Timestamp: g.clock.Now(),
		}
		pdpResp, pdpErr := g.pdp.Evaluate(ctx, pdpReq)
		if pdpErr != nil {
			// Fail-closed: PDP error → DENY
			decision.Verdict = string(contracts.VerdictDeny)
			decision.ReasonCode = string(contracts.ReasonPDPError)
			decision.Reason = fmt.Sprintf("%s: %v", contracts.ReasonPDPError, pdpErr)
			decision.PolicyBackend = string(g.pdp.Backend())
			_ = g.signer.SignDecision(decision)
			return decision, nil
		}

		// Bind PDP metadata into DecisionRecord for receipt chain
		decision.PolicyBackend = string(g.pdp.Backend())
		decision.PolicyContentHash = g.pdp.PolicyHash()
		decision.PolicyDecisionHash = pdpResp.DecisionHash

		if !pdpResp.Allow {
			reasonCode := pdpResp.ReasonCode
			if reasonCode == "" {
				reasonCode = string(contracts.ReasonPDPDeny)
			}
			decision.Verdict = string(contracts.VerdictDeny)
			decision.ReasonCode = reasonCode
			decision.Reason = fmt.Sprintf("%s (ref=%s)", reasonCode, pdpResp.PolicyRef)
			_ = g.signer.SignDecision(decision)
			// Audit log for PDP denials
			if g.auditLog != nil {
				decisionBytes, _ := canonicalize.JCS(decision)
				_, _ = g.auditLog.Append("guardian", "PDP_DENY", decision.ID, string(decisionBytes))
			}
			return decision, nil
		}
		// PDP allowed — fall through to existing PRG + temporal checks
	}

	// 3. F3: Evaluate Temporal Guardian if wired
	var intervention *contracts.InterventionMetadata
	if g.temporal != nil {
		resp := g.temporal.Evaluate(ctx)
		if resp.Level >= ResponseInterrupt {
			intervention = &contracts.InterventionMetadata{
				Type:         responseToIntervention(resp.Level),
				ReasonCode:   string(contracts.ReasonTemporalIntervene),
				WaitDuration: resp.Duration,
			}
		} else if resp.Level == ResponseThrottle {
			intervention = &contracts.InterventionMetadata{
				Type:         contracts.InterventionThrottle,
				ReasonCode:   string(contracts.ReasonTemporalThrottle),
				WaitDuration: resp.Duration,
			}
		}
	}

	err := g.SignDecision(ctx, decision, effect, []string{}, intervention)
	if err != nil {
		return nil, err
	}

	// 4. F2: Persistence — audit failure is a hard error
	if g.auditLog != nil {
		decisionBytes, _ := canonicalize.JCS(decision)
		if _, logErr := g.auditLog.Append("guardian", "DECISION_MADE", decision.ID, string(decisionBytes)); logErr != nil {
			return nil, fmt.Errorf("audit failure for decision %s: %w", decision.ID, logErr)
		}
	}

	return decision, nil
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
