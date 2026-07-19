// quantum_posture: SHA-256 for JCS content hashing and deterministic permit
// nonce derivation only; no signatures here (receipt signing is Ed25519 in the
// workstation engine). Classical hash, PQ posture inherited from the signer.

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	mcpcore "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtimeadapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

// Dispatch states recorded on a governed MCP effect.
const (
	DispatchStateDispatched    = "dispatched"
	DispatchStateFailed        = "dispatch_failed"
	DispatchStateNoDispatch    = "no_dispatch_proof"
	DispatchStateNotDispatched = "not_dispatched"
)

// ApprovalEvidence is verifier-approved evidence that satisfies an escalation.
type ApprovalEvidence struct {
	ApproverID   string
	ApprovalHash string
	GrantedScope string
}

// ApprovalStore verifies approval evidence for an escalated request. It is keyed
// by the request's canonical input hash so an approval is bound to the exact
// proposed effect it was granted for.
type ApprovalStore interface {
	Approved(requestHash string) (ApprovalEvidence, bool)
}

// WriteClassifier reports whether a tool call is a bounded write that requires
// human approval before dispatch, even when policy would otherwise allow it.
type WriteClassifier func(toolName string, args map[string]any) bool

// DefaultWriteClassifier flags tool names with common mutating verbs. Deployments
// should replace it with connector-declared effect classes.
//
// ponytail: verb heuristic; connector effect-class metadata should drive this in
// production (see effects.EffectRequest.EffectType).
func DefaultWriteClassifier(toolName string, _ map[string]any) bool {
	lower := strings.ToLower(toolName)
	for _, verb := range []string{"create", "update", "delete", "send", "write", "add", "post", "merge", "deploy", "publish", "pay", "transfer", "remove", "set", "close", "comment"} {
		if strings.Contains(lower, verb) {
			return true
		}
	}
	return false
}

// GovernedBridge turns an MCP tool call into a governed decision, a signed
// workstation decision receipt, an EffectPermit, and (optionally) a dispatched
// source-system effect. It composes the existing workstation enforcement engine
// (ALLOW/DENY) with an approval-gated ESCALATE tier for bounded writes.
//
// It is fail-closed: any internal error yields a DENY outcome, never an ALLOW.
//
// Threat-model note: policy authority here is the workstation profile engine
// (workstation.Decide), NOT the full 6-gate guardian PEP. It enforces
// operate-permission and (via the boundary firewall) allowlist/identity/scope,
// but it does not run the Threat/injection, Freeze, or full Delegation-scope
// gates. MCP is a prime prompt-injection surface, so routing it through the
// complete guardian pipeline is a tracked follow-up before this bridge is
// enabled by default. DelegationSessionID is forwarded into the decision record
// but not yet scope-enforced on this path.
type GovernedBridge struct {
	firewall    *mcpcore.ExecutionFirewall // optional boundary gate: allowlist/identity/scope/pinned-schema
	serverID    string
	scopes      []string
	profile     contracts.WorkstationPolicyProfile
	signingSeed []byte
	nonces      effects.NonceStore
	connector   effects.Connector // optional: nil => allowed but not dispatched (no-dispatch proof)
	approvals   ApprovalStore     // optional: nil => escalations cannot be satisfied
	isWrite     WriteClassifier
	permitTTL   time.Duration
	issuerID    string
	now         func() time.Time
}

// BridgeConfig configures a GovernedBridge.
type BridgeConfig struct {
	// Firewall, when set, is the MCP boundary authority run BEFORE policy:
	// server-identity (quarantine), tool allowlist (catalog), permission scope,
	// and pinned-schema/argument canonicalization. A boundary refusal short-
	// circuits to DENY/ESCALATE and policy is never consulted. Nil => the bridge
	// relies on policy alone (still fail-closed via the deny-all default profile).
	Firewall *mcpcore.ExecutionFirewall
	// ServerID identifies the MCP server for boundary authorization. Falls back
	// to req.Metadata["server_id"] when empty.
	ServerID string
	// GrantedScopes are the OAuth scopes presented for boundary scope checks.
	GrantedScopes []string
	// Profile is the workstation policy profile. Zero value uses the default
	// observe/draft profile (which denies all operate-class MCP calls).
	Profile contracts.WorkstationPolicyProfile
	// SigningSeed is the Ed25519 seed used to sign decision receipts. It is
	// required; a zero value fails closed through the governed decision path.
	SigningSeed []byte
	// Nonces prevents permit replay. Zero value uses an in-process store.
	Nonces effects.NonceStore
	// Connector dispatches ALLOW effects. Nil => allowed but not dispatched.
	Connector effects.Connector
	// Approvals verifies approval evidence for escalated writes. Nil => writes
	// requiring approval always escalate and can never proceed.
	Approvals ApprovalStore
	// IsWrite classifies bounded writes that require approval. Nil => default.
	IsWrite WriteClassifier
	// PermitTTL bounds permit validity. Zero => 5 minutes.
	PermitTTL time.Duration
	// IssuerID identifies the permit issuer. Zero => "mcp-governed-bridge-v1".
	IssuerID string
	// Now is the clock (injectable for deterministic tests). Nil => time.Now.
	Now func() time.Time
}

// NewGovernedBridge builds a GovernedBridge from config, applying safe defaults.
func NewGovernedBridge(cfg BridgeConfig) *GovernedBridge {
	profile := cfg.Profile
	if profile.ID == "" {
		profile = workstation.DefaultObserveDraftProfile()
	}
	nonces := cfg.Nonces
	if nonces == nil {
		nonces = NewMemoryNonceStore()
	}
	isWrite := cfg.IsWrite
	if isWrite == nil {
		isWrite = DefaultWriteClassifier
	}
	ttl := cfg.PermitTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	issuer := cfg.IssuerID
	if issuer == "" {
		issuer = "mcp-governed-bridge-v1"
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &GovernedBridge{
		firewall:    cfg.Firewall,
		serverID:    cfg.ServerID,
		scopes:      cfg.GrantedScopes,
		profile:     profile,
		signingSeed: cfg.SigningSeed,
		nonces:      nonces,
		connector:   cfg.Connector,
		approvals:   cfg.Approvals,
		isWrite:     isWrite,
		permitTTL:   ttl,
		issuerID:    issuer,
		now:         now,
	}
}

// GovernedOutcome is the result of governing one MCP tool call.
type GovernedOutcome struct {
	Verdict       contracts.Verdict
	DecisionID    string
	ReceiptHash   string
	ReasonCode    string
	Reason        string
	Permit        *effects.EffectPermit
	Output        any
	OutputHash    string
	DispatchState string
	Approval      *ApprovalEvidence
}

// Govern evaluates an MCP tool call and, on ALLOW, mints a permit and (if a
// connector is configured) dispatches the effect. inputHash is the canonical
// hash of the request, already computed by the adapter.
func (b *GovernedBridge) Govern(ctx context.Context, req *runtimeadapters.AdaptedRequest, inputHash string) GovernedOutcome {
	now := b.now().UTC()

	// Boundary gate (allowlist / server identity / scope / pinned schema) runs
	// before policy. A boundary refusal short-circuits; policy is never asked to
	// authorize a call the boundary already rejected.
	if b.firewall != nil {
		if outcome, ok := b.authorizeBoundary(ctx, req, inputHash); !ok {
			return outcome
		}
	}

	decisionReq := contracts.WorkstationDecisionRequest{
		RequestID:    firstNonEmpty(req.SessionID, inputHash),
		RunID:        req.SessionID,
		ActorID:      req.PrincipalID,
		WorkspaceID:  req.Metadata["workspace_id"],
		AgentSurface: firstNonEmpty(req.RuntimeType, "mcp"),
		ToolID:       req.ToolName,
		Action:       "mcp_tool_call",
		EffectType:   contracts.EffectTypeWorkstationMCPToolCall,
		EffectMode:   contracts.WorkstationEffectModeOperate,
		Target:       req.ToolName,
		Metadata:     mergeMetadata(req.Metadata, inputHash, req.DelegationSessionID),
		OccurredAt:   now,
	}

	receipt, err := workstation.Decide(b.profile, decisionReq, workstation.DecisionOptions{SigningSeed: b.signingSeed})
	if err != nil {
		// Fail closed: a decision-engine error is a denial, never an allow.
		return GovernedOutcome{
			Verdict:       contracts.VerdictDeny,
			ReasonCode:    string(contracts.ReasonPDPError),
			Reason:        fmt.Sprintf("workstation decision failed: %v", err),
			DispatchState: DispatchStateNotDispatched,
		}
	}

	base := GovernedOutcome{
		DecisionID:    receipt.DecisionID,
		ReceiptHash:   receipt.ReceiptHash,
		ReasonCode:    receipt.ReasonCode,
		Reason:        receipt.Reason,
		DispatchState: DispatchStateNotDispatched,
	}

	// Base policy DENY is terminal.
	if receipt.Verdict != contracts.WorkstationVerdictAllow {
		base.Verdict = contracts.VerdictDeny
		return base
	}

	// Approval-gated ESCALATE tier: policy allows it, but a bounded write needs
	// human approval evidence bound to this exact request.
	isWrite := b.isWrite(req.ToolName, req.Arguments)
	if isWrite {
		approval, ok := b.checkApproval(inputHash)
		if !ok {
			base.Verdict = contracts.VerdictEscalate
			base.ReasonCode = string(contracts.ReasonApprovalRequired)
			base.Reason = "bounded write requires human approval before dispatch"
			return base
		}
		base.Approval = &approval
	}

	// ALLOW: mint a permit bound to the verdict. The nonce is deterministic over
	// (intent, verdict, tool) — NOT the clock — so an identical request always
	// yields the same nonce and can be recognized as a replay regardless of when
	// it arrives.
	permit, err := b.mintPermit(req, inputHash, receipt, now)
	if err != nil {
		base.Verdict = contracts.VerdictDeny
		base.ReasonCode = string(contracts.ReasonPDPError)
		base.Reason = err.Error()
		return base
	}

	// Single-use replay protection is enforced for WRITES only: a bounded write
	// may execute at most once per approved (request, verdict). Reads are
	// idempotent and safe to retry, so they are not consumed. The check-and-record
	// is atomic where the store supports it (the in-process default does), closing
	// the concurrent-duplicate TOCTOU window.
	if isWrite {
		if fresh, err := b.consumeNonce(permit.Nonce); err != nil {
			base.Verdict = contracts.VerdictDeny
			base.ReasonCode = string(contracts.ReasonPDPError)
			base.Reason = fmt.Sprintf("nonce store error: %v", err)
			return base
		} else if !fresh {
			base.Verdict = contracts.VerdictDeny
			base.ReasonCode = string(contracts.ReasonPlanTransactionConflict)
			base.Reason = "single-use write permit already consumed (replay)"
			return base
		}
	}

	base.Verdict = contracts.VerdictAllow
	base.Permit = permit

	// Dispatch through the connector if one is bound; otherwise emit no-dispatch
	// proof (allowed, but the effect was not executed by the kernel).
	if b.connector == nil {
		base.DispatchState = DispatchStateNoDispatch
		return base
	}
	output, execErr := b.connector.Execute(ctx, permit, req.ToolName, req.Arguments)
	if execErr != nil {
		base.DispatchState = DispatchStateFailed
		base.Reason = execErr.Error()
		return base
	}
	outHash, hashErr := canonicalize.CanonicalHash(output)
	if hashErr != nil {
		// A source effect happened but we cannot canonicalize its output: record
		// the ambiguity for reconciliation rather than claiming clean success.
		base.DispatchState = DispatchStateFailed
		base.Reason = fmt.Sprintf("output canonicalization failed: %v", hashErr)
		return base
	}
	base.Output = output
	base.OutputHash = outHash
	base.DispatchState = DispatchStateDispatched
	return base
}

// authorizeBoundary runs the MCP execution firewall. It returns (outcome,false)
// when the boundary refuses (caller returns that outcome); (_,true) when the
// boundary authorizes dispatch and policy evaluation should proceed. It is
// fail-closed: schema/canonicalization or firewall errors deny.
func (b *GovernedBridge) authorizeBoundary(ctx context.Context, req *runtimeadapters.AdaptedRequest, inputHash string) (GovernedOutcome, bool) {
	serverID := firstNonEmpty(b.serverID, req.Metadata["server_id"])
	effect := "read"
	if b.isWrite(req.ToolName, req.Arguments) {
		effect = "write"
	}
	argsHash := inputHash
	if tool, ok := b.firewall.Catalog.Lookup(req.ToolName); ok {
		hash, err := mcpcore.ValidateToolArguments(tool, req.Arguments)
		if err != nil {
			return GovernedOutcome{
				Verdict:       contracts.VerdictDeny,
				ReasonCode:    string(contracts.ReasonSchemaViolation),
				Reason:        fmt.Sprintf("tool argument validation failed: %v", err),
				DispatchState: DispatchStateNotDispatched,
			}, false
		}
		argsHash = hash
	}

	record, err := b.firewall.AuthorizeToolCall(ctx, mcpcore.ToolCallAuthorization{
		ServerID:      serverID,
		ToolName:      req.ToolName,
		Effect:        effect,
		ArgsHash:      argsHash,
		GrantedScopes: b.scopes,
	})
	if err != nil {
		return GovernedOutcome{
			Verdict:       contracts.VerdictDeny,
			ReasonCode:    string(contracts.ReasonPDPError),
			Reason:        fmt.Sprintf("boundary authorization failed: %v", err),
			DispatchState: DispatchStateNotDispatched,
		}, false
	}
	if mcpcore.ShouldDispatch(record) {
		return GovernedOutcome{}, true
	}

	verdict := contracts.VerdictDeny
	if record.Verdict == contracts.VerdictEscalate {
		verdict = contracts.VerdictEscalate
	}
	return GovernedOutcome{
		Verdict:       verdict,
		DecisionID:    record.RecordID,
		ReceiptHash:   record.RecordHash,
		ReasonCode:    string(record.ReasonCode),
		Reason:        "denied at MCP execution boundary",
		DispatchState: DispatchStateNotDispatched,
	}, false
}

func (b *GovernedBridge) checkApproval(inputHash string) (ApprovalEvidence, bool) {
	if b.approvals == nil {
		return ApprovalEvidence{}, false
	}
	ev, ok := b.approvals.Approved(inputHash)
	// Reject empty evidence: an ApprovalStore that returns ok=true with no
	// approver has not actually approved anything. This is a floor, not a
	// cryptographic bind — a hardened store should also commit the evidence to
	// inputHash.
	if !ok || strings.TrimSpace(ev.ApproverID) == "" {
		return ApprovalEvidence{}, false
	}
	return ev, true
}

// atomicNonceStore is the check-and-record-in-one-step extension of
// effects.NonceStore. The in-process default implements it; external stores that
// do not fall back to a (non-atomic) HasNonce+RecordNonce sequence.
type atomicNonceStore interface {
	RecordIfAbsent(nonce string) (bool, error)
}

// consumeNonce records the nonce and reports whether it was fresh (not seen
// before). It uses the atomic path when the store supports it.
func (b *GovernedBridge) consumeNonce(nonce string) (bool, error) {
	if atomic, ok := b.nonces.(atomicNonceStore); ok {
		return atomic.RecordIfAbsent(nonce)
	}
	if b.nonces.HasNonce(nonce) {
		return false, nil
	}
	return true, b.nonces.RecordNonce(nonce)
}

func (b *GovernedBridge) mintPermit(req *runtimeadapters.AdaptedRequest, inputHash string, receipt *contracts.WorkstationPolicyDecisionReceipt, now time.Time) (*effects.EffectPermit, error) {
	verdictHash, err := canonicalize.CanonicalHash(receipt)
	if err != nil {
		return nil, fmt.Errorf("mcp bridge: verdict hash: %w", err)
	}
	// Nonce binds the permit to its intent, verdict, and tool — deterministically,
	// with NO clock component — so an identical approved write always produces the
	// same nonce and its second dispatch is caught as a replay. inputHash and
	// verdictHash are hex, so the "|" join is unambiguous.
	nonceSum := sha256.Sum256([]byte(strings.Join([]string{inputHash, verdictHash, req.ToolName}, "|")))
	permit := &effects.EffectPermit{
		PermitID:    "permit-" + hex.EncodeToString(nonceSum[:8]),
		IntentHash:  inputHash,
		VerdictHash: verdictHash,
		EffectType:  effects.EffectTypeExecute,
		ConnectorID: connectorIDFor(b.connector),
		Scope:       effects.EffectScope{AllowedAction: req.ToolName},
		ResourceRef: req.ToolName,
		ExpiresAt:   now.Add(b.permitTTL),
		SingleUse:   true,
		Nonce:       hex.EncodeToString(nonceSum[:]),
		IssuedAt:    now,
		IssuerID:    b.issuerID,
	}
	if receipt.DecisionID != "" {
		permit.EvidenceBindings = map[string]string{"decision_id": receipt.DecisionID}
	}
	return permit, nil
}

func connectorIDFor(c effects.Connector) string {
	if c == nil {
		return ""
	}
	return c.ID()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func mergeMetadata(md map[string]string, inputHash, delegationSessionID string) map[string]string {
	out := map[string]string{"input_hash": inputHash}
	for k, v := range md {
		out[k] = v
	}
	// Forward the delegation session so the decision record carries it. Full
	// delegation-scope enforcement on the MCP surface is a follow-up (see the
	// GovernedBridge threat-model note) — this preserves the reference today.
	if strings.TrimSpace(delegationSessionID) != "" {
		out["delegation_session_id"] = delegationSessionID
	}
	return out
}

// MemoryNonceStore is an in-process effects.NonceStore. It is the safe default
// for a single-process kernel; a deployment that needs durable, cross-process
// replay protection injects a data-plane-backed store instead.
//
// ponytail: in-memory map; durable permit/nonce state is a data-plane concern.
type MemoryNonceStore struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

// NewMemoryNonceStore builds an empty in-process nonce store.
func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{seen: make(map[string]struct{})}
}

// HasNonce reports whether the nonce was already recorded.
func (s *MemoryNonceStore) HasNonce(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.seen[nonce]
	return ok
}

// RecordNonce marks a nonce consumed.
func (s *MemoryNonceStore) RecordNonce(nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[nonce] = struct{}{}
	return nil
}

// RecordIfAbsent atomically records the nonce and reports whether it was fresh
// (not previously seen). It closes the check-then-record TOCTOU window under
// concurrent identical requests.
func (s *MemoryNonceStore) RecordIfAbsent(nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[nonce]; ok {
		return false, nil
	}
	s.seen[nonce] = struct{}{}
	return true, nil
}

// MemoryApprovalStore is an in-process ApprovalStore keyed by request input hash.
type MemoryApprovalStore struct {
	mu       sync.Mutex
	approved map[string]ApprovalEvidence
}

// NewMemoryApprovalStore builds an empty approval store.
func NewMemoryApprovalStore() *MemoryApprovalStore {
	return &MemoryApprovalStore{approved: make(map[string]ApprovalEvidence)}
}

// Grant records approval evidence for a request input hash.
func (s *MemoryApprovalStore) Grant(requestHash string, ev ApprovalEvidence) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.approved[requestHash] = ev
}

// Approved returns approval evidence for a request input hash, if present.
func (s *MemoryApprovalStore) Approved(requestHash string) (ApprovalEvidence, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ev, ok := s.approved[requestHash]
	return ev, ok
}
