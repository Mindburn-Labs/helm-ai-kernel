// quantum_posture: SHA-256 for JCS content hashing and deterministic permit
// nonce derivation only; no signatures here (receipt signing is Ed25519 in the
// workstation engine). Classical hash, PQ posture inherited from the signer.

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalceremony"
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
	DispatchStateAdmitted      = "admitted"
	DispatchStateStarted       = "started"
	DispatchStateNotStarted    = "not_started"
	DispatchStateUncertain     = "uncertain"
)

// ApprovalEvidence is verifier-approved evidence that satisfies an escalation.
type ApprovalEvidence struct {
	ApproverID   string
	ApprovalHash string
	GrantedScope string
	// DispatchAdmission is the exact Kernel-signed near-effect authority. A
	// production effect-reservation boundary requires it for every write.
	DispatchAdmission *approvalceremony.DispatchAdmissionRecord
}

// ApprovalStore verifies approval evidence for an escalated request. It is keyed
// by the request's canonical input hash so an approval is bound to the exact
// proposed effect it was granted for.
type ApprovalStore interface {
	Approved(requestHash string) (ApprovalEvidence, bool)
}

// EffectReservationBoundary is the durable lifecycle authority used by the
// production write path. approvalceremony.EffectReservationAdmitter satisfies
// this interface without exposing database handles to the bridge.
type EffectReservationBoundary interface {
	Admit(context.Context, approvalceremony.DispatchAdmissionRecord) (approvalceremony.EffectReservationEvent, error)
	Recover(context.Context, string) (approvalceremony.EffectReservationEvent, error)
	MarkStarted(context.Context, string, approvalceremony.EffectTransitionMeta) (approvalceremony.EffectReservationEvent, error)
	MarkNotStarted(context.Context, string, approvalceremony.EffectTransitionMeta) (approvalceremony.EffectReservationEvent, error)
	MarkUncertain(context.Context, string, approvalceremony.EffectTransitionMeta) (approvalceremony.EffectReservationEvent, error)
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
	firewall     *mcpcore.ExecutionFirewall // optional boundary gate: allowlist/identity/scope/pinned-schema
	serverID     string
	scopes       []string
	profile      contracts.WorkstationPolicyProfile
	signingSeed  []byte
	nonces       effects.NonceStore
	connector    effects.Connector // optional: nil => allowed but not dispatched (no-dispatch proof)
	approvals    ApprovalStore     // optional: nil => escalations cannot be satisfied
	reservations EffectReservationBoundary
	isWrite      WriteClassifier
	permitTTL    time.Duration
	issuerID     string
	now          func() time.Time
	permitSeq    atomic.Uint64
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
	// EffectReservations enables the durable near-effect path for writes. When
	// configured, a write without an exact signed dispatch admission or a
	// lifecycle-aware connector fails closed.
	EffectReservations EffectReservationBoundary
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
		firewall:     cfg.Firewall,
		serverID:     cfg.ServerID,
		scopes:       cfg.GrantedScopes,
		profile:      profile,
		signingSeed:  cfg.SigningSeed,
		nonces:       nonces,
		connector:    cfg.Connector,
		approvals:    cfg.Approvals,
		reservations: cfg.EffectReservations,
		isWrite:      isWrite,
		permitTTL:    ttl,
		issuerID:     issuer,
		now:          now,
	}
}

// GovernedOutcome is the result of governing one MCP tool call.
type GovernedOutcome struct {
	Verdict           contracts.Verdict
	DecisionID        string
	ReceiptHash       string
	ReasonCode        string
	Reason            string
	Permit            *effects.EffectPermit
	Output            any
	OutputHash        string
	DispatchState     string
	Approval          *ApprovalEvidence
	EffectReservation *approvalceremony.EffectReservationEvent
}

// Govern evaluates an MCP tool call and, on ALLOW, mints a permit and (if a
// connector is configured) dispatches the effect. inputHash is the canonical
// hash of the request, already computed by the adapter.
func (b *GovernedBridge) Govern(ctx context.Context, req *runtimeadapters.AdaptedRequest, inputHash string) GovernedOutcome {
	now := b.now().UTC()
	permitScope, err := b.resolvePermitScope(req)
	if err != nil {
		return GovernedOutcome{
			Verdict:       contracts.VerdictDeny,
			ReasonCode:    "CONNECTOR_PERMIT_SCOPE_REJECTED",
			Reason:        err.Error(),
			DispatchState: DispatchStateNotDispatched,
		}
	}
	if b.reservations != nil && !permitScope.connectorDeclared {
		return GovernedOutcome{
			Verdict:       contracts.VerdictDeny,
			ReasonCode:    "CONNECTOR_PERMIT_SCOPE_UNSUPPORTED",
			Reason:        "durable execution connector does not declare its exact permit scope",
			DispatchState: DispatchStateNotDispatched,
		}
	}
	boundaryEffect := "read"
	if permitScope.connectorDeclared {
		boundaryEffect = strings.ToLower(string(permitScope.effectType))
	} else if b.isWrite(req.ToolName, req.Arguments) {
		boundaryEffect = "write"
	}

	// Boundary gate (allowlist / server identity / scope / pinned schema) runs
	// before policy. A boundary refusal short-circuits; policy is never asked to
	// authorize a call the boundary already rejected.
	if b.firewall != nil {
		if outcome, ok := b.authorizeBoundary(ctx, req, inputHash, boundaryEffect); !ok {
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
	// human approval evidence bound to this exact request. Connector-declared
	// effect metadata is authoritative when present; the verb heuristic remains
	// only for legacy connectors without a permit-scope contract.
	isWrite := b.isWrite(req.ToolName, req.Arguments)
	if permitScope.connectorDeclared {
		isWrite = effectTypeRequiresApproval(permitScope.effectType)
	}
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
	// ALLOW: mint a permit bound to the verdict. Write nonces are deterministic
	// over (intent, verdict, tool) — NOT the clock — so an identical approved
	// write always yields the same nonce and its second dispatch is caught as a
	// replay. Reads receive distinct single-use permits so a connector can
	// enforce single use without rejecting a safe read retry.
	permit, err := b.mintPermit(req, inputHash, receipt, now, permitScope, isWrite)
	if err != nil {
		base.Verdict = contracts.VerdictDeny
		base.ReasonCode = string(contracts.ReasonPDPError)
		base.Reason = err.Error()
		return base
	}

	var lifecycle *bridgeExecutionLifecycle
	if isWrite && b.reservations != nil {
		reservation, reservationErr := b.admitWriteReservation(ctx, req, inputHash, base.Approval)
		if reservationErr != nil {
			base.Verdict = contracts.VerdictDeny
			base.ReasonCode = "EFFECT_RESERVATION_REJECTED"
			base.Reason = reservationErr.Error()
			return base
		}
		base.EffectReservation = &reservation
		base.DispatchState = DispatchStateAdmitted
		if reservation.State != approvalceremony.EffectReservationStateAdmitted {
			base.Verdict = contracts.VerdictDeny
			base.ReasonCode = "EFFECT_RESERVATION_NOT_DISPATCHABLE"
			base.Reason = "effect reservation is not in ADMITTED state; reconcile instead of retrying"
			return base
		}
		lifecycle = &bridgeExecutionLifecycle{boundary: b.reservations, admissionID: reservation.Admission.Admission.AdmissionID}
	}

	// Single-use replay protection is enforced for WRITES only: a bounded write
	// may execute at most once per approved (request, verdict). Reads are
	// idempotent and safe to retry, so they are not consumed. The check-and-record
	// is atomic where the store supports it (the in-process default does), closing
	// the concurrent-duplicate TOCTOU window.
	if isWrite {
		if fresh, err := b.consumeNonce(permit.Nonce); err != nil {
			resolved, resolutionErr := b.resolvePreDispatchFailure(ctx, lifecycle, "NONCE_STORE_UNAVAILABLE")
			applyEffectReservation(&base, resolved)
			if resolutionErr != nil {
				base.Verdict = contracts.VerdictDeny
				base.ReasonCode = "EFFECT_LIFECYCLE_UNCERTAIN"
				base.Reason = resolutionErr.Error()
				return base
			}
			base.Verdict = contracts.VerdictDeny
			base.ReasonCode = string(contracts.ReasonPDPError)
			base.Reason = fmt.Sprintf("nonce store error: %v", err)
			return base
		} else if !fresh {
			resolved, resolutionErr := b.resolvePreDispatchFailure(ctx, lifecycle, "WRITE_PERMIT_REPLAY")
			applyEffectReservation(&base, resolved)
			if resolutionErr != nil {
				base.Verdict = contracts.VerdictDeny
				base.ReasonCode = "EFFECT_LIFECYCLE_UNCERTAIN"
				base.Reason = resolutionErr.Error()
				return base
			}
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
		resolved, resolutionErr := b.resolvePreDispatchFailure(ctx, lifecycle, "CONNECTOR_NOT_CONFIGURED")
		applyEffectReservation(&base, resolved)
		if resolutionErr != nil {
			base.Verdict = contracts.VerdictDeny
			base.ReasonCode = "EFFECT_LIFECYCLE_UNCERTAIN"
			base.Reason = resolutionErr.Error()
			return base
		}
		base.DispatchState = DispatchStateNoDispatch
		return base
	}
	var output any
	var execErr error
	if lifecycle != nil {
		connector, ok := b.connector.(effects.LifecycleConnector)
		if !ok {
			resolved, resolutionErr := b.resolvePreDispatchFailure(ctx, lifecycle, "CONNECTOR_LIFECYCLE_UNSUPPORTED")
			applyEffectReservation(&base, resolved)
			if resolutionErr != nil {
				base.Verdict = contracts.VerdictDeny
				base.ReasonCode = "EFFECT_LIFECYCLE_UNCERTAIN"
				base.Reason = resolutionErr.Error()
				return base
			}
			base.Verdict = contracts.VerdictDeny
			base.ReasonCode = "CONNECTOR_LIFECYCLE_UNSUPPORTED"
			base.Reason = "write connector does not expose a durable start seam"
			base.DispatchState = DispatchStateNotStarted
			return base
		}
		output, execErr = connector.ExecuteWithLifecycle(ctx, permit, req.ToolName, req.Arguments, lifecycle)
		current, recoverErr := b.reservations.Recover(ctx, lifecycle.admissionID)
		if recoverErr != nil {
			base.Verdict = contracts.VerdictDeny
			base.ReasonCode = "EFFECT_RESERVATION_UNVERIFIED"
			base.Reason = fmt.Sprintf("recover effect reservation after connector return: %v", recoverErr)
			base.DispatchState = DispatchStateUncertain
			return base
		}
		base.EffectReservation = &current
		base.DispatchState = dispatchStateForReservation(current.State)
		if current.State == approvalceremony.EffectReservationStateAdmitted {
			uncertain, transitionErr := b.reservations.MarkUncertain(ctx, lifecycle.admissionID, approvalceremony.EffectTransitionMeta{ReasonCode: "CONNECTOR_LIFECYCLE_MISSING"})
			if transitionErr == nil {
				base.EffectReservation = &uncertain
			}
			base.Verdict = contracts.VerdictDeny
			base.ReasonCode = "EFFECT_LIFECYCLE_UNCERTAIN"
			base.Reason = "connector returned without durable lifecycle evidence"
			base.DispatchState = DispatchStateUncertain
			return base
		}
		if execErr == nil && current.State != approvalceremony.EffectReservationStateStarted {
			base.Verdict = contracts.VerdictDeny
			base.ReasonCode = "EFFECT_LIFECYCLE_UNCERTAIN"
			base.Reason = "connector returned success without a durable STARTED event"
			return base
		}
	} else {
		output, execErr = b.connector.Execute(ctx, permit, req.ToolName, req.Arguments)
	}
	if execErr != nil {
		if lifecycle != nil {
			if base.EffectReservation != nil && base.EffectReservation.State == approvalceremony.EffectReservationStateStarted {
				if uncertain, transitionErr := b.reservations.MarkUncertain(ctx, lifecycle.admissionID, approvalceremony.EffectTransitionMeta{
					ReasonCode:            "CONNECTOR_RETURNED_ERROR_AFTER_START",
					ConnectorExecutionRef: base.EffectReservation.ConnectorExecutionRef,
					ProofSessionRef:       base.EffectReservation.ProofSessionRef,
					IntentRef:             base.EffectReservation.IntentRef,
					EffectRef:             base.EffectReservation.EffectRef,
				}); transitionErr == nil {
					base.EffectReservation = &uncertain
				}
			}
			base.DispatchState = DispatchStateUncertain
			if base.EffectReservation != nil {
				base.DispatchState = dispatchStateForReservation(base.EffectReservation.State)
			}
			base.Verdict = contracts.VerdictDeny
			base.ReasonCode = "CONNECTOR_EXECUTION_NOT_CONFIRMED"
		} else {
			base.DispatchState = DispatchStateFailed
		}
		base.Reason = execErr.Error()
		return base
	}
	outHash, hashErr := canonicalize.CanonicalHash(output)
	if hashErr != nil {
		// A source effect happened but we cannot canonicalize its output: record
		// the ambiguity for reconciliation rather than claiming clean success.
		if lifecycle != nil {
			if uncertain, transitionErr := b.reservations.MarkUncertain(ctx, lifecycle.admissionID, approvalceremony.EffectTransitionMeta{ReasonCode: "OUTPUT_EVIDENCE_INVALID"}); transitionErr == nil {
				base.EffectReservation = &uncertain
			}
			base.DispatchState = DispatchStateUncertain
			base.Verdict = contracts.VerdictDeny
		} else {
			base.DispatchState = DispatchStateFailed
		}
		base.Reason = fmt.Sprintf("output canonicalization failed: %v", hashErr)
		return base
	}
	base.Output = output
	base.OutputHash = outHash
	base.DispatchState = DispatchStateDispatched
	return base
}

func (b *GovernedBridge) admitWriteReservation(
	ctx context.Context,
	req *runtimeadapters.AdaptedRequest,
	inputHash string,
	approval *ApprovalEvidence,
) (approvalceremony.EffectReservationEvent, error) {
	if b == nil || b.reservations == nil || approval == nil || approval.DispatchAdmission == nil {
		return approvalceremony.EffectReservationEvent{}, fmt.Errorf("durable write reservation requires a Kernel-signed dispatch admission")
	}
	record := *approval.DispatchAdmission
	admission := record.Admission
	if approval.ApprovalHash == "" || approval.ApprovalHash != admission.AdmissionHash {
		return approvalceremony.EffectReservationEvent{}, fmt.Errorf("approval evidence does not bind the dispatch admission hash")
	}
	if approval.GrantedScope != req.ToolName || admission.ConnectorAuthority.ConnectorAction != req.ToolName {
		return approvalceremony.EffectReservationEvent{}, fmt.Errorf("approval connector action does not bind the requested MCP tool")
	}
	if admission.EffectHash != inputHash {
		return approvalceremony.EffectReservationEvent{}, fmt.Errorf("dispatch admission effect hash does not bind the MCP request")
	}
	if b.connector == nil || admission.ConnectorAuthority.ConnectorID != b.connector.ID() {
		return approvalceremony.EffectReservationEvent{}, fmt.Errorf("dispatch admission connector does not match the runtime connector")
	}
	return b.reservations.Admit(ctx, record)
}

func (b *GovernedBridge) resolvePreDispatchFailure(ctx context.Context, lifecycle *bridgeExecutionLifecycle, reasonCode string) (*approvalceremony.EffectReservationEvent, error) {
	if lifecycle == nil {
		return nil, nil
	}
	resolved, err := b.reservations.MarkNotStarted(ctx, lifecycle.admissionID, approvalceremony.EffectTransitionMeta{ReasonCode: reasonCode})
	if err == nil {
		return &resolved, nil
	}
	uncertain, uncertainErr := b.reservations.MarkUncertain(ctx, lifecycle.admissionID, approvalceremony.EffectTransitionMeta{ReasonCode: "PRE_DISPATCH_RESOLUTION_FAILED"})
	if uncertainErr == nil {
		return &uncertain, fmt.Errorf("persist NOT_STARTED: %w", err)
	}
	recovered, recoverErr := b.reservations.Recover(ctx, lifecycle.admissionID)
	if recoverErr == nil {
		return &recovered, errors.Join(fmt.Errorf("persist NOT_STARTED: %w", err), fmt.Errorf("persist UNCERTAIN: %w", uncertainErr))
	}
	return nil, errors.Join(fmt.Errorf("persist NOT_STARTED: %w", err), fmt.Errorf("persist UNCERTAIN: %w", uncertainErr), fmt.Errorf("recover reservation: %w", recoverErr))
}

func applyEffectReservation(outcome *GovernedOutcome, event *approvalceremony.EffectReservationEvent) {
	if outcome == nil || event == nil {
		return
	}
	outcome.EffectReservation = event
	outcome.DispatchState = dispatchStateForReservation(event.State)
}

func dispatchStateForReservation(state approvalceremony.EffectReservationState) string {
	switch state {
	case approvalceremony.EffectReservationStateAdmitted:
		return DispatchStateAdmitted
	case approvalceremony.EffectReservationStateStarted:
		return DispatchStateStarted
	case approvalceremony.EffectReservationStateNotStarted:
		return DispatchStateNotStarted
	case approvalceremony.EffectReservationStateUncertain:
		return DispatchStateUncertain
	default:
		return DispatchStateFailed
	}
}

type bridgeExecutionLifecycle struct {
	boundary    EffectReservationBoundary
	admissionID string
}

func (l *bridgeExecutionLifecycle) MarkStarted(ctx context.Context, meta effects.ExecutionLifecycleMeta) error {
	if l == nil || l.boundary == nil {
		return fmt.Errorf("effect reservation lifecycle is unavailable")
	}
	_, err := l.boundary.MarkStarted(ctx, l.admissionID, approvalEffectTransitionMeta(meta))
	if errors.Is(err, approvalceremony.ErrEffectReservationStartDenied) {
		return errors.Join(effects.ErrExecutionStartDenied, err)
	}
	return err
}

func (l *bridgeExecutionLifecycle) MarkNotStarted(ctx context.Context, meta effects.ExecutionLifecycleMeta) error {
	if l == nil || l.boundary == nil {
		return fmt.Errorf("effect reservation lifecycle is unavailable")
	}
	_, err := l.boundary.MarkNotStarted(ctx, l.admissionID, approvalEffectTransitionMeta(meta))
	return err
}

func (l *bridgeExecutionLifecycle) MarkUncertain(ctx context.Context, meta effects.ExecutionLifecycleMeta) error {
	if l == nil || l.boundary == nil {
		return fmt.Errorf("effect reservation lifecycle is unavailable")
	}
	_, err := l.boundary.MarkUncertain(ctx, l.admissionID, approvalEffectTransitionMeta(meta))
	return err
}

func approvalEffectTransitionMeta(meta effects.ExecutionLifecycleMeta) approvalceremony.EffectTransitionMeta {
	return approvalceremony.EffectTransitionMeta{
		ReasonCode: meta.ReasonCode, ConnectorExecutionRef: meta.ConnectorExecutionRef,
		ProofSessionRef: meta.ProofSessionRef, IntentRef: meta.IntentRef, EffectRef: meta.EffectRef,
	}
}

// authorizeBoundary runs the MCP execution firewall. It returns (outcome,false)
// when the boundary refuses (caller returns that outcome); (_,true) when the
// boundary authorizes dispatch and policy evaluation should proceed. It is
// fail-closed: schema/canonicalization or firewall errors deny.
func (b *GovernedBridge) authorizeBoundary(ctx context.Context, req *runtimeadapters.AdaptedRequest, inputHash, effect string) (GovernedOutcome, bool) {
	serverID := firstNonEmpty(b.serverID, req.Metadata["server_id"])
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

type permitScopeResolution struct {
	effectType        effects.EffectType
	scope             effects.EffectScope
	resourceRef       string
	connectorDeclared bool
}

func (b *GovernedBridge) resolvePermitScope(req *runtimeadapters.AdaptedRequest) (permitScopeResolution, error) {
	resolution := permitScopeResolution{
		effectType:  effects.EffectTypeExecute,
		scope:       effects.EffectScope{AllowedAction: req.ToolName},
		resourceRef: req.ToolName,
	}
	provider, ok := b.connector.(effects.PermitScopeProvider)
	if !ok {
		return resolution, nil
	}
	effectType, scope, resourceRef, err := provider.PermitScope(req.ToolName, req.Arguments)
	if err != nil {
		return permitScopeResolution{}, fmt.Errorf("mcp bridge: connector permit scope: %w", err)
	}
	if !knownEffectType(effectType) {
		return permitScopeResolution{}, fmt.Errorf("mcp bridge: connector permit scope returned unsupported effect type %q", effectType)
	}
	if scope.AllowedAction != req.ToolName {
		return permitScopeResolution{}, fmt.Errorf("mcp bridge: connector permit action %q does not bind %q", scope.AllowedAction, req.ToolName)
	}
	if effectTypeRequiresApproval(effectType) && strings.TrimSpace(resourceRef) == "" {
		return permitScopeResolution{}, fmt.Errorf("mcp bridge: connector permit scope omitted the governed resource")
	}
	return permitScopeResolution{
		effectType: effectType, scope: scope, resourceRef: resourceRef, connectorDeclared: true,
	}, nil
}

func knownEffectType(effectType effects.EffectType) bool {
	switch effectType {
	case effects.EffectTypeRead, effects.EffectTypeWrite, effects.EffectTypeDelete,
		effects.EffectTypeExecute, effects.EffectTypeNetwork, effects.EffectTypeFinance:
		return true
	default:
		return false
	}
}

func effectTypeRequiresApproval(effectType effects.EffectType) bool {
	return effectType != effects.EffectTypeRead
}

func (b *GovernedBridge) mintPermit(req *runtimeadapters.AdaptedRequest, inputHash string, receipt *contracts.WorkstationPolicyDecisionReceipt, now time.Time, resolution permitScopeResolution, isWrite bool) (*effects.EffectPermit, error) {
	verdictHash, err := canonicalize.CanonicalHash(receipt)
	if err != nil {
		return nil, fmt.Errorf("mcp bridge: verdict hash: %w", err)
	}
	// Writes keep a deterministic nonce so an identical approved effect is caught
	// as replay. Reads receive a per-bridge sequence so a connector can enforce a
	// single-use permit while the bridge still permits safe read retries.
	nonceParts := []string{inputHash, verdictHash, req.ToolName}
	if !isWrite {
		nonceParts = append(nonceParts, fmt.Sprintf("read:%d", b.permitSeq.Add(1)))
	}
	nonceSum := sha256.Sum256([]byte(strings.Join(nonceParts, "|")))
	permit := &effects.EffectPermit{
		PermitID:    "permit-" + hex.EncodeToString(nonceSum[:8]),
		IntentHash:  inputHash,
		VerdictHash: verdictHash,
		EffectType:  resolution.effectType,
		ConnectorID: connectorIDFor(b.connector),
		Scope:       resolution.scope,
		ResourceRef: resolution.resourceRef,
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
