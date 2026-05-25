package safedep

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

var ErrDispatchBlocked = errors.New("safe dep: dispatch blocked")

type Signal struct {
	HazardCode   contracts.SafeDepHazardCode `json:"hazard_code"`
	LaneID       string                      `json:"lane_id,omitempty"`
	ConnectorID  string                      `json:"connector_id,omitempty"`
	ActiveClock  bool                        `json:"active_clock"`
	HighRiskLane bool                        `json:"high_risk_lane"`
	Reason       string                      `json:"reason,omitempty"`
	Evidence     map[string]string           `json:"evidence,omitempty"`
}

type HazardCodedError interface {
	SafeDepHazardCode() contracts.SafeDepHazardCode
}

func SignalFromError(err error, activeClock bool, highRiskLane bool) Signal {
	if err == nil {
		return Signal{}
	}
	var coded HazardCodedError
	if !errors.As(err, &coded) {
		return Signal{}
	}
	return Signal{
		HazardCode:   coded.SafeDepHazardCode(),
		ActiveClock:  activeClock,
		HighRiskLane: highRiskLane,
		Reason:       err.Error(),
	}
}

func (s Signal) Empty() bool {
	return strings.TrimSpace(string(s.HazardCode)) == ""
}

type GateRequest struct {
	Signal             Signal
	Checkpoint         contracts.ContinuityCheckpoint
	Capsule            *contracts.EmergencyCapsule
	DevFallbackPosture contracts.DevFallbackPosture
	Expectation        ActivationExpectation
	Intent             *contracts.AuthorizedExecutionIntent

	DecisionID     string
	EffectID       string
	EffectType     string
	Action         string
	ToolName       string
	ConnectorID    string
	InspectionOnly bool
}

type GateResult struct {
	Classification    contracts.HazardClassification `json:"classification"`
	DispatchAllowed   bool                           `json:"dispatch_allowed"`
	ReadOnly          bool                           `json:"read_only"`
	NarrowedScope     bool                           `json:"narrowed_scope"`
	ReasonCode        contracts.ReasonCode           `json:"reason_code"`
	Reason            string                         `json:"reason,omitempty"`
	ActivationReceipt *contracts.ActivationReceipt   `json:"activation_receipt,omitempty"`
	ProofGraphRef     string                         `json:"proof_graph_ref,omitempty"`
	EvidencePackRef   string                         `json:"evidence_pack_ref,omitempty"`
}

type ContinuityState struct {
	CheckpointID     string    `json:"checkpoint_id"`
	CheckpointHash   string    `json:"checkpoint_hash"`
	HazardSequence   uint64    `json:"hazard_sequence"`
	PolicyEpoch      uint64    `json:"policy_epoch"`
	LamportClock     uint64    `json:"lamport_clock"`
	DeadManWindowID  string    `json:"dead_man_window_id,omitempty"`
	ActivationID     string    `json:"activation_id,omitempty"`
	ActivationExpiry time.Time `json:"activation_expiry,omitempty"`
}

type ContinuityStore interface {
	Latest(ctx context.Context) (ContinuityState, bool, error)
	AppendCheckpoint(ctx context.Context, checkpoint contracts.ContinuityCheckpoint) (ContinuityState, error)
	StoreActivation(ctx context.Context, receipt contracts.ActivationReceipt) error
	GetActivation(ctx context.Context, activationID string) (contracts.ActivationReceipt, bool, error)
	CloseActivation(ctx context.Context, activationID string, checkpoint contracts.ContinuityCheckpoint) error
}

type EvidenceRefs struct {
	ProofGraphRef   string
	EvidencePackRef string
}

type EvidenceEvent struct {
	Type           string                          `json:"type"`
	Classification contracts.HazardClassification  `json:"classification,omitempty"`
	Checkpoint     *contracts.ContinuityCheckpoint `json:"checkpoint,omitempty"`
	CapsuleID      string                          `json:"capsule_id,omitempty"`
	ActivationID   string                          `json:"activation_id,omitempty"`
	ReasonCode     contracts.ReasonCode            `json:"reason_code,omitempty"`
	Reason         string                          `json:"reason,omitempty"`
	OccurredAt     time.Time                       `json:"occurred_at"`
}

type EvidenceSink interface {
	RecordSafeDepEvent(ctx context.Context, event EvidenceEvent) (EvidenceRefs, error)
}

type ReceiptSigner interface {
	Sign(data []byte) (string, error)
}

type ControllerConfig struct {
	Store                  ContinuityStore
	Evidence               EvidenceSink
	Signer                 ReceiptSigner
	Clock                  func() time.Time
	DefaultQuorum          int
	DefaultMaxTTL          time.Duration
	RequireHardwareBound   bool
	RequireDistinctRoles   bool
	RequireTransparency    bool
	RequireDeadManActive   bool
	MaxContinuityClockSkew time.Duration
}

type Controller struct {
	store                ContinuityStore
	evidence             EvidenceSink
	signer               ReceiptSigner
	clock                func() time.Time
	defaultQuorum        int
	defaultMaxTTL        time.Duration
	requireHardwareBound bool
	requireDistinctRoles bool
	requireTransparency  bool
	requireDeadManActive bool
	maxClockSkew         time.Duration
}

func NewController(cfg ControllerConfig) *Controller {
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	store := cfg.Store
	if store == nil {
		store = NewMemoryContinuityStore()
	}
	evidence := cfg.Evidence
	if evidence == nil {
		evidence = HashEvidenceSink{}
	}
	quorum := cfg.DefaultQuorum
	if quorum == 0 {
		quorum = 3
	}
	return &Controller{
		store:                store,
		evidence:             evidence,
		signer:               cfg.Signer,
		clock:                clock,
		defaultQuorum:        quorum,
		defaultMaxTTL:        cfg.DefaultMaxTTL,
		requireHardwareBound: cfg.RequireHardwareBound,
		requireDistinctRoles: cfg.RequireDistinctRoles,
		requireTransparency:  cfg.RequireTransparency,
		requireDeadManActive: cfg.RequireDeadManActive,
		maxClockSkew:         cfg.MaxContinuityClockSkew,
	}
}

func (c *Controller) Classify(ctx context.Context, signal Signal) (contracts.HazardClassification, error) {
	classification := ClassifyHazard(signal.HazardCode, signal.ActiveClock, signal.HighRiskLane)
	classification.LaneID = strings.TrimSpace(signal.LaneID)
	classification.ConnectorID = strings.TrimSpace(signal.ConnectorID)
	if c != nil {
		_, _ = c.record(ctx, EvidenceEvent{
			Type:           "safedep.classification",
			Classification: classification,
			ReasonCode:     classification.ReasonCode,
			Reason:         signal.Reason,
			OccurredAt:     c.now(),
		})
	}
	return classification, nil
}

func (c *Controller) Gate(ctx context.Context, req GateRequest) (GateResult, error) {
	if c == nil || req.Signal.Empty() {
		return GateResult{DispatchAllowed: true}, nil
	}
	if err := ctx.Err(); err != nil {
		return GateResult{}, err
	}
	if req.Signal.ConnectorID == "" {
		req.Signal.ConnectorID = req.ConnectorID
	}
	classification, err := c.Classify(ctx, req.Signal)
	if err != nil {
		return GateResult{}, err
	}
	result := GateResult{
		Classification: classification,
		ReasonCode:     classification.ReasonCode,
		Reason:         req.Signal.Reason,
		ReadOnly:       classification.State == contracts.SafeDepDeprecatedReadonly,
		NarrowedScope:  classification.State == contracts.SafeDepDegradedNarrowing,
	}

	switch classification.State {
	case contracts.SafeDepTerminalFreeze:
		c.attachEvidence(ctx, &result, "safedep.terminal_freeze", nil, nil)
		return result, nil
	case contracts.SafeDepDeprecatedReadonly:
		if req.InspectionOnly || IsInspectionAction(req.Action, req.ToolName) {
			result.DispatchAllowed = true
			c.attachEvidence(ctx, &result, "safedep.deprecated_readonly.allow", nil, nil)
			return result, nil
		}
		c.attachEvidence(ctx, &result, "safedep.deprecated_readonly.deny", nil, nil)
		return result, nil
	case contracts.SafeDepDegradedNarrowing:
		if !classification.ActivationAllowed {
			c.attachEvidence(ctx, &result, "safedep.degraded_narrowing.clock_inactive", nil, nil)
			return result, nil
		}
		receipt, err := c.activate(ctx, req, classification)
		if err != nil {
			result.Reason = err.Error()
			c.attachEvidence(ctx, &result, "safedep.degraded_narrowing.deny", nil, nil)
			return result, err
		}
		result.DispatchAllowed = true
		result.ActivationReceipt = &receipt
		result.ProofGraphRef = receipt.ProofGraphRef
		result.EvidencePackRef = receipt.EvidencePackRef
		if req.Intent != nil {
			req.Intent.EmergencyActivationID = receipt.ActivationID
			req.Intent.EmergencyDelegationSessionID = receipt.DelegationSessionID
			req.Intent.EmergencyScopeHash = firstScopeHash(req.Capsule.Delegation)
		}
		return result, nil
	default:
		c.attachEvidence(ctx, &result, "safedep.unknown_hazard", nil, nil)
		return result, nil
	}
}

func (c *Controller) Restore(ctx context.Context, activationID string, checkpoint contracts.ContinuityCheckpoint) error {
	if c == nil {
		return nil
	}
	latest, ok, err := c.store.Latest(ctx)
	if err != nil {
		return err
	}
	expected := ContinuityExpectation{
		MinHazardSequence:            latest.HazardSequence,
		LatestAcceptedCheckpointHash: latest.CheckpointHash,
		RequireDeadManActive:         false,
		Now:                          c.now(),
		MaxClockSkew:                 c.maxClockSkew,
	}
	if !ok {
		expected.MinHazardSequence = 0
		expected.LatestAcceptedCheckpointHash = ""
	}
	if err := ValidateContinuity(checkpoint, expected); err != nil {
		return err
	}
	if _, err := c.store.AppendCheckpoint(ctx, checkpoint); err != nil {
		return err
	}
	if err := c.store.CloseActivation(ctx, activationID, checkpoint); err != nil {
		return err
	}
	_, _ = c.record(ctx, EvidenceEvent{
		Type:         "safedep.restore",
		Checkpoint:   &checkpoint,
		ActivationID: activationID,
		OccurredAt:   c.now(),
	})
	return nil
}

func (c *Controller) activate(ctx context.Context, req GateRequest, classification contracts.HazardClassification) (contracts.ActivationReceipt, error) {
	if req.Capsule == nil {
		return contracts.ActivationReceipt{}, fmt.Errorf("%w: no matching emergency capsule", ErrEmergencyCapsuleInvalid)
	}
	now := c.now()
	expectation, err := c.defaultExpectation(ctx, req, *req.Capsule)
	if err != nil {
		return contracts.ActivationReceipt{}, err
	}
	if err := ValidateDevFallbackPosture(req.DevFallbackPosture); err != nil {
		return contracts.ActivationReceipt{}, err
	}
	if err := ValidateContinuity(req.Checkpoint, expectation.Continuity); err != nil {
		return contracts.ActivationReceipt{}, err
	}
	if err := ValidateEmergencyCapsule(*req.Capsule, expectation.Capsule); err != nil {
		return contracts.ActivationReceipt{}, err
	}
	if err := ValidateHardwareCeremony(req.Capsule.Ceremony, expectation.Ceremony); err != nil {
		return contracts.ActivationReceipt{}, err
	}
	if err := ValidateEmergencyDelegation(req.Capsule.Delegation, now); err != nil {
		return contracts.ActivationReceipt{}, err
	}
	if err := ValidateAttestationResult(req.Capsule.Attestation, expectation.Attestation); err != nil {
		return contracts.ActivationReceipt{}, err
	}
	if err := validateCapsuleScope(*req.Capsule, req); err != nil {
		return contracts.ActivationReceipt{}, err
	}
	state, err := c.store.AppendCheckpoint(ctx, req.Checkpoint)
	if err != nil {
		return contracts.ActivationReceipt{}, err
	}
	receipt := contracts.ActivationReceipt{
		ActivationID:        activationID(*req.Capsule, req.Checkpoint),
		CapsuleID:           req.Capsule.CapsuleID,
		ApertureID:          req.Capsule.ApertureID,
		State:               classification.State,
		HazardCode:          classification.HazardCode,
		ContinuityHash:      state.CheckpointHash,
		CeremonyHash:        req.Capsule.Ceremony.TranscriptHash,
		DelegationSessionID: req.Capsule.Delegation.SessionID,
		PolicyEpoch:         req.Capsule.PolicyEpoch,
		ActivatedAt:         now,
		ExpiresAt:           req.Capsule.ExpiresAt,
		ReasonCode:          classification.ReasonCode,
		Transparency:        req.Capsule.Transparency,
		Attestation:         req.Capsule.Attestation,
	}
	refs, err := c.record(ctx, EvidenceEvent{
		Type:           "safedep.activation",
		Classification: classification,
		Checkpoint:     &req.Checkpoint,
		CapsuleID:      req.Capsule.CapsuleID,
		ActivationID:   receipt.ActivationID,
		ReasonCode:     classification.ReasonCode,
		OccurredAt:     now,
	})
	if err != nil {
		return contracts.ActivationReceipt{}, err
	}
	receipt.ProofGraphRef = refs.ProofGraphRef
	receipt.EvidencePackRef = refs.EvidencePackRef
	if c.signer != nil {
		payload, err := canonicalize.JCS(receipt)
		if err != nil {
			return contracts.ActivationReceipt{}, err
		}
		sig, err := c.signer.Sign(payload)
		if err != nil {
			return contracts.ActivationReceipt{}, err
		}
		receipt.Signature = sig
	}
	if err := c.store.StoreActivation(ctx, receipt); err != nil {
		return contracts.ActivationReceipt{}, err
	}
	return receipt, nil
}

func (c *Controller) defaultExpectation(ctx context.Context, req GateRequest, capsule contracts.EmergencyCapsule) (ActivationExpectation, error) {
	expectation := req.Expectation
	now := c.now()
	latest, ok, err := c.store.Latest(ctx)
	if err != nil {
		return expectation, err
	}
	if expectation.Now.IsZero() {
		expectation.Now = now
	}
	if expectation.Continuity.Now.IsZero() {
		expectation.Continuity.Now = now
	}
	if expectation.Continuity.PolicyEpoch == 0 {
		expectation.Continuity.PolicyEpoch = capsule.PolicyEpoch
	}
	if expectation.Continuity.PolicyHash == "" {
		expectation.Continuity.PolicyHash = capsule.PolicyHash
	}
	if expectation.Continuity.OrgGenomeHash == "" {
		expectation.Continuity.OrgGenomeHash = capsule.OrgGenomeHash
	}
	if ok && expectation.Continuity.MinHazardSequence < latest.HazardSequence {
		expectation.Continuity.MinHazardSequence = latest.HazardSequence
	}
	if ok && expectation.Continuity.LatestAcceptedCheckpointHash == "" {
		expectation.Continuity.LatestAcceptedCheckpointHash = latest.CheckpointHash
	}
	if expectation.Continuity.MaxClockSkew == 0 {
		expectation.Continuity.MaxClockSkew = c.maxClockSkew
	}
	expectation.Continuity.RequireDeadManActive = expectation.Continuity.RequireDeadManActive || c.requireDeadManActive

	if expectation.Capsule.Now.IsZero() {
		expectation.Capsule.Now = now
	}
	if expectation.Capsule.HazardCode == "" {
		expectation.Capsule.HazardCode = req.Signal.HazardCode
	}
	if expectation.Capsule.State == "" {
		expectation.Capsule.State = contracts.SafeDepDegradedNarrowing
	}
	if expectation.Capsule.OrgGenomeHash == "" {
		expectation.Capsule.OrgGenomeHash = capsule.OrgGenomeHash
	}
	if expectation.Capsule.PolicyEpoch == 0 {
		expectation.Capsule.PolicyEpoch = capsule.PolicyEpoch
	}
	if expectation.Capsule.PolicyHash == "" {
		expectation.Capsule.PolicyHash = capsule.PolicyHash
	}
	if expectation.Capsule.P0CeilingsHash == "" {
		expectation.Capsule.P0CeilingsHash = capsule.P0CeilingsHash
	}
	if expectation.Capsule.P1BundleHash == "" {
		expectation.Capsule.P1BundleHash = capsule.P1BundleHash
	}
	if expectation.Capsule.CPIHash == "" {
		expectation.Capsule.CPIHash = capsule.CPIHash
	}
	if expectation.Capsule.ProviderRegistryHash == "" {
		expectation.Capsule.ProviderRegistryHash = capsule.ProviderRegistryHash
	}
	if expectation.Capsule.CredentialRegistryHash == "" {
		expectation.Capsule.CredentialRegistryHash = capsule.CredentialRegistryHash
	}
	if expectation.Capsule.VerifierProfileHash == "" {
		expectation.Capsule.VerifierProfileHash = capsule.VerifierProfileHash
	}
	if expectation.Capsule.MaxTTL == 0 {
		expectation.Capsule.MaxTTL = c.defaultMaxTTL
	}
	expectation.Capsule.RequireTransparency = expectation.Capsule.RequireTransparency || c.requireTransparency

	if expectation.Ceremony.Now.IsZero() {
		expectation.Ceremony.Now = now
	}
	if expectation.Ceremony.RequiredQuorum == 0 {
		expectation.Ceremony.RequiredQuorum = c.defaultQuorum
	}
	if expectation.Ceremony.PolicyEpoch == 0 {
		expectation.Ceremony.PolicyEpoch = capsule.PolicyEpoch
	}
	expectation.Ceremony.RequireHardwareBound = expectation.Ceremony.RequireHardwareBound || c.requireHardwareBound
	expectation.Ceremony.RequireDistinctRoles = expectation.Ceremony.RequireDistinctRoles || c.requireDistinctRoles

	if expectation.Attestation.Now.IsZero() {
		expectation.Attestation.Now = now
	}
	if expectation.Attestation.ProfileID == "" {
		expectation.Attestation.ProfileID = capsule.Attestation.ProfileID
	}
	if expectation.Attestation.PolicyHash == "" {
		expectation.Attestation.PolicyHash = capsule.Attestation.PolicyHash
	}
	if expectation.Attestation.Nonce == "" {
		expectation.Attestation.Nonce = capsule.Attestation.Nonce
	}
	if expectation.Attestation.MeasurementHash == "" {
		expectation.Attestation.MeasurementHash = capsule.Attestation.MeasurementHash
	}
	return expectation, nil
}

func (c *Controller) attachEvidence(ctx context.Context, result *GateResult, eventType string, checkpoint *contracts.ContinuityCheckpoint, capsule *contracts.EmergencyCapsule) {
	refs, _ := c.record(ctx, EvidenceEvent{
		Type:           eventType,
		Classification: result.Classification,
		Checkpoint:     checkpoint,
		ReasonCode:     result.ReasonCode,
		Reason:         result.Reason,
		OccurredAt:     c.now(),
	})
	if capsule != nil {
		_ = capsule
	}
	result.ProofGraphRef = refs.ProofGraphRef
	result.EvidencePackRef = refs.EvidencePackRef
}

func (c *Controller) record(ctx context.Context, event EvidenceEvent) (EvidenceRefs, error) {
	if c.evidence == nil {
		return EvidenceRefs{}, nil
	}
	return c.evidence.RecordSafeDepEvent(ctx, event)
}

func (c *Controller) now() time.Time {
	if c == nil || c.clock == nil {
		return time.Now().UTC()
	}
	return c.clock().UTC()
}

func IsInspectionAction(action string, toolName string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	toolName = strings.ToLower(strings.TrimSpace(toolName))
	for _, value := range []string{action, toolName} {
		if value == "" {
			continue
		}
		if strings.Contains(value, "inspect") || strings.Contains(value, "export") || strings.Contains(value, "read") || strings.Contains(value, "status") || strings.Contains(value, "list") {
			return true
		}
	}
	return false
}

func SignalFromContext(ctx map[string]any) Signal {
	if len(ctx) == 0 {
		return Signal{}
	}
	raw := firstString(ctx, "safe_deprecation_hazard_code", "safedep_hazard_code", "hazard_code")
	if raw == "" {
		if nested, ok := ctx["safe_deprecation"].(map[string]any); ok {
			return SignalFromContext(nested)
		}
		return Signal{}
	}
	return Signal{
		HazardCode:   contracts.SafeDepHazardCode(raw),
		LaneID:       firstString(ctx, "safe_deprecation_lane_id", "safedep_lane_id", "lane_id"),
		ConnectorID:  firstString(ctx, "safe_deprecation_connector_id", "safedep_connector_id", "connector_id"),
		ActiveClock:  firstBool(ctx, "safe_deprecation_active_clock", "safedep_active_clock", "active_clock", "dead_man_active"),
		HighRiskLane: firstBool(ctx, "safe_deprecation_high_risk_lane", "safedep_high_risk_lane", "high_risk_lane"),
		Reason:       firstString(ctx, "safe_deprecation_reason", "safedep_reason", "reason"),
	}
}

func GateRequestFromContext(ctx map[string]any) GateRequest {
	if len(ctx) == 0 {
		return GateRequest{}
	}
	if req, ok := ctx["safe_deprecation_gate_request"].(GateRequest); ok {
		return req
	}
	req := GateRequest{Signal: SignalFromContext(ctx)}
	if cp, ok := ctx["safe_deprecation_checkpoint"].(contracts.ContinuityCheckpoint); ok {
		req.Checkpoint = cp
	}
	if capsule, ok := ctx["safe_deprecation_capsule"].(contracts.EmergencyCapsule); ok {
		req.Capsule = &capsule
	}
	if capsule, ok := ctx["safe_deprecation_capsule"].(*contracts.EmergencyCapsule); ok {
		req.Capsule = capsule
	}
	if posture, ok := ctx["safe_deprecation_dev_fallback_posture"].(contracts.DevFallbackPosture); ok {
		req.DevFallbackPosture = posture
	}
	if expectation, ok := ctx["safe_deprecation_expectation"].(ActivationExpectation); ok {
		req.Expectation = expectation
	}
	if inspection, ok := ctx["safe_deprecation_inspection_only"].(bool); ok {
		req.InspectionOnly = inspection
	}
	return req
}

func firstString(ctx map[string]any, keys ...string) string {
	for _, key := range keys {
		switch v := ctx[key].(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		case fmt.Stringer:
			if strings.TrimSpace(v.String()) != "" {
				return strings.TrimSpace(v.String())
			}
		}
	}
	return ""
}

func firstBool(ctx map[string]any, keys ...string) bool {
	for _, key := range keys {
		switch v := ctx[key].(type) {
		case bool:
			return v
		case string:
			return strings.EqualFold(strings.TrimSpace(v), "true")
		}
	}
	return false
}

func validateCapsuleScope(capsule contracts.EmergencyCapsule, req GateRequest) error {
	action := strings.TrimSpace(req.Action)
	if action == "" {
		action = strings.TrimSpace(req.EffectType)
	}
	if action == "" {
		action = strings.TrimSpace(req.ToolName)
	}
	if len(capsule.AllowedActions) == 0 {
		return fmt.Errorf("%w: capsule has no predeclared allowed actions", ErrEmergencyCapsuleInvalid)
	}
	if !containsString(capsule.AllowedActions, action) {
		return fmt.Errorf("%w: action %q is outside capsule scope", ErrEmergencyCapsuleInvalid, action)
	}
	connector := strings.TrimSpace(req.ConnectorID)
	if connector == "" {
		connector = strings.TrimSpace(req.ToolName)
	}
	if len(capsule.AllowedConnectors) > 0 && connector != "" && !containsString(capsule.AllowedConnectors, connector) {
		return fmt.Errorf("%w: connector %q is outside capsule scope", ErrEmergencyCapsuleInvalid, connector)
	}
	if len(capsule.Delegation.Scope) > 0 && !containsString(capsule.Delegation.Scope, action) {
		return fmt.Errorf("%w: delegation scope does not cover action %q", ErrEmergencyCapsuleInvalid, action)
	}
	return nil
}

func containsString(values []string, needle string) bool {
	needle = strings.TrimSpace(needle)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), needle) {
			return true
		}
	}
	return false
}

func firstScopeHash(chain contracts.EmergencyDelegationChain) string {
	for _, hop := range chain.Hops {
		if strings.TrimSpace(hop.ScopeHash) != "" {
			return strings.TrimSpace(hop.ScopeHash)
		}
	}
	return ""
}

func activationID(capsule contracts.EmergencyCapsule, checkpoint contracts.ContinuityCheckpoint) string {
	payload, err := canonicalize.JCS(map[string]any{
		"capsule_id":      capsule.CapsuleID,
		"checkpoint_id":   checkpoint.CheckpointID,
		"hazard_sequence": checkpoint.HazardSequence,
		"policy_epoch":    capsule.PolicyEpoch,
	})
	if err != nil {
		return "safedep-act-" + capsule.CapsuleID + "-" + checkpoint.CheckpointID
	}
	hash := canonicalize.HashBytes(payload)
	return "safedep-act-" + strings.TrimPrefix(hash, "sha256:")[:16]
}

type HashEvidenceSink struct{}

func (HashEvidenceSink) RecordSafeDepEvent(ctx context.Context, event EvidenceEvent) (EvidenceRefs, error) {
	if err := ctx.Err(); err != nil {
		return EvidenceRefs{}, err
	}
	data, err := canonicalize.JCS(event)
	if err != nil {
		return EvidenceRefs{}, err
	}
	hash := canonicalize.HashBytes(data)
	return EvidenceRefs{
		ProofGraphRef:   "proofgraph:" + hash,
		EvidencePackRef: "evidencepack:" + hash,
	}, nil
}

type MemoryContinuityStore struct {
	mu          sync.Mutex
	checkpoints []ContinuityState
	nonces      map[string]struct{}
	activations map[string]contracts.ActivationReceipt
}

func NewMemoryContinuityStore() *MemoryContinuityStore {
	return &MemoryContinuityStore{
		nonces:      make(map[string]struct{}),
		activations: make(map[string]contracts.ActivationReceipt),
	}
}

func (s *MemoryContinuityStore) Latest(context.Context) (ContinuityState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.checkpoints) == 0 {
		return ContinuityState{}, false, nil
	}
	return s.checkpoints[len(s.checkpoints)-1], true, nil
}

func (s *MemoryContinuityStore) AppendCheckpoint(_ context.Context, checkpoint contracts.ContinuityCheckpoint) (ContinuityState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if checkpoint.Nonce == "" {
		return ContinuityState{}, fmt.Errorf("%w: checkpoint nonce is required", ErrContinuityStale)
	}
	if _, ok := s.nonces[checkpoint.Nonce]; ok {
		return ContinuityState{}, fmt.Errorf("%w: nonce replay", ErrContinuityStale)
	}
	if len(s.checkpoints) > 0 {
		latest := s.checkpoints[len(s.checkpoints)-1]
		if checkpoint.HazardSequence <= latest.HazardSequence {
			return ContinuityState{}, fmt.Errorf("%w: hazard sequence rollback", ErrContinuityStale)
		}
		if checkpoint.LatestAcceptedCheckpointHash != "" && checkpoint.LatestAcceptedCheckpointHash != latest.CheckpointHash {
			return ContinuityState{}, fmt.Errorf("%w: latest checkpoint hash mismatch", ErrContinuityStale)
		}
	}
	hash, err := CheckpointHash(checkpoint)
	if err != nil {
		return ContinuityState{}, err
	}
	state := ContinuityState{
		CheckpointID:    checkpoint.CheckpointID,
		CheckpointHash:  hash,
		HazardSequence:  checkpoint.HazardSequence,
		PolicyEpoch:     checkpoint.PolicyEpoch,
		LamportClock:    checkpoint.LamportClock,
		DeadManWindowID: checkpoint.DeadManWindowID,
	}
	s.nonces[checkpoint.Nonce] = struct{}{}
	s.checkpoints = append(s.checkpoints, state)
	return state, nil
}

func (s *MemoryContinuityStore) StoreActivation(_ context.Context, receipt contracts.ActivationReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if receipt.ActivationID == "" {
		return fmt.Errorf("safe dep: activation id is required")
	}
	s.activations[receipt.ActivationID] = receipt
	return nil
}

func (s *MemoryContinuityStore) GetActivation(_ context.Context, activationID string) (contracts.ActivationReceipt, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, ok := s.activations[activationID]
	return receipt, ok, nil
}

func (s *MemoryContinuityStore) CloseActivation(_ context.Context, activationID string, _ contracts.ContinuityCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, ok := s.activations[activationID]
	if !ok {
		return fmt.Errorf("safe dep: activation %q not found", activationID)
	}
	receipt.ExpiresAt = time.Now().UTC()
	s.activations[activationID] = receipt
	return nil
}

func CheckpointHash(checkpoint contracts.ContinuityCheckpoint) (string, error) {
	cp := checkpoint
	cp.Signature = ""
	data, err := canonicalize.JCS(cp)
	if err != nil {
		return "", err
	}
	return canonicalize.HashBytes(data), nil
}
