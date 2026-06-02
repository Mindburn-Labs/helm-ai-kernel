package extauthz

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrPermitRejected = errors.New("extauthz permit rejected")
	ErrProofRejected  = errors.New("extauthz proof lifecycle rejected")
)

type PermitConsumer interface {
	DurableCompareAndSwap() bool
	ConsumePermit(req AuthorizationRequest, resp AuthorizationResponse, now time.Time) (*DispatchRecord, error)
}

type PermitLedger struct {
	mu      sync.Mutex
	records map[string]*DispatchRecord
}

func NewPermitLedger() *PermitLedger {
	return &PermitLedger{records: make(map[string]*DispatchRecord)}
}

func (l *PermitLedger) DurableCompareAndSwap() bool {
	return false
}

func (l *PermitLedger) ConsumePermit(req AuthorizationRequest, resp AuthorizationResponse, now time.Time) (*DispatchRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if resp.Verdict != VerdictAllow {
		return nil, fmt.Errorf("%w: non-allow permit", ErrPermitRejected)
	}
	if err := verifyDispatchBinding(req, resp); err != nil {
		return nil, err
	}
	if resp.EffectPermitRef == "" || resp.IdempotencyKeyCandidate == "" {
		return nil, fmt.Errorf("%w: missing permit or idempotency key", ErrPermitRejected)
	}
	expiry, err := time.Parse(time.RFC3339Nano, resp.PermitExpiry)
	if err != nil || !expiry.After(now) {
		return nil, fmt.Errorf("%w: stale permit", ErrPermitRejected)
	}
	if _, exists := l.records[resp.EffectPermitRef]; exists {
		return nil, fmt.Errorf("%w: duplicate permit", ErrPermitRejected)
	}
	for _, existing := range l.records {
		if existing.IdempotencyKey == resp.IdempotencyKeyCandidate {
			return nil, fmt.Errorf("%w: duplicate idempotency key", ErrPermitRejected)
		}
		if existing.PermitNonce == resp.PermitNonce {
			return nil, fmt.Errorf("%w: duplicate permit nonce", ErrPermitRejected)
		}
		if existing.KernelVerdictRef == resp.KernelVerdictRef {
			return nil, fmt.Errorf("%w: duplicate kernel verdict", ErrPermitRejected)
		}
	}
	record := &DispatchRecord{
		EffectPermitRef:           resp.EffectPermitRef,
		PermitNonce:               resp.PermitNonce,
		IdempotencyKey:            resp.IdempotencyKeyCandidate,
		KernelVerdictRef:          resp.KernelVerdictRef,
		KernelVerdictHash:         resp.KernelVerdictHash,
		ProofSessionRef:           resp.ProofSessionRef,
		EvidenceReservationRef:    resp.EvidenceReservationRef,
		BudgetReservationRef:      resp.BudgetReservationRef,
		ConnectorID:               req.ConnectorID,
		ActionURN:                 req.ActionURN,
		AuthorizedRequestBodyHash: req.RequestBodyHash,
		AuthorizedArgsC14NHash:    req.ArgsC14NHash,
		ProofState:                ProofStateAuthorized,
		ConsumedAt:                now.UTC().Format(time.RFC3339Nano),
	}
	l.records[resp.EffectPermitRef] = record
	return cloneRecord(record), nil
}

func verifyDispatchBinding(req AuthorizationRequest, resp AuthorizationResponse) error {
	if req.SchemaVersion != resp.SchemaVersion ||
		req.ContractVersion != resp.ContractVersion ||
		req.RequestID != resp.RequestID ||
		req.TenantID != resp.TenantID ||
		req.WorkspaceID != resp.WorkspaceID ||
		req.PrincipalID != resp.PrincipalID ||
		req.PrincipalSeq != resp.PrincipalSeq ||
		req.AgentIdentityProfileRef != resp.AgentIdentityProfileRef ||
		req.Protocol != resp.Protocol ||
		req.ActionURN != resp.ActionURN ||
		req.ToolURN != resp.ToolURN ||
		req.ConnectorID != resp.ConnectorID ||
		req.ConnectorContractHash != resp.ConnectorContractHash ||
		req.ExecutorKind != resp.ExecutorKind ||
		req.EffectClass != resp.EffectClass ||
		req.RiskClass != resp.RiskClass ||
		req.ArgsC14NHash != resp.ArgsC14NHash ||
		req.RequestBodyHash != resp.RequestBodyHash ||
		req.PlanHash != resp.PlanHash ||
		req.PolicyHash != resp.PolicyHash ||
		req.P0Hash != resp.P0Hash ||
		req.PolicyEpoch != resp.PolicyEpoch ||
		req.IdempotencyKeyCandidate != resp.IdempotencyKeyCandidate ||
		req.PayloadClass != resp.PayloadClass ||
		req.RedactionProfile != resp.RedactionProfile ||
		req.UpstreamTraceID != resp.UpstreamTraceID ||
		req.UpstreamRunID != resp.UpstreamRunID ||
		req.DeadlineMS != resp.DeadlineMS ||
		req.RiskContextHash != resp.RiskContextHash {
		return fmt.Errorf("%w: request response binding mismatch", ErrPermitRejected)
	}
	return nil
}

func (l *PermitLedger) RecordOutcome(permitRef, outcome, requestHash, responseHash, connectorReceipt string) (*DispatchRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	record, ok := l.records[permitRef]
	if !ok {
		return nil, fmt.Errorf("%w: unknown permit", ErrProofRejected)
	}
	if record.ProofState == ProofStateFinalized {
		return nil, fmt.Errorf("%w: finalized proof is terminal", ErrProofRejected)
	}
	if record.OutcomeRecorded {
		return nil, fmt.Errorf("%w: outcome is already recorded", ErrProofRejected)
	}
	if !isSHA256URN(requestHash) || requestHash != record.AuthorizedRequestBodyHash {
		return nil, fmt.Errorf("%w: request hash mismatch", ErrProofRejected)
	}
	if !isSHA256URN(responseHash) {
		return nil, fmt.Errorf("%w: invalid response hash", ErrProofRejected)
	}

	switch outcome {
	case EffectOutcomeSucceeded:
		if connectorReceipt == "" {
			return nil, fmt.Errorf("%w: connector receipt required for successful mutation", ErrProofRejected)
		}
		record.ProofState = ProofStatePending
		record.OutcomeRecorded = true
		record.EffectOutcome = outcome
		record.RequestHash = requestHash
		record.ResponseHash = responseHash
		record.ConnectorReceipt = connectorReceipt
	case EffectOutcomeFailed:
		record.ProofState = ProofStateEffectFailed
		record.OutcomeRecorded = true
		record.EffectOutcome = outcome
		record.RequestHash = requestHash
		record.ResponseHash = responseHash
		record.ConnectorReceipt = connectorReceipt
	default:
		return nil, fmt.Errorf("%w: unknown effect outcome", ErrProofRejected)
	}
	return cloneRecord(record), nil
}

func (l *PermitLedger) MarkProofFinalizationFailed(permitRef string) (*DispatchRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	record, ok := l.records[permitRef]
	if !ok {
		return nil, fmt.Errorf("%w: unknown permit", ErrProofRejected)
	}
	if record.ProofState == ProofStateFinalized {
		return nil, fmt.Errorf("%w: finalized proof is terminal", ErrProofRejected)
	}
	if record.ProofState != ProofStatePending {
		return nil, fmt.Errorf("%w: proof is not pending", ErrProofRejected)
	}
	record.ProofState = ProofStateFailed
	return cloneRecord(record), nil
}

func (l *PermitLedger) FinalizeProof(permitRef, evidencePackRef, effectReceiptRef, proofGraphEdgeRef string) (*DispatchRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	record, ok := l.records[permitRef]
	if !ok {
		return nil, fmt.Errorf("%w: unknown permit", ErrProofRejected)
	}
	if record.ProofState == ProofStateFinalized {
		return nil, fmt.Errorf("%w: finalized proof is terminal", ErrProofRejected)
	}
	if record.ProofState != ProofStatePending && record.ProofState != ProofStateFailed {
		return nil, fmt.Errorf("%w: proof is not pending", ErrProofRejected)
	}
	if !record.OutcomeRecorded || record.EffectOutcome != EffectOutcomeSucceeded {
		return nil, fmt.Errorf("%w: successful outcome required before proof finalization", ErrProofRejected)
	}
	if record.ConnectorReceipt == "" {
		return nil, fmt.Errorf("%w: connector receipt required before proof finalization", ErrProofRejected)
	}
	if evidencePackRef == "" || effectReceiptRef == "" || proofGraphEdgeRef == "" {
		return nil, fmt.Errorf("%w: missing proof closure references", ErrProofRejected)
	}
	record.ProofState = ProofStateFinalized
	record.EvidencePackRef = evidencePackRef
	record.EffectReceiptRef = effectReceiptRef
	record.ProofGraphEdgeRef = proofGraphEdgeRef
	return cloneRecord(record), nil
}

func (l *PermitLedger) Get(permitRef string) (*DispatchRecord, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	record, ok := l.records[permitRef]
	if !ok {
		return nil, false
	}
	return cloneRecord(record), true
}

type DispatchRecord struct {
	EffectPermitRef           string
	PermitNonce               string
	IdempotencyKey            string
	KernelVerdictRef          string
	KernelVerdictHash         string
	ProofSessionRef           string
	EvidenceReservationRef    string
	BudgetReservationRef      string
	ConnectorID               string
	ActionURN                 string
	AuthorizedRequestBodyHash string
	AuthorizedArgsC14NHash    string
	ProofState                string
	ConsumedAt                string
	OutcomeRecorded           bool
	EffectOutcome             string
	RequestHash               string
	ResponseHash              string
	ConnectorReceipt          string
	EvidencePackRef           string
	EffectReceiptRef          string
	ProofGraphEdgeRef         string
}

func cloneRecord(record *DispatchRecord) *DispatchRecord {
	if record == nil {
		return nil
	}
	copy := *record
	return &copy
}
