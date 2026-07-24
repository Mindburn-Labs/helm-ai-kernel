package generatedspecapprovalceremony

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapproval"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// memoryStore is intentionally unexported and process-local. It exists solely
// for unit tests; it is not a durable-store substitute.
type memoryStore struct {
	mu                   sync.Mutex
	records              map[recordKey]Record
	maxChallengeLifetime time.Duration
}

type recordKey struct {
	tenantID    string
	workspaceID string
	approvalID  string
}

func newMemoryStore(maxChallengeLifetime time.Duration) *memoryStore {
	return &memoryStore{records: make(map[recordKey]Record), maxChallengeLifetime: maxChallengeLifetime}
}

func (s *memoryStore) CreateHold(ctx context.Context, record Record) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if record.State != StateHoldPending {
		return Record{}, ErrTransitionConflict
	}
	if err := record.validate(); err != nil {
		return Record{}, err
	}
	key := keyFor(record.TenantID, record.WorkspaceID, record.ApprovalID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[key]; exists {
		return Record{}, ErrTransitionConflict
	}
	s.records[key] = cloneRecord(record)
	return cloneRecord(record), nil
}

func (s *memoryStore) Get(ctx context.Context, tenantID, workspaceID, approvalID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[keyFor(tenantID, workspaceID, approvalID)]
	if !ok {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

func (s *memoryStore) IssueChallenge(ctx context.Context, tenantID, workspaceID, approvalID string, challenge contracts.GeneratedSpecApprovalChallenge, issuedAt time.Time) (Record, error) {
	return s.update(ctx, tenantID, workspaceID, approvalID, func(record *Record) error {
		if record.State != StateHoldPending || !issuedAt.Equal(challenge.IssuedAt) {
			return ErrTransitionConflict
		}
		record.State = StateChallengeIssued
		record.Challenge = &challenge
		expiresAt := challenge.ExpiresAt
		record.ExpiresAt = &expiresAt
		record.UpdatedAt = issuedAt
		return nil
	})
}

func (s *memoryStore) RecordQuorum(ctx context.Context, tenantID, workspaceID, approvalID string, assertions []contracts.GeneratedSpecApprovalAssertion, verifiedAt time.Time) (Record, error) {
	return s.update(ctx, tenantID, workspaceID, approvalID, func(record *Record) error {
		if record.State != StateChallengeIssued || record.Challenge == nil || len(assertions) < record.Binding.Quorum || !verifiedAt.Before(record.Challenge.ExpiresAt) {
			return ErrTransitionConflict
		}
		record.State = StateQuorumVerified
		record.Assertions = append([]contracts.GeneratedSpecApprovalAssertion(nil), assertions...)
		at := verifiedAt
		record.QuorumVerifiedAt = &at
		record.UpdatedAt = verifiedAt
		return nil
	})
}

func (s *memoryStore) IssueGrant(ctx context.Context, tenantID, workspaceID, approvalID string, signed generatedspecapproval.SignedGrant, verifier GrantSignatureVerifier, issuedAt time.Time) (Record, error) {
	return s.update(ctx, tenantID, workspaceID, approvalID, func(record *Record) error {
		if verifier == nil || record.State != StateQuorumVerified || record.Challenge == nil || record.QuorumVerifiedAt == nil || !issuedAt.Equal(signed.Grant.IssuedAt) || !issuedAt.Before(signed.Grant.ExpiresAt) {
			return ErrTransitionConflict
		}
		if err := verifier.VerifyGrant(signed, issuedAt); err != nil {
			return err
		}
		record.State = StateGrantIssued
		record.SignedGrant = cloneSignedGrant(&signed)
		expiresAt := signed.Grant.ExpiresAt
		record.ExpiresAt = &expiresAt
		record.UpdatedAt = issuedAt
		return nil
	})
}

func (s *memoryStore) ConsumeGrant(ctx context.Context, tenantID, workspaceID, approvalID, grantID, grantHash, nonce, consumedBy, audience string, verifier GrantSignatureVerifier, consumedAt time.Time, seal ConsumptionSealer) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if seal == nil || verifier == nil {
		return Record{}, ErrTransitionConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := keyFor(tenantID, workspaceID, approvalID)
	record, ok := s.records[key]
	if !ok {
		return Record{}, ErrNotFound
	}
	if err := record.validate(); err != nil {
		return Record{}, err
	}
	if record.State != StateGrantIssued || record.SignedGrant == nil || record.SignedGrant.Grant.GrantID != grantID || record.SignedGrant.Grant.GrantHash != grantHash || record.SignedGrant.Grant.Nonce != nonce || record.SignedGrant.Grant.TenantID != tenantID || record.SignedGrant.Grant.WorkspaceID != workspaceID {
		return Record{}, ErrTransitionConflict
	}
	if record.SignedGrant.Grant.Audience != audience {
		return Record{}, fmt.Errorf("%w: signed grant workload scope mismatch", ErrConsumerUnavailable)
	}
	if err := ensureGrantActive(record.SignedGrant.Grant, consumedAt); err != nil {
		return Record{}, err
	}
	if err := verifier.VerifyGrant(*record.SignedGrant, consumedAt); err != nil {
		return Record{}, err
	}
	signedConsumption, err := seal(*cloneSignedGrant(record.SignedGrant), consumedBy, consumedAt)
	if err != nil {
		return Record{}, err
	}
	if err := verifier.VerifyConsumption(signedConsumption, *record.SignedGrant); err != nil {
		return Record{}, err
	}
	record.State = StateConsumed
	record.SignedConsumption = cloneSignedConsumption(&signedConsumption)
	at := consumedAt
	record.ConsumedAt = &at
	record.ConsumedBy = consumedBy
	record.UpdatedAt = consumedAt
	record.Version++
	if err := record.validate(); err != nil {
		return Record{}, err
	}
	s.records[key] = cloneRecord(record)
	return cloneRecord(record), nil
}

func (s *memoryStore) Deny(ctx context.Context, tenantID, workspaceID, approvalID string, deniedAt time.Time) (Record, error) {
	return s.update(ctx, tenantID, workspaceID, approvalID, func(record *Record) error {
		switch record.State {
		case StateHoldPending, StateChallengeIssued, StateQuorumVerified, StateGrantIssued:
		default:
			return ErrTransitionConflict
		}
		record.State = StateDenied
		record.UpdatedAt = deniedAt
		return nil
	})
}

func (s *memoryStore) Expire(ctx context.Context, tenantID, workspaceID, approvalID string, expiredAt time.Time) (Record, error) {
	return s.update(ctx, tenantID, workspaceID, approvalID, func(record *Record) error {
		switch record.State {
		case StateHoldPending:
			// A never-challenged hold commits to HoldStartedAt + MaxChallengeLifetime:
			// IssueChallenge refuses challenges past that point, so without an expiry
			// path the record would stay pending forever. Committing the deadline as
			// the record expiry keeps the terminal-state invariant intact.
			if s.maxChallengeLifetime <= 0 {
				return ErrTransitionConflict
			}
			deadline := record.HoldStartedAt.Add(s.maxChallengeLifetime)
			if expiredAt.Before(deadline) {
				return ErrTransitionConflict
			}
			record.ExpiresAt = &deadline
		case StateChallengeIssued, StateQuorumVerified, StateGrantIssued:
			if record.ExpiresAt == nil || expiredAt.Before(*record.ExpiresAt) {
				return ErrTransitionConflict
			}
		default:
			return ErrTransitionConflict
		}
		record.State = StateExpired
		record.UpdatedAt = expiredAt
		return nil
	})
}

func (s *memoryStore) update(ctx context.Context, tenantID, workspaceID, approvalID string, mutate func(*Record) error) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := keyFor(tenantID, workspaceID, approvalID)
	record, ok := s.records[key]
	if !ok {
		return Record{}, ErrNotFound
	}
	if err := mutate(&record); err != nil {
		return Record{}, err
	}
	record.Version++
	if err := record.validate(); err != nil {
		return Record{}, err
	}
	s.records[key] = cloneRecord(record)
	return cloneRecord(record), nil
}

func keyFor(tenantID, workspaceID, approvalID string) recordKey {
	return recordKey{tenantID: tenantID, workspaceID: workspaceID, approvalID: approvalID}
}

func cloneRecord(record Record) Record {
	copy := record
	if record.Challenge != nil {
		challenge := *record.Challenge
		copy.Challenge = &challenge
	}
	copy.Assertions = append([]contracts.GeneratedSpecApprovalAssertion(nil), record.Assertions...)
	copy.QuorumVerifiedAt = cloneTime(record.QuorumVerifiedAt)
	copy.SignedGrant = cloneSignedGrant(record.SignedGrant)
	copy.SignedConsumption = cloneSignedConsumption(record.SignedConsumption)
	copy.ExpiresAt = cloneTime(record.ExpiresAt)
	copy.ConsumedAt = cloneTime(record.ConsumedAt)
	return copy
}

func cloneSignedGrant(signed *generatedspecapproval.SignedGrant) *generatedspecapproval.SignedGrant {
	if signed == nil {
		return nil
	}
	copy := *signed
	copy.Grant.ApproverPrincipalIDs = append([]string(nil), signed.Grant.ApproverPrincipalIDs...)
	return &copy
}

func cloneSignedConsumption(signed *generatedspecapproval.SignedConsumption) *generatedspecapproval.SignedConsumption {
	if signed == nil {
		return nil
	}
	copy := *signed
	copy.Consumption.ApproverPrincipalIDs = append([]string(nil), signed.Consumption.ApproverPrincipalIDs...)
	return &copy
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

var _ Store = (*memoryStore)(nil)
