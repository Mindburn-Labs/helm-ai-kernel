package boundary

// quantum_posture: Approval challenges and assertions use the configured credential verifier.

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// ErrApprovalTransitionConflict means the approval changed after a caller
// reviewed its sealed ceremony hash. Callers must load the current ceremony
// and require a new review before trying again.
var ErrApprovalTransitionConflict = errors.New("approval ceremony changed")

// ErrApprovalVerificationUnavailable keeps approval assertions fail-closed:
// without a registered credential verifier an opaque assertion string must
// never transition a ceremony to allowed. Routes map this error to an RFC 7807
// problem-details 503 response.
var ErrApprovalVerificationUnavailable = errors.New("approval verification unavailable")

// ApprovalAssertionVerifier verifies a WebAuthn/passkey approval assertion
// against a registered credential before any ceremony transition. A verifier
// that cannot handle the ceremony's credential or method must return an error
// wrapping ErrApprovalVerificationUnavailable so the surface stays fail-closed
// instead of degrading into acceptance.
type ApprovalAssertionVerifier interface {
	VerifyApprovalAssertion(challenge contracts.ApprovalWebAuthnChallenge, assertion contracts.ApprovalWebAuthnAssertion) error
}

func (r *SurfaceRegistry) PutApproval(approval contracts.ApprovalCeremony) (contracts.ApprovalCeremony, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.putApprovalLocked(approval)
}

func (r *SurfaceRegistry) putApprovalLocked(approval contracts.ApprovalCeremony) (contracts.ApprovalCeremony, error) {
	sealed, err := approval.Seal()
	if err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	r.approvals[sealed.ApprovalID] = sealed
	if err := r.appendEventLocked("approval", sealed.ApprovalID, sealed); err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	return sealed, nil
}

func (r *SurfaceRegistry) ListApprovals() []contracts.ApprovalCeremony {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]contracts.ApprovalCeremony, 0, len(r.approvals))
	for _, approval := range r.approvals {
		out = append(out, approval)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ApprovalID < out[j].ApprovalID })
	return out
}

func (r *SurfaceRegistry) TransitionApproval(id string, state contracts.ApprovalCeremonyState, actor, receiptID, reason string) (contracts.ApprovalCeremony, error) {
	return r.TransitionApprovalIfCurrent(id, state, actor, receiptID, reason, "")
}

// TransitionApprovalIfCurrent transitions an approval only if its current
// sealed hash still matches the snapshot explicitly reviewed by the caller.
// An empty expected hash retains the local direct-command boundary, where the
// process owns the registry directly; HTTP callers must supply one.
func (r *SurfaceRegistry) TransitionApprovalIfCurrent(id string, state contracts.ApprovalCeremonyState, actor, receiptID, reason, expectedCeremonyHash string) (contracts.ApprovalCeremony, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.transitionApprovalLocked(id, state, actor, receiptID, reason, expectedCeremonyHash)
}

func (r *SurfaceRegistry) transitionApprovalLocked(id string, state contracts.ApprovalCeremonyState, actor, receiptID, reason, expectedCeremonyHash string) (contracts.ApprovalCeremony, error) {
	approval, ok := r.approvals[id]
	if !ok {
		return contracts.ApprovalCeremony{}, fmt.Errorf("approval %q not found", id)
	}
	if expected := strings.TrimSpace(expectedCeremonyHash); expected != "" && expected != approval.CeremonyHash {
		return contracts.ApprovalCeremony{}, fmt.Errorf("%w: approval %q has changed; refresh and review again", ErrApprovalTransitionConflict, id)
	}
	if approval.State != contracts.ApprovalCeremonyPending &&
		!(approval.State == contracts.ApprovalCeremonyAllowed && state == contracts.ApprovalCeremonyRevoked) {
		return contracts.ApprovalCeremony{}, fmt.Errorf("approval %q cannot transition from %s to %s", id, approval.State, state)
	}
	now := r.now().UTC()
	if state == contracts.ApprovalCeremonyAllowed {
		if approval.TimelockUntil.IsZero() || approval.ExpiresAt.IsZero() {
			return contracts.ApprovalCeremony{}, fmt.Errorf("approval %q requires timelock_until and expires_at", id)
		}
		if !now.Before(approval.ExpiresAt) {
			approval.State = contracts.ApprovalCeremonyExpired
			approval.UpdatedAt = now
			approval.Reason = "approval expired before assertion"
			return r.putApprovalLocked(approval)
		}
		if now.Before(approval.TimelockUntil) {
			approval.UpdatedAt = now
			approval.Reason = "approval timelock has not elapsed"
			return r.putApprovalLocked(approval)
		}
	}
	if state == contracts.ApprovalCeremonyAllowed && approval.BreakGlass && (strings.TrimSpace(reason) == "" || strings.TrimSpace(receiptID) == "") {
		return contracts.ApprovalCeremony{}, fmt.Errorf("break-glass approval requires reason and receipt_id")
	}
	// An approver identity that is merely asserted by the caller cannot
	// establish dual control. The actor arrives as a plain string — from a
	// request body on the HTTP route, or a CLI flag — and the only credential
	// behind it is the single shared admin key. One key holder could therefore
	// satisfy a 2-of-2 quorum by approving twice under two different names,
	// which is precisely the interlock that gates high-risk actions (F-08).
	//
	// There is no verified approver identity on this path: the WebAuthn variant
	// checks only that an assertion string is non-empty and never verifies it
	// against a credential. Until one exists, a multi-party quorum is refused
	// rather than faked. The correct implementation is
	// boundary/approvalverify.VerifyQuorum, which already enforces distinct
	// principal / credential / device / key and a real ed25519.Verify against
	// authority-registry-pinned keys.
	if state == contracts.ApprovalCeremonyAllowed {
		if actor != "" && actor == approval.RequestedBy {
			return contracts.ApprovalCeremony{}, fmt.Errorf(
				"approver %q is the requester of approval %q: dual control requires a distinct approver",
				actor, id)
		}
		if quorumFor(approval) > 1 {
			approval.UpdatedAt = now
			approval.State = contracts.ApprovalCeremonyPending
			approval.Reason = fmt.Sprintf(
				"approval requires a %d-party quorum, which cannot be established from an asserted actor name; "+
					"verified approver credentials are required", quorumFor(approval))
			return r.putApprovalLocked(approval)
		}
	}

	approval.State = state
	approval.UpdatedAt = now
	approval.Reason = reason
	if actor != "" {
		approval.Approvers = appendUnique(approval.Approvers, actor)
	}
	if receiptID != "" {
		approval.ReceiptID = receiptID
	}
	if state == contracts.ApprovalCeremonyAllowed {
		quorum := quorumFor(approval)
		if len(approval.Approvers) < quorum {
			approval.State = contracts.ApprovalCeremonyPending
			approval.Reason = fmt.Sprintf("approval quorum pending: %d/%d", len(approval.Approvers), quorum)
		}
	}
	return r.putApprovalLocked(approval)
}

// quorumFor normalises an unset quorum to single-approver.
func quorumFor(approval contracts.ApprovalCeremony) int {
	if approval.Quorum <= 0 {
		return 1
	}
	return approval.Quorum
}

func (r *SurfaceRegistry) CreateApprovalChallenge(approvalID, method string, ttl time.Duration) (contracts.ApprovalWebAuthnChallenge, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if strings.TrimSpace(method) == "" {
		method = "passkey"
	}
	r.mu.RLock()
	_, ok := r.approvals[approvalID]
	r.mu.RUnlock()
	if !ok {
		return contracts.ApprovalWebAuthnChallenge{}, fmt.Errorf("approval %q not found", approvalID)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return contracts.ApprovalWebAuthnChallenge{}, fmt.Errorf("generate approval challenge: %w", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw)
	hash, err := canonicalize.CanonicalHash(map[string]string{"approval_id": approvalID, "challenge": challenge, "method": method})
	if err != nil {
		return contracts.ApprovalWebAuthnChallenge{}, err
	}
	now := r.now().UTC()
	record := contracts.ApprovalWebAuthnChallenge{
		ChallengeID:   contracts.SurfaceID("challenge", approvalID+"-"+challenge[:12]),
		ApprovalID:    approvalID,
		Method:        method,
		Challenge:     challenge,
		ChallengeHash: "sha256:" + hash,
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.challenges[record.ChallengeID] = record
	if err := r.appendEventLocked("approval_challenge", record.ChallengeID, record); err != nil {
		return contracts.ApprovalWebAuthnChallenge{}, err
	}
	if err := r.persistLocked(); err != nil {
		return contracts.ApprovalWebAuthnChallenge{}, err
	}
	return record, nil
}

// SetApprovalAssertionVerifier registers the credential verifier consulted by
// AssertApprovalChallenge before any ceremony transition. Passing nil returns
// the surface to its fail-closed default, where assertions cannot transition
// ceremonies at all.
func (r *SurfaceRegistry) SetApprovalAssertionVerifier(v ApprovalAssertionVerifier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.assertionVerifier = v
}

// AssertApprovalChallenge binds a WebAuthn/passkey assertion to an approval
// ceremony. The assertion is verified against the registered credential
// verifier before any transition: with no verifier registered the surface
// fails closed with ErrApprovalVerificationUnavailable, and a rejected
// assertion never mutates the ceremony or the challenge record.
func (r *SurfaceRegistry) AssertApprovalChallenge(assertion contracts.ApprovalWebAuthnAssertion) (contracts.ApprovalCeremony, error) {
	if strings.TrimSpace(assertion.ChallengeID) == "" || strings.TrimSpace(assertion.Actor) == "" || strings.TrimSpace(assertion.Assertion) == "" {
		return contracts.ApprovalCeremony{}, fmt.Errorf("challenge_id, actor, and assertion are required")
	}
	assertionHash, err := canonicalize.CanonicalHash(map[string]string{
		"challenge_id": assertion.ChallengeID,
		"actor":        assertion.Actor,
		"assertion":    assertion.Assertion,
	})
	if err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	challenge, ok := r.challenges[assertion.ChallengeID]
	if !ok {
		return contracts.ApprovalCeremony{}, fmt.Errorf("approval challenge %q not found", assertion.ChallengeID)
	}
	if r.now().UTC().After(challenge.ExpiresAt) {
		return contracts.ApprovalCeremony{}, fmt.Errorf("approval challenge expired")
	}
	if r.assertionVerifier == nil {
		// Fail closed: an opaque assertion string must never mint approval
		// authority. Hashing the assertion is bookkeeping, not verification.
		return contracts.ApprovalCeremony{}, fmt.Errorf("cannot verify assertion for challenge %q: %w", assertion.ChallengeID, ErrApprovalVerificationUnavailable)
	}
	if err := r.assertionVerifier.VerifyApprovalAssertion(challenge, assertion); err != nil {
		if errors.Is(err, ErrApprovalVerificationUnavailable) {
			return contracts.ApprovalCeremony{}, err
		}
		return contracts.ApprovalCeremony{}, fmt.Errorf("approval assertion rejected: %w", err)
	}
	approval, err := r.transitionApprovalLocked(challenge.ApprovalID, contracts.ApprovalCeremonyAllowed, assertion.Actor, assertion.ReceiptID, assertion.Reason, "")
	if err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	approval.AuthMethod = challenge.Method
	approval.ChallengeID = challenge.ChallengeID
	approval.ChallengeHash = challenge.ChallengeHash
	approval.AssertionHash = "sha256:" + assertionHash
	sealed, err := r.putApprovalLocked(approval)
	if err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	challenge.Verified = sealed.State == contracts.ApprovalCeremonyAllowed
	challenge.AssertionHash = sealed.AssertionHash
	r.challenges[challenge.ChallengeID] = challenge
	err = r.persistLocked()
	if err != nil {
		return contracts.ApprovalCeremony{}, err
	}
	return sealed, nil
}

func (r *SurfaceRegistry) countOpenApprovalsLocked() int {
	count := 0
	for _, approval := range r.approvals {
		if approval.State == contracts.ApprovalCeremonyPending {
			count++
		}
	}
	return count
}
