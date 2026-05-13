// Package iatp implements the Inter-Agent Trust Protocol handshake for HELM.
//
// IATP composes three previously-shipped HELM primitives into a single
// agent-to-agent capability exchange:
//
//  1. W3C DID — portable identifiers backed by core/pkg/identity/did/.
//  2. W3C Verifiable Credential — capability claims signed by a HELM issuer.
//  3. AITH Continuous Delegation — time-bound, revocable scoped delegations.
//
// Handshake flow (Agent A initiates with Agent B):
//
//	A -> B : Presentation { DID_A, VC_A, Delegation_A, nonce, timestamp }
//	B verifies (DID_A resolvable) ∧ (VC_A signed by trusted issuer DID) ∧
//	         (Delegation_A active, scope covers Request) ∧ (nonce fresh)
//	B -> A : Capability { session_id, granted_scope, B_signature_over_pres }
//	A verifies (B_signature is from DID_B's assertion key)
//
// Both sides emit IATP receipts citing the DIDs as `subject` and
// `counterparty`. The receipts are returned to the caller; persistence is
// the caller's responsibility (kernel proofgraph, file store, etc.).
//
// Invariants:
//   - Handshake nonce is 32 cryptographically-random bytes (hex).
//   - Each presentation's VC must be signed by a trusted issuer DID.
//   - Granted scope is the intersection of requested scope and the
//     delegation's active scope.
//   - Counter-signature binds session_id + DID_A + DID_B + scope hash.
//   - Verification is fully offline once DID Documents are cached.
package iatp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/identity"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/identity/did"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/vcredentials"
)

// nonceBytes is the size of the handshake nonce in random bytes.
const nonceBytes = 32

// defaultPresentationTTL bounds replay protection on the initial offer.
const defaultPresentationTTL = 30 * time.Second

// defaultSessionTTL bounds the granted capability's lifetime.
const defaultSessionTTL = 1 * time.Hour

// Presentation is the wire form of agent A's opening offer to agent B.
type Presentation struct {
	PresentationID string                             `json:"presentation_id"`
	HolderDID      string                             `json:"holder_did"`
	Counterparty   string                             `json:"counterparty"`
	Credential     *vcredentials.VerifiableCredential `json:"credential"`
	Delegation     *identity.ContinuousDelegation     `json:"delegation"`
	RequestedScope []string                           `json:"requested_scope"`
	Nonce          string                             `json:"nonce"` // hex of nonceBytes
	Timestamp      time.Time                          `json:"timestamp"`
	TTL            time.Duration                      `json:"ttl"`
}

// Capability is the counter-signed session token agent B returns to agent A.
type Capability struct {
	SessionID      string    `json:"session_id"`
	HolderDID      string    `json:"holder_did"` // DID_A
	IssuerDID      string    `json:"issuer_did"` // DID_B (the counter-signer)
	GrantedScope   []string  `json:"granted_scope"`
	ScopeHash      string    `json:"scope_hash"`
	PresentationID string    `json:"presentation_id"`
	Nonce          string    `json:"nonce"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Signature      string    `json:"signature"` // hex Ed25519 over canonical capability bytes
}

// Receipt is the audit-log entry both sides emit after a successful handshake.
// It cites the DIDs as `subject` and `counterparty` so receipts can be joined
// with proofgraph nodes by DID.
type Receipt struct {
	ReceiptID    string    `json:"receipt_id"`
	Direction    string    `json:"direction"` // "outgoing" or "incoming"
	Subject      string    `json:"subject"`
	Counterparty string    `json:"counterparty"`
	SessionID    string    `json:"session_id"`
	ScopeHash    string    `json:"scope_hash"`
	IssuedAt     time.Time `json:"issued_at"`
}

// Participant runs the local end of an IATP handshake. A Participant is an
// in-memory object; it does not persist sessions or receipts on its own.
type Participant struct {
	did      string
	signer   crypto.Signer
	resolver *did.Resolver
	verifier *did.Verifier
	cdm      *identity.ContinuousDelegationManager
	clock    func() time.Time

	usedNonces *nonceCache
}

// Option configures a Participant.
type Option func(*Participant)

// WithClock injects a deterministic clock for testing.
func WithClock(clock func() time.Time) Option {
	return func(p *Participant) { p.clock = clock }
}

// WithDelegationManager wires the participant to a continuous-delegation
// manager. Optional: useful when the participant needs to mint a delegation
// before issuing a Presentation.
func WithDelegationManager(cdm *identity.ContinuousDelegationManager) Option {
	return func(p *Participant) { p.cdm = cdm }
}

// NewParticipant constructs a Participant bound to a DID, a signer for that
// DID's assertion key, a DID resolver, and a DID-aware VC verifier.
func NewParticipant(holderDID string, signer crypto.Signer, resolver *did.Resolver, verifier *did.Verifier, opts ...Option) (*Participant, error) {
	if holderDID == "" {
		return nil, errors.New("iatp: holder DID required")
	}
	if signer == nil {
		return nil, errors.New("iatp: signer required")
	}
	if resolver == nil {
		return nil, errors.New("iatp: DID resolver required")
	}
	if verifier == nil {
		return nil, errors.New("iatp: DID verifier required")
	}
	p := &Participant{
		did:        holderDID,
		signer:     signer,
		resolver:   resolver,
		verifier:   verifier,
		clock:      time.Now,
		usedNonces: newNonceCache(),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// DID returns the participant's DID.
func (p *Participant) DID() string { return p.did }

// Offer builds the opening Presentation for a handshake against counterpartyDID.
// vc is the agent's W3C Verifiable Credential, delegation is its active AITH
// continuous delegation, and requestedScope is the subset of scope the agent
// wants to exercise on this session.
func (p *Participant) Offer(
	counterpartyDID string,
	vc *vcredentials.VerifiableCredential,
	delegation *identity.ContinuousDelegation,
	requestedScope []string,
) (*Presentation, *Receipt, error) {
	if counterpartyDID == "" {
		return nil, nil, errors.New("iatp: counterparty DID required")
	}
	if vc == nil {
		return nil, nil, errors.New("iatp: verifiable credential required")
	}
	if delegation == nil {
		return nil, nil, errors.New("iatp: continuous delegation required")
	}
	if len(requestedScope) == 0 {
		return nil, nil, errors.New("iatp: requested scope must contain at least one entry")
	}

	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("iatp: nonce generation failed: %w", err)
	}

	now := p.clock()
	pres := &Presentation{
		PresentationID: "iatp-pres:" + uuid.NewString()[:8],
		HolderDID:      p.did,
		Counterparty:   counterpartyDID,
		Credential:     vc,
		Delegation:     delegation,
		RequestedScope: append([]string(nil), requestedScope...),
		Nonce:          hex.EncodeToString(nonce),
		Timestamp:      now,
		TTL:            defaultPresentationTTL,
	}

	rcpt := &Receipt{
		ReceiptID:    "iatp-rcpt:" + uuid.NewString()[:8],
		Direction:    "outgoing",
		Subject:      p.did,
		Counterparty: counterpartyDID,
		SessionID:    "",
		ScopeHash:    hashScope(pres.RequestedScope),
		IssuedAt:     now,
	}
	return pres, rcpt, nil
}

// Accept verifies a Presentation from agent A, counter-signs a Capability,
// and returns it together with an incoming receipt. Steps performed:
//
//  1. Presentation TTL not exceeded.
//  2. Holder DID resolves and the credential subject DID matches.
//  3. Issuer DID of the VC resolves; the VC signature verifies.
//  4. Delegation is active (TTL not elapsed, not revoked) and its grantee
//     matches the holder DID.
//  5. Requested scope is contained in the delegation's scope.
//  6. Nonce has not been seen before by this participant.
//
// On success, B counter-signs a Capability binding session_id + holder_did +
// issuer_did + scope_hash + nonce.
func (p *Participant) Accept(ctx context.Context, pres *Presentation) (*Capability, *Receipt, error) {
	if pres == nil {
		return nil, nil, errors.New("iatp: nil presentation")
	}
	if pres.HolderDID == "" {
		return nil, nil, errors.New("iatp: presentation missing holder DID")
	}
	if pres.Counterparty != "" && pres.Counterparty != p.did {
		return nil, nil, fmt.Errorf("iatp: presentation counterparty %q does not match local DID %q", pres.Counterparty, p.did)
	}

	now := p.clock()
	if pres.TTL > 0 && now.After(pres.Timestamp.Add(pres.TTL)) {
		return nil, nil, fmt.Errorf("iatp: presentation %s expired at %s", pres.PresentationID, pres.Timestamp.Add(pres.TTL).Format(time.RFC3339))
	}

	// 1. Holder DID resolves.
	if _, err := p.resolver.Resolve(ctx, pres.HolderDID); err != nil {
		return nil, nil, fmt.Errorf("iatp: resolving holder DID: %w", err)
	}

	// 2. Credential present and subject matches the holder.
	if pres.Credential == nil {
		return nil, nil, errors.New("iatp: presentation missing verifiable credential")
	}
	if pres.Credential.CredentialSubject.ID != pres.HolderDID {
		return nil, nil, fmt.Errorf("iatp: credential subject %q does not match holder DID %q",
			pres.Credential.CredentialSubject.ID, pres.HolderDID)
	}
	if err := p.verifier.VerifyVC(ctx, pres.Credential); err != nil {
		return nil, nil, fmt.Errorf("iatp: VC verification failed: %w", err)
	}

	// 3. Continuous delegation is present, active, and bound to the holder.
	if pres.Delegation == nil {
		return nil, nil, errors.New("iatp: presentation missing continuous delegation")
	}
	if pres.Delegation.GranteeID != pres.HolderDID {
		return nil, nil, fmt.Errorf("iatp: delegation grantee %q does not match holder DID %q",
			pres.Delegation.GranteeID, pres.HolderDID)
	}
	if !delegationActive(pres.Delegation, now) {
		return nil, nil, fmt.Errorf("iatp: delegation %s is not active", pres.Delegation.ID)
	}

	// 4. Requested scope must be contained in delegation scope.
	delegScope := make(map[string]struct{}, len(pres.Delegation.Scope))
	for _, s := range pres.Delegation.Scope {
		delegScope[s] = struct{}{}
	}
	granted := make([]string, 0, len(pres.RequestedScope))
	for _, s := range pres.RequestedScope {
		if _, ok := delegScope[s]; !ok {
			return nil, nil, fmt.Errorf("iatp: requested scope %q not covered by delegation", s)
		}
		granted = append(granted, s)
	}

	// 5. Nonce freshness.
	if !p.usedNonces.consume(pres.Nonce, now.Add(2*pres.TTL)) {
		return nil, nil, fmt.Errorf("iatp: nonce replay detected for presentation %s", pres.PresentationID)
	}

	// 6. Build & sign the capability.
	scopeHash := hashScope(granted)
	cap := &Capability{
		SessionID:      "iatp-sess:" + uuid.NewString()[:8],
		HolderDID:      pres.HolderDID,
		IssuerDID:      p.did,
		GrantedScope:   granted,
		ScopeHash:      scopeHash,
		PresentationID: pres.PresentationID,
		Nonce:          pres.Nonce,
		IssuedAt:       now,
		ExpiresAt:      now.Add(defaultSessionTTL),
	}
	canonical, err := canonicalCapabilityBytes(cap)
	if err != nil {
		return nil, nil, fmt.Errorf("iatp: canonicalize capability: %w", err)
	}
	sig, err := p.signer.Sign(canonical)
	if err != nil {
		return nil, nil, fmt.Errorf("iatp: signing capability: %w", err)
	}
	cap.Signature = sig

	rcpt := &Receipt{
		ReceiptID:    "iatp-rcpt:" + uuid.NewString()[:8],
		Direction:    "incoming",
		Subject:      p.did,
		Counterparty: pres.HolderDID,
		SessionID:    cap.SessionID,
		ScopeHash:    scopeHash,
		IssuedAt:     now,
	}
	return cap, rcpt, nil
}

// VerifyCapability is the offline verification path. Agent A calls this on
// the Capability it received from B to confirm the counter-signature is
// valid against B's resolved DID Document.
func (p *Participant) VerifyCapability(ctx context.Context, cap *Capability) error {
	if cap == nil {
		return errors.New("iatp: nil capability")
	}
	if cap.IssuerDID == "" {
		return errors.New("iatp: capability missing issuer DID")
	}
	if cap.HolderDID != p.did {
		return fmt.Errorf("iatp: capability holder %q does not match local DID %q", cap.HolderDID, p.did)
	}
	if cap.Signature == "" {
		return errors.New("iatp: capability missing signature")
	}

	doc, err := p.resolver.Resolve(ctx, cap.IssuerDID)
	if err != nil {
		return fmt.Errorf("iatp: resolving issuer DID: %w", err)
	}
	pub, err := doc.PrimaryAssertionKey()
	if err != nil {
		return fmt.Errorf("iatp: extracting issuer assertion key: %w", err)
	}

	canonical, err := canonicalCapabilityBytes(cap)
	if err != nil {
		return fmt.Errorf("iatp: canonicalize capability: %w", err)
	}
	pubHex := hex.EncodeToString(pub)
	ok, err := crypto.Verify(pubHex, cap.Signature, canonical)
	if err != nil {
		return fmt.Errorf("iatp: verify signature: %w", err)
	}
	if !ok {
		return errors.New("iatp: capability signature invalid")
	}
	if !cap.ExpiresAt.IsZero() && p.clock().After(cap.ExpiresAt) {
		return fmt.Errorf("iatp: capability expired at %s", cap.ExpiresAt.Format(time.RFC3339))
	}
	if cap.ScopeHash != hashScope(cap.GrantedScope) {
		return errors.New("iatp: capability scope hash does not match granted scope")
	}
	return nil
}

// canonicalCapabilityBytes returns the deterministic bytes used as the
// signing input. It excludes the Signature field so the same payload can be
// re-derived on the verifying side.
func canonicalCapabilityBytes(cap *Capability) ([]byte, error) {
	scope := append([]string(nil), cap.GrantedScope...)
	sort.Strings(scope)

	signable := struct {
		SessionID      string    `json:"session_id"`
		HolderDID      string    `json:"holder_did"`
		IssuerDID      string    `json:"issuer_did"`
		GrantedScope   []string  `json:"granted_scope"`
		ScopeHash      string    `json:"scope_hash"`
		PresentationID string    `json:"presentation_id"`
		Nonce          string    `json:"nonce"`
		IssuedAt       time.Time `json:"issued_at"`
		ExpiresAt      time.Time `json:"expires_at"`
	}{
		SessionID:      cap.SessionID,
		HolderDID:      cap.HolderDID,
		IssuerDID:      cap.IssuerDID,
		GrantedScope:   scope,
		ScopeHash:      cap.ScopeHash,
		PresentationID: cap.PresentationID,
		Nonce:          cap.Nonce,
		IssuedAt:       cap.IssuedAt.UTC(),
		ExpiresAt:      cap.ExpiresAt.UTC(),
	}
	return json.Marshal(signable)
}

// hashScope returns a deterministic SHA-256 over a sorted scope slice.
func hashScope(scope []string) string {
	sorted := append([]string(nil), scope...)
	sort.Strings(sorted)
	data, _ := json.Marshal(sorted)
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// delegationActive checks the AITH semantics: not revoked and within TTL of
// the most recent refresh.
func delegationActive(d *identity.ContinuousDelegation, now time.Time) bool {
	if d == nil {
		return false
	}
	if d.RevokedAt != nil {
		return false
	}
	if d.TTL <= 0 {
		return false
	}
	return !now.After(d.RefreshedAt.Add(d.TTL))
}
