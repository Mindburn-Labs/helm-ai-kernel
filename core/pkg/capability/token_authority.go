package capability

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	kcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// TokenError is a typed verification/minting failure. Guardian maps every
// TokenError to DENY / CAPABILITY_TOKEN_INVALID.
type TokenError struct {
	Reason  string
	Details string
}

func (e *TokenError) Error() string {
	if e.Details == "" {
		return e.Reason
	}
	return fmt.Sprintf("%s: %s", e.Reason, e.Details)
}

// Token rejection reasons (surfaced in the decision Reason text).
const (
	TokenRejectMalformed         = "malformed"
	TokenRejectBadSignature      = "bad_signature"
	TokenRejectUnknown           = "unknown_token"
	TokenRejectNotActive         = "not_active"
	TokenRejectExpired           = "expired"
	TokenRejectExhausted         = "exhausted"
	TokenRejectRevoked           = "revoked"
	TokenRejectTaskMismatch      = "task_mismatch"
	TokenRejectManifestDrift     = "manifest_drift"
	TokenRejectArgsDigest        = "args_digest_mismatch"
	TokenRejectBoundaryCeiling   = "boundary_ceiling_exceeded"
	TokenRejectUnknownCapability = "unknown_capability"
)

// TokenStore tracks token lifecycle state. Implementations must be safe for
// concurrent use.
type TokenStore interface {
	Put(t *Token) error
	Get(tokenID string) (*Token, int, error) // token, uses consumed, error
	ConsumeUse(tokenID string) (int, error)  // new use count
	Revoke(tokenID, receiptRef string) error
}

// InMemoryTokenStore is a mutex-guarded in-process store. Preview scope:
// state does not survive restart and does not propagate across processes.
type InMemoryTokenStore struct {
	mu     sync.Mutex
	tokens map[string]*Token
	uses   map[string]int
}

// NewInMemoryTokenStore creates an empty store.
func NewInMemoryTokenStore() *InMemoryTokenStore {
	return &InMemoryTokenStore{
		tokens: make(map[string]*Token),
		uses:   make(map[string]int),
	}
}

func (s *InMemoryTokenStore) Put(t *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tokens[t.TokenID]; exists {
		return &TokenError{Reason: TokenRejectMalformed, Details: "duplicate token_id " + t.TokenID}
	}
	cp := *t
	s.tokens[t.TokenID] = &cp
	return nil
}

func (s *InMemoryTokenStore) Get(tokenID string) (*Token, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokenID]
	if !ok {
		return nil, 0, &TokenError{Reason: TokenRejectUnknown, Details: tokenID}
	}
	cp := *t
	return &cp, s.uses[tokenID], nil
}

func (s *InMemoryTokenStore) ConsumeUse(tokenID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokenID]
	if !ok {
		return 0, &TokenError{Reason: TokenRejectUnknown, Details: tokenID}
	}
	if t.Status.Terminal() {
		return s.uses[tokenID], &TokenError{Reason: string(t.Status), Details: tokenID}
	}
	s.uses[tokenID]++
	if t.Grant.MaxUses > 0 && s.uses[tokenID] >= t.Grant.MaxUses {
		t.Status = TokenStatusUsedUp
	}
	return s.uses[tokenID], nil
}

func (s *InMemoryTokenStore) Revoke(tokenID, receiptRef string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokenID]
	if !ok {
		return &TokenError{Reason: TokenRejectUnknown, Details: tokenID}
	}
	t.Status = TokenStatusRevoked
	t.RevocationReceiptRef = receiptRef
	return nil
}

// TokenAuthority mints signed tokens bound to registry manifest revisions.
//
// quantum_posture: classical Ed25519 only (matches the kernel receipt
// signing posture); no post-quantum claim.
type TokenAuthority struct {
	signer   kcrypto.Signer
	registry *Registry
	store    TokenStore
	clock    func() time.Time
}

// NewTokenAuthority creates an authority. store may be nil to use a fresh
// in-memory store; clock may be nil to use time.Now.
func NewTokenAuthority(signer kcrypto.Signer, registry *Registry, store TokenStore, clock func() time.Time) *TokenAuthority {
	if store == nil {
		store = NewInMemoryTokenStore()
	}
	if clock == nil {
		clock = time.Now
	}
	return &TokenAuthority{signer: signer, registry: registry, store: store, clock: clock}
}

// Store returns the authority's token store.
func (a *TokenAuthority) Store() TokenStore { return a.store }

// PubKeyHex returns the authority signer's public key (hex), for verifier setup.
func (a *TokenAuthority) PubKeyHex() string { return a.signer.PublicKey() }

// MintRequest describes a desired grant.
type MintRequest struct {
	TaskID       string
	Subject      TokenSubject
	CapabilityID string
	TTL          time.Duration // 0 -> DefaultTokenTTL
	MaxUses      int           // 0 -> bounded by expiry only
	Constraints  TokenConstraints
}

// Mint creates, signs, and stores a new active token. Minting against an
// unregistered capability fails closed.
func (a *TokenAuthority) Mint(req MintRequest) (*Token, error) {
	entry := a.registry.Resolve(req.CapabilityID)
	if entry == nil {
		return nil, &TokenError{Reason: TokenRejectUnknownCapability, Details: req.CapabilityID}
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	now := a.clock().UTC()
	token := &Token{
		SchemaVersion: TokenSchemaVersion,
		TokenID:       "tok_" + randomHex(16),
		TaskID:        req.TaskID,
		Subject:       req.Subject,
		CapabilityRef: TokenCapabilityRef{
			CapabilityID: entry.Manifest.CapabilityID,
			Version:      entry.Manifest.Version,
			ManifestHash: entry.Hash,
		},
		Grant: TokenGrant{
			IssuedAt:    now,
			ExpiresAt:   now.Add(ttl),
			MaxUses:     req.MaxUses,
			Constraints: req.Constraints,
		},
		Status: TokenStatusActive,
	}
	if err := token.ValidateShape(); err != nil {
		return nil, &TokenError{Reason: TokenRejectMalformed, Details: err.Error()}
	}
	if err := a.sign(token); err != nil {
		return nil, err
	}
	if err := a.store.Put(token); err != nil {
		return nil, err
	}
	return token, nil
}

func (a *TokenAuthority) sign(t *Token) error {
	payload := t.signedPayload()
	canonical, err := canonicalize.JCS(payload)
	if err != nil {
		return fmt.Errorf("canonicalize token: %w", err)
	}
	sig, err := a.signer.Sign(canonical)
	if err != nil {
		return fmt.Errorf("sign token: %w", err)
	}
	t.Signature = sig
	return nil
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := crand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

// TokenVerifier checks presented tokens against the store, registry, and
// authority public key, then records consumption.
type TokenVerifier struct {
	authorityPubHex string
	registry        *Registry
	store           TokenStore
	clock           func() time.Time
}

// NewTokenVerifier creates a verifier over the same registry/store as the
// authority. pubKeyHex is the authority's Ed25519 public key (hex).
func NewTokenVerifier(pubKeyHex string, registry *Registry, store TokenStore, clock func() time.Time) *TokenVerifier {
	if clock == nil {
		clock = time.Now
	}
	return &TokenVerifier{authorityPubHex: pubKeyHex, registry: registry, store: store, clock: clock}
}

// VerifyRequest is one presented token plus its dispatch context.
type VerifyRequest struct {
	Presented *Token
	TaskID    string
	Args      map[string]interface{} // dispatch arguments, for args_digest constraint
}

// Verify checks shape, signature, store state, task binding, manifest drift,
// and constraints. On success it consumes one use and returns the stored
// token. Every failure is a *TokenError (fail closed).
func (v *TokenVerifier) Verify(req VerifyRequest) (*Token, error) {
	t := req.Presented
	if t == nil {
		return nil, &TokenError{Reason: TokenRejectMalformed, Details: "no token presented"}
	}
	if err := t.ValidateShape(); err != nil {
		return nil, &TokenError{Reason: TokenRejectMalformed, Details: err.Error()}
	}

	// Signature over the signed payload (status/revocation/signature excluded).
	payload := t.signedPayload()
	canonical, err := canonicalize.JCS(payload)
	if err != nil {
		return nil, &TokenError{Reason: TokenRejectMalformed, Details: err.Error()}
	}
	ok, err := kcrypto.Verify(v.authorityPubHex, t.Signature, canonical)
	if err != nil || !ok {
		return nil, &TokenError{Reason: TokenRejectBadSignature, Details: t.TokenID}
	}

	stored, _, err := v.store.Get(t.TokenID)
	if err != nil {
		return nil, err
	}
	if stored.Status.Terminal() {
		return nil, &TokenError{Reason: string(stored.Status), Details: t.TokenID}
	}
	if stored.Status != TokenStatusActive {
		return nil, &TokenError{Reason: TokenRejectNotActive, Details: string(stored.Status)}
	}
	if !v.clock().UTC().Before(stored.Grant.ExpiresAt) {
		return nil, &TokenError{Reason: TokenRejectExpired, Details: t.TokenID}
	}
	if req.TaskID == "" || stored.TaskID != req.TaskID {
		return nil, &TokenError{Reason: TokenRejectTaskMismatch, Details: t.TokenID}
	}

	// Manifest drift: the registry must still serve the exact pinned revision.
	entry := v.registry.Resolve(stored.CapabilityRef.CapabilityID)
	if entry == nil {
		return nil, &TokenError{Reason: TokenRejectUnknownCapability, Details: stored.CapabilityRef.CapabilityID}
	}
	if entry.Hash != stored.CapabilityRef.ManifestHash {
		return nil, &TokenError{Reason: TokenRejectManifestDrift, Details: stored.CapabilityRef.CapabilityID}
	}

	// Constraints.
	if digest := stored.Grant.Constraints.ArgsDigest; digest != "" {
		argsDigest, err := HashArgs(req.Args)
		if err != nil {
			return nil, &TokenError{Reason: TokenRejectMalformed, Details: err.Error()}
		}
		if argsDigest != digest {
			return nil, &TokenError{Reason: TokenRejectArgsDigest, Details: t.TokenID}
		}
	}
	if ceiling := stored.Grant.Constraints.DataBoundaryCeiling; ceiling != "" {
		if boundaryRank(entry.Manifest.DataBoundary) > boundaryRank(DataBoundary(ceiling)) {
			return nil, &TokenError{Reason: TokenRejectBoundaryCeiling, Details: string(entry.Manifest.DataBoundary) + " > " + ceiling}
		}
	}

	if _, err := v.store.ConsumeUse(t.TokenID); err != nil {
		return nil, err
	}
	return stored, nil
}

// HashArgs computes the canonical sha256 digest of dispatch arguments, in the
// same sha256:<hex> form as manifest hashes.
func HashArgs(args map[string]interface{}) (string, error) {
	canonical, err := canonicalize.JCS(args)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
