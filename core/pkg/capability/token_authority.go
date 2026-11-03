package capability

import (
	"bytes"
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
	TokenRejectMalformed          = "malformed"
	TokenRejectBadSignature       = "bad_signature"
	TokenRejectUnknown            = "unknown_token"
	TokenRejectNotActive          = "not_active"
	TokenRejectExpired            = "expired"
	TokenRejectExhausted          = "exhausted"
	TokenRejectRevoked            = "revoked"
	TokenRejectTaskMismatch       = "task_mismatch"
	TokenRejectManifestDrift      = "manifest_drift"
	TokenRejectArgsDigest         = "args_digest_mismatch"
	TokenRejectBoundaryCeiling    = "boundary_ceiling_exceeded"
	TokenRejectUnknownCapability  = "unknown_capability"
	TokenRejectCapabilityMismatch = "capability_mismatch"
	TokenRejectClockUnavailable   = "authority_clock_unavailable"
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

// MintRequest describes a desired grant.
type MintRequest struct {
	TaskID       string
	Subject      TokenSubject
	CapabilityID string
	TTL          time.Duration // 0 -> DefaultTokenTTL
	MaxUses      int           // 0 -> bounded by expiry only
	Constraints  TokenConstraints
}

// TokenVerifier checks presented tokens against the store, registry, and
// authority public key, then records consumption.
type TokenVerifier struct {
	authorityPubHex string
	registry        *Registry
	store           TokenStore
	clock           func() time.Time
}

// VerifyRequest is one presented token plus its dispatch context.
type VerifyRequest struct {
	Presented    *Token
	TaskID       string
	CapabilityID string
	ManifestHash string
	Args         map[string]interface{} // dispatch arguments, for args_digest constraint
}

// Verify checks shape, signature, store state, task binding, manifest drift,
// and constraints. On success it consumes one use and returns the stored
// token. Every failure is a *TokenError (fail closed).
func (v *TokenVerifier) Verify(req VerifyRequest) (*Token, error) {
	if v == nil || v.registry == nil || v.store == nil || v.authorityPubHex == "" {
		return nil, &TokenError{Reason: TokenRejectMalformed, Details: "token verifier is incomplete"}
	}
	if v.clock == nil {
		return nil, &TokenError{Reason: TokenRejectClockUnavailable}
	}
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
	storedCanonical, err := canonicalize.JCS(stored.signedPayload())
	if err != nil || !bytes.Equal(canonical, storedCanonical) {
		return nil, &TokenError{Reason: TokenRejectMalformed, Details: "presented token does not match stored grant"}
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
	if req.CapabilityID != "" && stored.CapabilityRef.CapabilityID != req.CapabilityID {
		return nil, &TokenError{Reason: TokenRejectCapabilityMismatch, Details: t.TokenID}
	}
	if req.ManifestHash != "" && stored.CapabilityRef.ManifestHash != req.ManifestHash {
		return nil, &TokenError{Reason: TokenRejectCapabilityMismatch, Details: t.TokenID}
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
