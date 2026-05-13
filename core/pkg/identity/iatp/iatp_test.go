package iatp

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/identity"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/identity/did"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/identity/did/method/key"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/vcredentials"
)

// fixedNow is the deterministic clock used across all IATP tests.
var fixedNow = time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)

func clockFn() time.Time { return fixedNow }

// testActor is an Ed25519-signed agent identity backed by a did:key DID.
type testActor struct {
	signer *crypto.Ed25519Signer
	did    string
}

func newTestActor(t *testing.T, label string) *testActor {
	t.Helper()
	s, err := crypto.NewEd25519Signer(label)
	require.NoError(t, err)
	d, err := did.FromEd25519PublicKey(s.PublicKeyBytes())
	require.NoError(t, err)
	return &testActor{signer: s, did: string(d)}
}

// newResolver returns a resolver wired to the in-tree did:key driver.
func newResolver() *did.Resolver {
	r := did.NewResolver(did.WithCacheTTL(time.Hour), did.WithClock(clockFn))
	r.Register(key.New())
	return r
}

// issueVC builds and signs a HELM AgentCapabilityCredential issued by
// `issuer` to `holder`.
func issueVC(t *testing.T, issuer *testActor, holderDID string, scope []string) *vcredentials.VerifiableCredential {
	t.Helper()
	caps := make([]vcredentials.CapabilityClaim, 0, len(scope))
	for _, action := range scope {
		caps = append(caps, vcredentials.CapabilityClaim{
			Action:     action,
			Verified:   true,
			VerifiedAt: fixedNow,
		})
	}
	subject := vcredentials.AgentCapabilitySubject{
		ID:           holderDID,
		AgentName:    "Test Agent",
		Capabilities: caps,
	}
	is := vcredentials.NewIssuerWithClock(issuer.did, "Test Issuer", issuer.signer, clockFn)
	vc, err := is.Issue("urn:uuid:test-vc-001", subject, time.Hour)
	require.NoError(t, err)
	return vc
}

func TestParticipant_HandshakeRoundTrip(t *testing.T) {
	ctx := context.Background()

	holder := newTestActor(t, "alpha-holder")
	counter := newTestActor(t, "beta-counter")
	issuer := newTestActor(t, "gamma-issuer")

	resolver := newResolver()
	verifier := did.NewVerifier(resolver, did.WithVerifierClock(clockFn))

	// Holder presents a VC issued by `issuer` for two scope entries.
	scope := []string{"tool:search", "tool:summarize"}
	vc := issueVC(t, issuer, holder.did, scope)

	// AITH continuous delegation from a delegator to the holder.
	cdm := identity.NewContinuousDelegationManager(identity.WithCDMClock(clockFn))
	delegation, err := cdm.Grant("did:helm:human:user", holder.did, scope, time.Hour)
	require.NoError(t, err)

	// Build participants.
	a, err := NewParticipant(holder.did, holder.signer, resolver, verifier, WithClock(clockFn))
	require.NoError(t, err)
	b, err := NewParticipant(counter.did, counter.signer, resolver, verifier, WithClock(clockFn))
	require.NoError(t, err)

	// Step 1: A → Offer to B.
	pres, outRcpt, err := a.Offer(b.did, vc, delegation, []string{"tool:search"})
	require.NoError(t, err)
	require.NotNil(t, pres)
	assert.Equal(t, holder.did, pres.HolderDID)
	assert.Equal(t, counter.did, pres.Counterparty)
	assert.NotEmpty(t, pres.Nonce)
	assert.Equal(t, holder.did, outRcpt.Subject)
	assert.Equal(t, counter.did, outRcpt.Counterparty)
	assert.Equal(t, "outgoing", outRcpt.Direction)

	// Step 2: B → Accept and counter-sign.
	cap, inRcpt, err := b.Accept(ctx, pres)
	require.NoError(t, err)
	require.NotNil(t, cap)
	assert.Equal(t, holder.did, cap.HolderDID)
	assert.Equal(t, counter.did, cap.IssuerDID)
	assert.Equal(t, []string{"tool:search"}, cap.GrantedScope)
	assert.NotEmpty(t, cap.Signature)
	assert.Equal(t, counter.did, inRcpt.Subject)
	assert.Equal(t, holder.did, inRcpt.Counterparty)
	assert.Equal(t, "incoming", inRcpt.Direction)
	assert.Equal(t, cap.SessionID, inRcpt.SessionID)

	// Step 3: A verifies the counter-signed capability offline.
	require.NoError(t, a.VerifyCapability(ctx, cap))

	// SessionStore round-trip.
	store := NewSessionStore().WithSessionClock(clockFn)
	store.Put(cap)
	got, ok := store.Get(cap.SessionID)
	require.True(t, ok)
	assert.Equal(t, cap.SessionID, got.SessionID)
}

func TestParticipant_OfferRejectsMissingInputs(t *testing.T) {
	holder := newTestActor(t, "h-missing")
	counter := newTestActor(t, "c-missing")
	resolver := newResolver()
	verifier := did.NewVerifier(resolver, did.WithVerifierClock(clockFn))
	a, err := NewParticipant(holder.did, holder.signer, resolver, verifier, WithClock(clockFn))
	require.NoError(t, err)

	vc := issueVC(t, holder, holder.did, []string{"tool:x"})
	cdm := identity.NewContinuousDelegationManager(identity.WithCDMClock(clockFn))
	deleg, err := cdm.Grant("did:helm:human:user", holder.did, []string{"tool:x"}, time.Hour)
	require.NoError(t, err)

	_, _, err = a.Offer("", vc, deleg, []string{"tool:x"})
	require.Error(t, err)

	_, _, err = a.Offer(counter.did, nil, deleg, []string{"tool:x"})
	require.Error(t, err)

	_, _, err = a.Offer(counter.did, vc, nil, []string{"tool:x"})
	require.Error(t, err)

	_, _, err = a.Offer(counter.did, vc, deleg, nil)
	require.Error(t, err)
}

func TestParticipant_AcceptRejectsScopeWidening(t *testing.T) {
	ctx := context.Background()

	holder := newTestActor(t, "h-scope")
	counter := newTestActor(t, "c-scope")
	issuer := newTestActor(t, "i-scope")

	resolver := newResolver()
	verifier := did.NewVerifier(resolver, did.WithVerifierClock(clockFn))

	delegationScope := []string{"tool:search"}
	vc := issueVC(t, issuer, holder.did, delegationScope)

	cdm := identity.NewContinuousDelegationManager(identity.WithCDMClock(clockFn))
	deleg, err := cdm.Grant("did:helm:human:user", holder.did, delegationScope, time.Hour)
	require.NoError(t, err)

	a, err := NewParticipant(holder.did, holder.signer, resolver, verifier, WithClock(clockFn))
	require.NoError(t, err)
	b, err := NewParticipant(counter.did, counter.signer, resolver, verifier, WithClock(clockFn))
	require.NoError(t, err)

	// Holder asks for a scope NOT in the delegation.
	pres, _, err := a.Offer(b.did, vc, deleg, []string{"tool:write"})
	require.NoError(t, err)

	_, _, err = b.Accept(ctx, pres)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not covered by delegation")
}

func TestParticipant_AcceptRejectsRevokedDelegation(t *testing.T) {
	ctx := context.Background()

	holder := newTestActor(t, "h-rev")
	counter := newTestActor(t, "c-rev")
	issuer := newTestActor(t, "i-rev")

	resolver := newResolver()
	verifier := did.NewVerifier(resolver, did.WithVerifierClock(clockFn))

	scope := []string{"tool:search"}
	vc := issueVC(t, issuer, holder.did, scope)

	cdm := identity.NewContinuousDelegationManager(identity.WithCDMClock(clockFn))
	deleg, err := cdm.Grant("did:helm:human:user", holder.did, scope, time.Hour)
	require.NoError(t, err)
	require.NoError(t, cdm.Revoke(deleg.ID))

	// Mark the snapshot revoked to mirror the over-the-wire state where the
	// responder receives a stale offer carrying a now-revoked delegation.
	revokedAt := fixedNow
	deleg.RevokedAt = &revokedAt

	a, err := NewParticipant(holder.did, holder.signer, resolver, verifier, WithClock(clockFn))
	require.NoError(t, err)
	b, err := NewParticipant(counter.did, counter.signer, resolver, verifier, WithClock(clockFn))
	require.NoError(t, err)

	pres, _, err := a.Offer(b.did, vc, deleg, scope)
	require.NoError(t, err)

	_, _, err = b.Accept(ctx, pres)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not active")
}

func TestParticipant_AcceptRejectsExpiredPresentation(t *testing.T) {
	ctx := context.Background()

	holder := newTestActor(t, "h-exp")
	counter := newTestActor(t, "c-exp")
	issuer := newTestActor(t, "i-exp")

	resolver := newResolver()
	verifier := did.NewVerifier(resolver, did.WithVerifierClock(clockFn))

	scope := []string{"tool:x"}
	vc := issueVC(t, issuer, holder.did, scope)

	cdm := identity.NewContinuousDelegationManager(identity.WithCDMClock(clockFn))
	deleg, err := cdm.Grant("did:helm:human:user", holder.did, scope, time.Hour)
	require.NoError(t, err)

	a, err := NewParticipant(holder.did, holder.signer, resolver, verifier, WithClock(clockFn))
	require.NoError(t, err)

	// Build the offer at fixedNow.
	pres, _, err := a.Offer(counter.did, vc, deleg, scope)
	require.NoError(t, err)

	// B's clock is far ahead, past the presentation TTL.
	bClock := func() time.Time { return fixedNow.Add(2 * time.Minute) }
	b, err := NewParticipant(counter.did, counter.signer, resolver, verifier, WithClock(bClock))
	require.NoError(t, err)

	_, _, err = b.Accept(ctx, pres)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestParticipant_AcceptRejectsTamperedCredential(t *testing.T) {
	ctx := context.Background()

	holder := newTestActor(t, "h-tamper")
	counter := newTestActor(t, "c-tamper")
	issuer := newTestActor(t, "i-tamper")

	resolver := newResolver()
	verifier := did.NewVerifier(resolver, did.WithVerifierClock(clockFn))

	scope := []string{"tool:x"}
	vc := issueVC(t, issuer, holder.did, scope)

	// Mutate the credential after signing.
	vc.CredentialSubject.AgentName = "Tampered"

	cdm := identity.NewContinuousDelegationManager(identity.WithCDMClock(clockFn))
	deleg, err := cdm.Grant("did:helm:human:user", holder.did, scope, time.Hour)
	require.NoError(t, err)

	a, err := NewParticipant(holder.did, holder.signer, resolver, verifier, WithClock(clockFn))
	require.NoError(t, err)
	b, err := NewParticipant(counter.did, counter.signer, resolver, verifier, WithClock(clockFn))
	require.NoError(t, err)

	pres, _, err := a.Offer(b.did, vc, deleg, scope)
	require.NoError(t, err)

	_, _, err = b.Accept(ctx, pres)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VC verification failed")
}

func TestParticipant_NonceReplayRejected(t *testing.T) {
	ctx := context.Background()

	holder := newTestActor(t, "h-replay")
	counter := newTestActor(t, "c-replay")
	issuer := newTestActor(t, "i-replay")

	resolver := newResolver()
	verifier := did.NewVerifier(resolver, did.WithVerifierClock(clockFn))

	scope := []string{"tool:x"}
	vc := issueVC(t, issuer, holder.did, scope)

	cdm := identity.NewContinuousDelegationManager(identity.WithCDMClock(clockFn))
	deleg, err := cdm.Grant("did:helm:human:user", holder.did, scope, time.Hour)
	require.NoError(t, err)

	a, err := NewParticipant(holder.did, holder.signer, resolver, verifier, WithClock(clockFn))
	require.NoError(t, err)
	b, err := NewParticipant(counter.did, counter.signer, resolver, verifier, WithClock(clockFn))
	require.NoError(t, err)

	pres, _, err := a.Offer(b.did, vc, deleg, scope)
	require.NoError(t, err)

	// First accept succeeds.
	_, _, err = b.Accept(ctx, pres)
	require.NoError(t, err)

	// Second accept of the same nonce is rejected.
	_, _, err = b.Accept(ctx, pres)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replay")
}

func TestParticipant_VerifyCapabilityRejectsTamperedSignature(t *testing.T) {
	ctx := context.Background()

	holder := newTestActor(t, "h-vsig")
	counter := newTestActor(t, "c-vsig")
	issuer := newTestActor(t, "i-vsig")

	resolver := newResolver()
	verifier := did.NewVerifier(resolver, did.WithVerifierClock(clockFn))

	scope := []string{"tool:x"}
	vc := issueVC(t, issuer, holder.did, scope)

	cdm := identity.NewContinuousDelegationManager(identity.WithCDMClock(clockFn))
	deleg, err := cdm.Grant("did:helm:human:user", holder.did, scope, time.Hour)
	require.NoError(t, err)

	a, err := NewParticipant(holder.did, holder.signer, resolver, verifier, WithClock(clockFn))
	require.NoError(t, err)
	b, err := NewParticipant(counter.did, counter.signer, resolver, verifier, WithClock(clockFn))
	require.NoError(t, err)

	pres, _, err := a.Offer(b.did, vc, deleg, scope)
	require.NoError(t, err)
	cap, _, err := b.Accept(ctx, pres)
	require.NoError(t, err)

	// Tamper with the granted scope after counter-signature.
	cap.GrantedScope = append(cap.GrantedScope, "tool:y")

	err = a.VerifyCapability(ctx, cap)
	require.Error(t, err)
}

func TestSessionStore_ExpirationDropsEntry(t *testing.T) {
	now := fixedNow
	clock := func() time.Time { return now }
	store := NewSessionStore().WithSessionClock(clock)

	cap := &Capability{
		SessionID: "iatp-sess:expiring",
		ExpiresAt: now.Add(10 * time.Second),
	}
	store.Put(cap)

	got, ok := store.Get("iatp-sess:expiring")
	require.True(t, ok)
	assert.Equal(t, cap.SessionID, got.SessionID)

	// Advance past expiry.
	now = fixedNow.Add(time.Minute)
	_, ok = store.Get("iatp-sess:expiring")
	assert.False(t, ok)
}
