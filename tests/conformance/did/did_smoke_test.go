// Package didconformance is the smoke suite for HELM's W3C DID surface.
// It exercises the resolver/verifier APIs plus a complete IATP handshake
// using the in-tree did:key driver. The CLI itself is covered by
// core/cmd/helm tests; here we focus on the public package contract.
package didconformance

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity/did"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity/did/method/key"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity/iatp"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/vcredentials"
)

var smokeNow = time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)

func smokeClock() time.Time { return smokeNow }

// TestDIDSmoke_ResolveDIDKey ensures the resolver returns a valid document
// for a freshly-minted did:key DID.
func TestDIDSmoke_ResolveDIDKey(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("smoke-resolve")
	require.NoError(t, err)

	d, err := did.FromEd25519PublicKey(signer.PublicKeyBytes())
	require.NoError(t, err)

	r := did.NewResolver()
	r.Register(key.New())

	doc, err := r.Resolve(context.Background(), string(d))
	require.NoError(t, err)
	assert.Equal(t, string(d), doc.ID)
	require.Len(t, doc.VerificationMethod, 1)

	pub, err := doc.PrimaryAssertionKey()
	require.NoError(t, err)
	assert.Equal(t, signer.PublicKeyBytes(), pub)
}

// TestDIDSmoke_VerifyVCAgainstResolverDID confirms the DID-aware VC
// verifier accepts a credential whose issuer DID resolves through the
// configured resolver.
func TestDIDSmoke_VerifyVCAgainstResolverDID(t *testing.T) {
	issuer, err := crypto.NewEd25519Signer("smoke-issuer")
	require.NoError(t, err)
	issuerDID, err := did.FromEd25519PublicKey(issuer.PublicKeyBytes())
	require.NoError(t, err)

	holder, err := crypto.NewEd25519Signer("smoke-holder")
	require.NoError(t, err)
	holderDID, err := did.FromEd25519PublicKey(holder.PublicKeyBytes())
	require.NoError(t, err)

	subject := vcredentials.AgentCapabilitySubject{
		ID:        string(holderDID),
		AgentName: "Smoke Agent",
		Capabilities: []vcredentials.CapabilityClaim{
			{Action: "EXECUTE_TOOL", Verified: true, VerifiedAt: smokeNow},
		},
	}
	is := vcredentials.NewIssuerWithClock(string(issuerDID), "Smoke Issuer", issuer, smokeClock)
	vc, err := is.Issue("urn:uuid:smoke-vc", subject, time.Hour)
	require.NoError(t, err)

	r := did.NewResolver(did.WithClock(smokeClock))
	r.Register(key.New())
	v := did.NewVerifier(r, did.WithVerifierClock(smokeClock))
	require.NoError(t, v.VerifyVC(context.Background(), vc))
}

// TestDIDSmoke_IATPHandshake completes a full DID + VC + AITH IATP
// handshake using two in-memory participants.
func TestDIDSmoke_IATPHandshake(t *testing.T) {
	ctx := context.Background()

	mkActor := func(label string) (*crypto.Ed25519Signer, string) {
		s, err := crypto.NewEd25519Signer(label)
		require.NoError(t, err)
		d, err := did.FromEd25519PublicKey(s.PublicKeyBytes())
		require.NoError(t, err)
		return s, string(d)
	}

	holderSigner, holderDID := mkActor("smoke-holder")
	counterSigner, counterDID := mkActor("smoke-counter")
	issuerSigner, issuerDID := mkActor("smoke-issuer")

	scope := []string{"tool:research", "tool:summarize"}
	subject := vcredentials.AgentCapabilitySubject{
		ID:        holderDID,
		AgentName: "Smoke Holder",
		Capabilities: []vcredentials.CapabilityClaim{
			{Action: "tool:research", Verified: true, VerifiedAt: smokeNow},
			{Action: "tool:summarize", Verified: true, VerifiedAt: smokeNow},
		},
	}
	is := vcredentials.NewIssuerWithClock(issuerDID, "Smoke Issuer", issuerSigner, smokeClock)
	vc, err := is.Issue("urn:uuid:smoke-handshake", subject, time.Hour)
	require.NoError(t, err)

	cdm := identity.NewContinuousDelegationManager(identity.WithCDMClock(smokeClock))
	delegation, err := cdm.Grant("did:helm:human:smoke", holderDID, scope, time.Hour)
	require.NoError(t, err)

	resolver := did.NewResolver(did.WithClock(smokeClock))
	resolver.Register(key.New())
	verifier := did.NewVerifier(resolver, did.WithVerifierClock(smokeClock))

	a, err := iatp.NewParticipant(holderDID, holderSigner, resolver, verifier, iatp.WithClock(smokeClock))
	require.NoError(t, err)
	b, err := iatp.NewParticipant(counterDID, counterSigner, resolver, verifier, iatp.WithClock(smokeClock))
	require.NoError(t, err)

	pres, outRcpt, err := a.Offer(counterDID, vc, delegation, []string{"tool:research"})
	require.NoError(t, err)
	assert.Equal(t, holderDID, outRcpt.Subject)
	assert.Equal(t, counterDID, outRcpt.Counterparty)

	cap, inRcpt, err := b.Accept(ctx, pres)
	require.NoError(t, err)
	assert.Equal(t, []string{"tool:research"}, cap.GrantedScope)
	assert.Equal(t, counterDID, inRcpt.Subject)
	assert.Equal(t, holderDID, inRcpt.Counterparty)

	require.NoError(t, a.VerifyCapability(ctx, cap))
}
