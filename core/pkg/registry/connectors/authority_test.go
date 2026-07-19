// quantum_posture: these tests exercise classical Ed25519 connector release
// authority signing and verification; no hybrid or post-quantum claim.
package connectors

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestReleaseAuthorityVerifierAcceptsPinnedSignedCertifiedRelease(t *testing.T) {
	authority := signedReleaseAuthorityFixture(t)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize))
	signer := crypto.NewEd25519SignerFromKey(privateKey, authority.SigningKeyRef)
	envelope, err := SignConnectorReleaseAuthority(authority, signer)
	if err != nil {
		t.Fatalf("SignConnectorReleaseAuthority(): %v", err)
	}
	verifier := releaseAuthorityVerifierFixture(t, authority, privateKey.Public().(ed25519.PublicKey), true)
	if err := verifier.VerifyCurrentCertifiedAt(envelope, authority.ValidFrom); err != nil {
		t.Fatalf("VerifyCurrentCertifiedAt(): %v", err)
	}

	mutated := envelope
	mutated.Authority.CertificationHash = "sha256:" + strings.Repeat("d", 64)
	mutated.Authority.AuthorityHash = ""
	mutated.Authority, err = mutated.Authority.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyEnvelope(mutated); !errors.Is(err, ErrReleaseAuthorityRejected) {
		t.Fatalf("mutated envelope error = %v, want rejected", err)
	}
}

func TestReleaseAuthorityVerifierRejectsTrustAndLivenessFailures(t *testing.T) {
	authority := signedReleaseAuthorityFixture(t)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{18}, ed25519.SeedSize))
	signer := crypto.NewEd25519SignerFromKey(privateKey, authority.SigningKeyRef)
	envelope, err := SignConnectorReleaseAuthority(authority, signer)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		verifier *Ed25519ReleaseAuthorityVerifier
		now      time.Time
	}{
		"wrong key": {
			verifier: releaseAuthorityVerifierFixture(t, authority, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{19}, ed25519.SeedSize)).Public().(ed25519.PublicKey), true),
			now:      authority.ValidFrom,
		},
		"disabled key": {
			verifier: releaseAuthorityVerifierFixture(t, authority, privateKey.Public().(ed25519.PublicKey), false),
			now:      authority.ValidFrom,
		},
		"expired release": {
			verifier: releaseAuthorityVerifierFixture(t, authority, privateKey.Public().(ed25519.PublicKey), true),
			now:      *authority.ValidUntil,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := test.verifier.VerifyCurrentCertifiedAt(envelope, test.now); !errors.Is(err, ErrReleaseAuthorityRejected) {
				t.Fatalf("VerifyCurrentCertifiedAt() error = %v, want rejected", err)
			}
		})
	}
}

func TestReleaseAuthorityVerifierAuthenticatesTerminalRevocation(t *testing.T) {
	certified := signedReleaseAuthorityFixture(t)
	revoked := certified
	revoked.RegistryRevision = 2
	revoked.State = contracts.ConnectorReleaseAuthorityStateRevoked
	revoked.SignedAt = certified.ValidFrom.Add(time.Minute)
	revoked.ValidFrom = revoked.SignedAt
	revoked.ValidUntil = nil
	revoked.PreviousAuthorityHash = certified.AuthorityHash
	revoked.RevokesAuthorityHash = certified.AuthorityHash
	revoked.AuthorityHash = ""
	var err error
	revoked, err = revoked.Seal()
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{20}, ed25519.SeedSize))
	envelope, err := SignConnectorReleaseAuthority(revoked, crypto.NewEd25519SignerFromKey(privateKey, revoked.SigningKeyRef))
	if err != nil {
		t.Fatal(err)
	}
	verifier := releaseAuthorityVerifierFixture(t, revoked, privateKey.Public().(ed25519.PublicKey), true)
	if err := verifier.VerifyEnvelope(envelope); err != nil {
		t.Fatalf("VerifyEnvelope(revocation): %v", err)
	}
	if err := verifier.VerifyCurrentCertifiedAt(envelope, revoked.ValidFrom); !errors.Is(err, ErrReleaseAuthorityRejected) {
		t.Fatalf("VerifyCurrentCertifiedAt(revocation) = %v, want rejected", err)
	}
}

func signedReleaseAuthorityFixture(t *testing.T) contracts.ConnectorReleaseAuthority {
	t.Helper()
	validFrom := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	validUntil := validFrom.Add(24 * time.Hour)
	authority, err := (contracts.ConnectorReleaseAuthority{
		SchemaVersion: contracts.ConnectorReleaseAuthoritySchemaV1, ContractVersion: contracts.ConnectorReleaseAuthorityContractV1,
		AuthorityID: "spiffe://helm/connector-release-authority", SigningKeyRef: "kms://helm/connector-release-authority/key-a",
		Algorithm: contracts.ConnectorReleaseAuthorityAlgorithmV1, RegistryRevision: 1,
		ScopeKind:   contracts.ConnectorReleaseAuthorityScopeGlobal,
		ConnectorID: "connector-a", ConnectorVersion: "1.0.0", State: contracts.ConnectorReleaseAuthorityStateCertified,
		ConnectorExecutorKind: "digital", ConnectorSandboxProfile: "sandbox-pack-lifecycle-v1",
		ConnectorDriftPolicyRef: "policy://connector-drift/v1",
		ConnectorBinaryHash:     "sha256:" + strings.Repeat("a", 64), ConnectorSignatureRef: "sigstore://connector-a/1.0.0",
		ConnectorSignatureHash: "sha256:" + strings.Repeat("b", 64), ConnectorSignerID: "publisher-a",
		CertificationRef: "cert://connector-a/1.0.0", CertificationHash: "sha256:" + strings.Repeat("c", 64),
		CertificationAuthority: "spiffe://helm/certification-review-authority",
		SignedAt:               validFrom.Add(-time.Minute), ValidFrom: validFrom, ValidUntil: &validUntil,
	}).Seal()
	if err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	return authority
}

func releaseAuthorityVerifierFixture(t *testing.T, authority contracts.ConnectorReleaseAuthority, publicKey ed25519.PublicKey, enabled bool) *Ed25519ReleaseAuthorityVerifier {
	t.Helper()
	verifier, err := NewEd25519ReleaseAuthorityVerifier(authority.AuthorityID, []TrustedReleaseAuthorityKey{{
		AuthorityID: authority.AuthorityID, SigningKeyRef: authority.SigningKeyRef, PublicKey: publicKey, Enabled: enabled,
		NotBefore: authority.SignedAt.Add(-time.Hour), NotAfter: authority.SignedAt.Add(time.Hour),
	}})
	if err != nil {
		t.Fatalf("NewEd25519ReleaseAuthorityVerifier(): %v", err)
	}
	return verifier
}

// TestReleaseAuthorityVerifierStoredEnvelopeToleratesDisabledKey proves a key
// disabled after signing still verifies an already-stored head (so a rotation
// can read and revoke it) while a new import from the same disabled key is
// still rejected.
func TestReleaseAuthorityVerifierStoredEnvelopeToleratesDisabledKey(t *testing.T) {
	authority := signedReleaseAuthorityFixture(t)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{21}, ed25519.SeedSize))
	signer := crypto.NewEd25519SignerFromKey(privateKey, authority.SigningKeyRef)
	envelope, err := SignConnectorReleaseAuthority(authority, signer)
	if err != nil {
		t.Fatal(err)
	}
	disabled := releaseAuthorityVerifierFixture(t, authority, privateKey.Public().(ed25519.PublicKey), false)

	if err := disabled.VerifyStoredEnvelope(envelope); err != nil {
		t.Fatalf("VerifyStoredEnvelope() with a disabled-after-signing key = %v, want nil", err)
	}
	if err := disabled.VerifyEnvelope(envelope); !errors.Is(err, ErrReleaseAuthorityRejected) {
		t.Fatalf("VerifyEnvelope() with a disabled key = %v, want rejected", err)
	}

	// A stored head whose signature is tampered must still fail stored verify.
	tampered := envelope
	tampered.Signature = strings.Repeat("0", len(envelope.Signature))
	if err := disabled.VerifyStoredEnvelope(tampered); !errors.Is(err, ErrReleaseAuthorityRejected) {
		t.Fatalf("VerifyStoredEnvelope() with a tampered signature = %v, want rejected", err)
	}
}
