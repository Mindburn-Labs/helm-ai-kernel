package gdpr17

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProofRoundTrip(t *testing.T) {
	keys := generateKeys(t)
	prover, err := NewProver(WithProvingKey(keys.ProvingKey), WithVerifyingKeyForProofs(keys.VerifyingKey))
	require.NoError(t, err)
	verifier, err := NewVerifier(WithVerifyingKey(keys.VerifyingKey))
	require.NoError(t, err)

	artifact, err := prover.Prove(validRequest())
	require.NoError(t, err)
	require.Equal(t, Scheme, artifact.Scheme)
	require.Equal(t, CircuitVersion, artifact.CircuitVersion)
	require.NotEmpty(t, artifact.Proof)
	require.NotEmpty(t, artifact.VerifyingKeyFingerprint)
	require.EqualValues(t, CircuitID, artifact.PublicSignals.CircuitID)

	require.NoError(t, verifier.Verify(artifact))

	data, err := MarshalProof(artifact)
	require.NoError(t, err)
	parsed, err := ParseProof(data)
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(parsed))
}

func TestProofRejectsPostErasureSubjectEvent(t *testing.T) {
	keys := generateKeys(t)
	prover, err := NewProver(WithProvingKey(keys.ProvingKey))
	require.NoError(t, err)

	req := validRequest()
	req.Events = append(req.Events, Event{Unix: req.ErasureUnix + 60, SubjectMatch: true})

	_, err = prover.Prove(req)
	require.Error(t, err)
}

func TestVerifierRejectsTamperedProof(t *testing.T) {
	keys := generateKeys(t)
	prover, err := NewProver(WithProvingKey(keys.ProvingKey))
	require.NoError(t, err)
	verifier, err := NewVerifier(WithVerifyingKey(keys.VerifyingKey))
	require.NoError(t, err)

	artifact, err := prover.Prove(validRequest())
	require.NoError(t, err)
	artifact.Proof[len(artifact.Proof)-1] ^= 0x01

	require.Error(t, verifier.Verify(artifact))
}

func TestVerifierRejectsTamperedPublicSignal(t *testing.T) {
	keys := generateKeys(t)
	prover, err := NewProver(WithProvingKey(keys.ProvingKey))
	require.NoError(t, err)
	verifier, err := NewVerifier(WithVerifyingKey(keys.VerifyingKey))
	require.NoError(t, err)

	artifact, err := prover.Prove(validRequest())
	require.NoError(t, err)
	artifact.PublicSignals.ErasureUnix++

	require.Error(t, verifier.Verify(artifact))
}

func TestVerifierRejectsWrongVerifyingKey(t *testing.T) {
	keys := generateKeys(t)
	otherKeys := generateKeys(t)
	prover, err := NewProver(WithProvingKey(keys.ProvingKey))
	require.NoError(t, err)
	verifier, err := NewVerifier(WithVerifyingKey(otherKeys.VerifyingKey))
	require.NoError(t, err)

	artifact, err := prover.Prove(validRequest())
	require.NoError(t, err)

	require.Error(t, verifier.Verify(artifact))
}

func TestKeyPathLoadingAndExpiry(t *testing.T) {
	keys := generateKeys(t)
	dir := t.TempDir()
	pkPath := dir + "/gdpr17.pk"
	vkPath := dir + "/gdpr17.vk"
	require.NoError(t, WriteProvingKey(pkPath, keys.ProvingKey))
	require.NoError(t, WriteVerifyingKey(vkPath, keys.VerifyingKey))

	future := time.Now().Add(time.Hour)
	prover, err := NewProver(
		WithProvingKeyPath(pkPath, future),
		WithVerifyingKeyForProofsPath(vkPath, future),
	)
	require.NoError(t, err)
	verifier, err := NewVerifier(WithVerifyingKeyPath(vkPath, future))
	require.NoError(t, err)

	artifact, err := prover.Prove(validRequest())
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(artifact))

	_, err = NewVerifier(WithVerifyingKeyPath(dir + "/missing.vk"))
	require.Error(t, err)

	past := time.Now().Add(-time.Minute)
	_, err = NewVerifier(WithVerifyingKeyPath(vkPath, past))
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrKeyExpired))

	_, err = NewProver(WithProvingKeyPath(pkPath, past))
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrKeyExpired))
}

func generateKeys(t *testing.T) *KeyPair {
	t.Helper()
	keys, err := GenerateKeys()
	require.NoError(t, err)
	return keys
}

func validRequest() ProveRequest {
	return ProveRequest{
		PolicyID:     "gdpr17-erasure-policy-v1",
		ErasureUnix:  1700000100,
		SubjectID:    "user-123",
		SubjectNonce: "nonce-2026-04-24",
		Events: []Event{
			{Unix: 1699999900, SubjectMatch: true},
			{Unix: 1700000200, SubjectMatch: false},
		},
	}
}
