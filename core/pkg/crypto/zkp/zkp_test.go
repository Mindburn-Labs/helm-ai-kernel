package zkp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComplianceProofStruct(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)

	proof := ComplianceProof{
		ProofBytes:   []byte("proof-data"),
		PublicInputs: []byte("public-inputs"),
		VerifierKey:  []byte("verifier-key"),
		ProvedAt:     now,
		Circuit:      "compliance-v1",
	}

	assert.Equal(t, "compliance-v1", proof.Circuit)
	assert.Equal(t, now, proof.ProvedAt)
	assert.NotEmpty(t, proof.ProofBytes)
	assert.NotEmpty(t, proof.PublicInputs)
	assert.NotEmpty(t, proof.VerifierKey)
}

func TestPlaceholderProver_ProveCompliance(t *testing.T) {
	prover := NewPlaceholderProver()

	proof, err := prover.ProveCompliance(
		"sha256:abc123",
		[]string{"trace-hash-1", "trace-hash-2"},
		[]string{"ALLOW", "DENY"},
	)
	require.NoError(t, err)
	require.NotNil(t, proof)

	assert.NotEmpty(t, proof.ProofBytes)
	assert.NotEmpty(t, proof.PublicInputs)
	assert.NotEmpty(t, proof.VerifierKey)
	assert.Equal(t, "compliance-v1", proof.Circuit)
	assert.False(t, proof.ProvedAt.IsZero())
}

func TestPlaceholderProver_Deterministic(t *testing.T) {
	prover := &PlaceholderProver{clock: func() time.Time {
		return time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	}}

	proof1, err := prover.ProveCompliance("policy-hash", []string{"t1"}, []string{"ALLOW"})
	require.NoError(t, err)

	proof2, err := prover.ProveCompliance("policy-hash", []string{"t1"}, []string{"ALLOW"})
	require.NoError(t, err)

	assert.Equal(t, proof1.ProofBytes, proof2.ProofBytes,
		"same inputs should produce same proof bytes")
	assert.Equal(t, proof1.PublicInputs, proof2.PublicInputs)
}

func TestPlaceholderProver_ValidationErrors(t *testing.T) {
	prover := NewPlaceholderProver()

	t.Run("empty policy hash", func(t *testing.T) {
		_, err := prover.ProveCompliance("", []string{"t1"}, []string{"ALLOW"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "policy hash")
	})

	t.Run("empty trace hashes", func(t *testing.T) {
		_, err := prover.ProveCompliance("policy", nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trace hash")
	})

	t.Run("mismatched counts", func(t *testing.T) {
		_, err := prover.ProveCompliance("policy", []string{"t1", "t2"}, []string{"ALLOW"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must match")
	})
}

func TestPlaceholderVerifier_VerifyCompliance(t *testing.T) {
	prover := NewPlaceholderProver()
	verifier := NewPlaceholderVerifier()

	proof, err := prover.ProveCompliance("policy-hash", []string{"t1"}, []string{"ALLOW"})
	require.NoError(t, err)

	valid, err := verifier.VerifyCompliance(proof)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestPlaceholderVerifier_NilProof(t *testing.T) {
	verifier := NewPlaceholderVerifier()

	valid, err := verifier.VerifyCompliance(nil)
	require.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "nil")
}

func TestPlaceholderVerifier_EmptyFields(t *testing.T) {
	verifier := NewPlaceholderVerifier()

	t.Run("empty proof bytes", func(t *testing.T) {
		valid, err := verifier.VerifyCompliance(&ComplianceProof{
			PublicInputs: []byte("pi"),
			VerifierKey:  []byte("vk"),
			Circuit:      "compliance-v1",
		})
		require.Error(t, err)
		assert.False(t, valid)
	})

	t.Run("empty public inputs", func(t *testing.T) {
		valid, err := verifier.VerifyCompliance(&ComplianceProof{
			ProofBytes:  []byte("proof"),
			VerifierKey: []byte("vk"),
			Circuit:     "compliance-v1",
		})
		require.Error(t, err)
		assert.False(t, valid)
	})

	t.Run("empty verifier key", func(t *testing.T) {
		valid, err := verifier.VerifyCompliance(&ComplianceProof{
			ProofBytes:   []byte("proof"),
			PublicInputs: []byte("pi"),
			Circuit:      "compliance-v1",
		})
		require.Error(t, err)
		assert.False(t, valid)
	})

	t.Run("empty circuit", func(t *testing.T) {
		valid, err := verifier.VerifyCompliance(&ComplianceProof{
			ProofBytes:   []byte("proof"),
			PublicInputs: []byte("pi"),
			VerifierKey:  []byte("vk"),
		})
		require.Error(t, err)
		assert.False(t, valid)
	})
}

func TestPlaceholderVerifier_WrongVerifierKey(t *testing.T) {
	verifier := NewPlaceholderVerifier()

	valid, err := verifier.VerifyCompliance(&ComplianceProof{
		ProofBytes:   []byte("proof"),
		PublicInputs: []byte("pi"),
		VerifierKey:  []byte("wrong-key-not-matching-circuit"),
		Circuit:      "compliance-v1",
	})
	require.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "verifier key does not match")
}

func TestProverVerifierInterfaceCompliance(t *testing.T) {
	// Verify that PlaceholderProver and PlaceholderVerifier satisfy their interfaces.
	var _ Prover = (*PlaceholderProver)(nil)
	var _ Verifier = (*PlaceholderVerifier)(nil)
}
