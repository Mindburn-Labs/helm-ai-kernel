package sovereignty

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuthorize(t *testing.T) {
	// Generate a real Ed25519 key pair for the test
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	signer := NewEd25519IntentSigner(privKey)
	guard := NewSovereigntyGuard(signer)

	// 1. Valid Decision
	t.Run("ValidDecision", func(t *testing.T) {
		validDecision := &DecisionRecord{
			DecisionID:   "dec_123",
			EffectDigest: "digest_abc",
			Expiry:       time.Now().Add(1 * time.Hour),
			Signature:    "valid_sig",
		}

		intent, err := guard.Authorize(validDecision)
		assert.NoError(t, err)
		assert.NotNil(t, intent)
		assert.Equal(t, validDecision.DecisionID, intent.DecisionID)
		assert.NotEmpty(t, intent.ExecutionID)
		assert.NotEmpty(t, intent.Signature)
		// Verify signature is not a mock prefix
		assert.NotContains(t, intent.Signature, "kernel_sig_")
	})

	// 2. Expired Decision
	t.Run("ExpiredDecision", func(t *testing.T) {
		expiredDecision := &DecisionRecord{
			DecisionID:   "dec_456",
			EffectDigest: "digest_def",
			Expiry:       time.Now().Add(-1 * time.Hour),
			Signature:    "valid_sig",
		}

		intent, err := guard.Authorize(expiredDecision)
		assert.Error(t, err)
		assert.Nil(t, intent)
		assert.Contains(t, err.Error(), "expired")
	})

	// 3. Unsigned Decision
	t.Run("UnsignedDecision", func(t *testing.T) {
		unsignedDecision := &DecisionRecord{
			DecisionID:   "dec_789",
			EffectDigest: "digest_ghi",
			Expiry:       time.Now().Add(1 * time.Hour),
			Signature:    "",
		}

		intent, err := guard.Authorize(unsignedDecision)
		assert.Error(t, err)
		assert.Nil(t, intent)
		assert.Contains(t, err.Error(), "unsigned")
	})

	// 4. No Signer Configured
	t.Run("NoSignerConfigured", func(t *testing.T) {
		guardNoSigner := NewSovereigntyGuard(nil)
		validDecision := &DecisionRecord{
			DecisionID:   "dec_101",
			EffectDigest: "digest_xyz",
			Expiry:       time.Now().Add(1 * time.Hour),
			Signature:    "valid_sig",
		}

		intent, err := guardNoSigner.Authorize(validDecision)
		assert.Error(t, err)
		assert.Nil(t, intent)
		assert.Contains(t, err.Error(), "no signer configured")
	})
}
