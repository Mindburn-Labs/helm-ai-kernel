package shredding

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyStore_EncryptDecryptShred(t *testing.T) {
	ks := NewKeyStore()
	ctx := context.Background()

	// Generate key
	sk, err := ks.GenerateKey(ctx, "user-42")
	require.NoError(t, err)
	assert.True(t, sk.Active)

	// Encrypt
	plaintext := []byte("sensitive personal data")
	ciphertext, err := ks.Encrypt(ctx, "user-42", plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	// Decrypt
	recovered, err := ks.Decrypt(ctx, "user-42", ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)

	// Shred
	record, err := ks.Shred(ctx, "user-42", "GDPR Art. 17 - Right to Erasure")
	require.NoError(t, err)
	assert.Equal(t, "user-42", record.SubjectID)
	assert.True(t, ks.IsShredded("user-42"))

	// Cannot decrypt after shredding
	_, err = ks.Decrypt(ctx, "user-42", ciphertext)
	assert.Error(t, err)

	// Audit log
	log := ks.GetShreddingLog()
	assert.Len(t, log, 1)
}
