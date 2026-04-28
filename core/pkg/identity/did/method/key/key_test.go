package key

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/identity/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDriverName(t *testing.T) {
	assert.Equal(t, "key", New().Name())
}

func TestResolveRoundTrip(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	d, err := did.FromEd25519PublicKey(pub)
	require.NoError(t, err)

	doc, err := New().Resolve(context.Background(), string(d))
	require.NoError(t, err)
	require.NotNil(t, doc)
	assert.Equal(t, string(d), doc.ID)
	require.Len(t, doc.VerificationMethod, 1)

	got, err := doc.PrimaryAssertionKey()
	require.NoError(t, err)
	assert.Equal(t, pub, got)
}

func TestResolveRejectsMalformed(t *testing.T) {
	_, err := New().Resolve(context.Background(), "did:key:")
	require.Error(t, err)

	_, err = New().Resolve(context.Background(), "did:web:example.com")
	require.Error(t, err)
}
