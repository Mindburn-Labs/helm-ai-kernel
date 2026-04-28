package jwk

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDriverName(t *testing.T) {
	assert.Equal(t, "jwk", New().Name())
}

func TestRoundTrip(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i + 1)
	}

	didURI, err := FromEd25519(pub)
	require.NoError(t, err)

	doc, err := New().Resolve(context.Background(), didURI)
	require.NoError(t, err)
	require.NotNil(t, doc)
	assert.Equal(t, didURI, doc.ID)

	got, err := doc.PrimaryAssertionKey()
	require.NoError(t, err)
	assert.Equal(t, pub, got)
}

func TestRejectsWrongMethod(t *testing.T) {
	_, err := New().Resolve(context.Background(), "did:key:zXyzzy")
	require.Error(t, err)
}

func TestRejectsUnsupportedCurve(t *testing.T) {
	// payload with kty=EC, which we explicitly reject.
	_, err := New().Resolve(context.Background(), "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OKP/Ed25519")
}

func TestRejectsBadIdentifier(t *testing.T) {
	_, err := New().Resolve(context.Background(), "did:jwk:!!notbase64!!")
	require.Error(t, err)
}
