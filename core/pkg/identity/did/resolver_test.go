package did

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubMethod satisfies the Method interface, counting Resolve calls so the
// cache behaviour can be asserted.
type stubMethod struct {
	name  string
	calls int
	doc   *ResolvedDocument
	err   error
}

func (s *stubMethod) Name() string { return s.name }
func (s *stubMethod) Resolve(_ context.Context, _ string) (*ResolvedDocument, error) {
	s.calls++
	return s.doc, s.err
}

func TestResolverDispatch(t *testing.T) {
	stub := &stubMethod{
		name: "key",
		doc:  &ResolvedDocument{ID: "did:key:z6MkTest"},
	}
	r := NewResolver()
	r.Register(stub)

	doc, err := r.Resolve(context.Background(), "did:key:z6MkTest")
	require.NoError(t, err)
	assert.Equal(t, "did:key:z6MkTest", doc.ID)
	assert.Equal(t, 1, stub.calls)
}

func TestResolverCacheHit(t *testing.T) {
	stub := &stubMethod{name: "key", doc: &ResolvedDocument{ID: "did:key:z6MkTest"}}
	r := NewResolver(WithCacheTTL(time.Hour))
	r.Register(stub)

	for i := 0; i < 3; i++ {
		_, err := r.Resolve(context.Background(), "did:key:z6MkTest")
		require.NoError(t, err)
	}
	assert.Equal(t, 1, stub.calls, "cache hits should not call the driver")
}

func TestResolverCacheExpiry(t *testing.T) {
	stub := &stubMethod{name: "key", doc: &ResolvedDocument{ID: "did:key:z6MkTest"}}
	now := time.Now()
	clock := &mockClock{t: now}
	r := NewResolver(WithCacheTTL(time.Minute), WithClock(clock.now))
	r.Register(stub)

	_, err := r.Resolve(context.Background(), "did:key:z6MkTest")
	require.NoError(t, err)
	clock.advance(2 * time.Minute)
	_, err = r.Resolve(context.Background(), "did:key:z6MkTest")
	require.NoError(t, err)
	assert.Equal(t, 2, stub.calls, "expired cache entries must trigger a re-resolve")
}

func TestResolverInvalidate(t *testing.T) {
	stub := &stubMethod{name: "key", doc: &ResolvedDocument{ID: "did:key:z6MkTest"}}
	r := NewResolver(WithCacheTTL(time.Hour))
	r.Register(stub)

	_, err := r.Resolve(context.Background(), "did:key:z6MkTest")
	require.NoError(t, err)
	r.Invalidate("did:key:z6MkTest")
	_, err = r.Resolve(context.Background(), "did:key:z6MkTest")
	require.NoError(t, err)
	assert.Equal(t, 2, stub.calls)
}

func TestResolverUnknownMethod(t *testing.T) {
	r := NewResolver()
	_, err := r.Resolve(context.Background(), "did:unknown:abc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no driver")
}

func TestResolverDriverError(t *testing.T) {
	stub := &stubMethod{name: "key", err: errors.New("boom")}
	r := NewResolver()
	r.Register(stub)
	_, err := r.Resolve(context.Background(), "did:key:z6MkTest")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

func TestResolverKeystorePersistence(t *testing.T) {
	stub := &stubMethod{name: "key", doc: &ResolvedDocument{ID: "did:key:z6MkTest"}}
	ks := NewMemoryKeystore()
	r := NewResolver(WithCacheTTL(time.Hour), WithKeystore(ks))
	r.Register(stub)

	_, err := r.Resolve(context.Background(), "did:key:z6MkTest")
	require.NoError(t, err)

	// Build a second resolver sharing the keystore. It should hit the
	// keystore cache without invoking the stub driver.
	stub2 := &stubMethod{name: "key", doc: &ResolvedDocument{ID: "did:key:z6MkTest"}}
	r2 := NewResolver(WithCacheTTL(time.Hour), WithKeystore(ks))
	r2.Register(stub2)
	_, err = r2.Resolve(context.Background(), "did:key:z6MkTest")
	require.NoError(t, err)
	assert.Equal(t, 0, stub2.calls, "second resolver should hit the keystore cache")
}

type mockClock struct{ t time.Time }

func (m *mockClock) now() time.Time          { return m.t }
func (m *mockClock) advance(d time.Duration) { m.t = m.t.Add(d) }

func TestParseDID(t *testing.T) {
	method, ident, err := ParseDID("did:web:example.com:agents:alice")
	require.NoError(t, err)
	assert.Equal(t, "web", method)
	assert.Equal(t, "example.com:agents:alice", ident)

	_, _, err = ParseDID("notadid")
	require.Error(t, err)
	_, _, err = ParseDID("did:")
	require.Error(t, err)
	_, _, err = ParseDID("did:web:")
	require.Error(t, err)
}
