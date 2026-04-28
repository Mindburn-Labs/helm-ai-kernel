package trust

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEUTrustedList_LoadFromFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "eu_lotl_sample.xml"))
	require.NoError(t, err)

	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	list := NewEUTrustedListWithConfig(EUTrustedListConfig{
		Now: func() time.Time { return now },
	})
	require.NoError(t, list.LoadFromBytes(data))

	// Granted QTSAs are trusted, with case-insensitive thumbprint lookup.
	assert.True(t, list.Trust(strings.Repeat("a", 64)))
	assert.True(t, list.Trust(strings.Repeat("b", 64)),
		"thumbprint lookup must be case-insensitive (fixture uses upper-case BBBB...)")
	assert.True(t, list.Trust(strings.Repeat("c", 64)))

	// Withdrawn services must not be cached.
	assert.False(t, list.Trust(strings.Repeat("d", 64)),
		"withdrawn services must not be trusted")

	// Unknown thumbprints return false.
	assert.False(t, list.Trust("0000000000000000000000000000000000000000000000000000000000000000"))
	assert.False(t, list.Trust(""))

	st := list.Status()
	assert.Equal(t, DefaultEULOTLEndpoint, st.Endpoint)
	assert.Equal(t, 3, st.QualifiedTSACount,
		"three granted QTSAs (sk-primary, sk-secondary, dtrust)")
	// EE and DE come from both PointersToOtherTSL and inline TSPs (deduped to a set);
	// FR only from PointersToOtherTSL. Total = 3.
	assert.Equal(t, 3, st.MemberStateCount)
	assert.Equal(t, "European Commission - DG CNECT (test fixture)", st.SchemeOperator)
	assert.False(t, st.Stale, "fresh load must not be stale")
	assert.Equal(t, now.UTC(), list.LastRefresh())
}

func TestEUTrustedList_StatusStaleWhenEmpty(t *testing.T) {
	list := NewEUTrustedList()
	st := list.Status()
	assert.True(t, st.Stale, "empty cache must report stale")
	assert.Equal(t, 0, st.QualifiedTSACount)
	assert.True(t, list.LastRefresh().IsZero())
}

func TestEUTrustedList_StatusStaleAfterInterval(t *testing.T) {
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	clock := &atomicClock{value: now.UnixNano()}

	list := NewEUTrustedListWithConfig(EUTrustedListConfig{
		RefreshInterval: time.Hour,
		Now:             clock.Now,
	})

	data, err := os.ReadFile(filepath.Join("testdata", "eu_lotl_sample.xml"))
	require.NoError(t, err)
	require.NoError(t, list.LoadFromBytes(data))

	// Immediately after load: not stale.
	assert.False(t, list.Status().Stale)

	// Advance clock past the refresh interval.
	clock.advance(2 * time.Hour)
	st := list.Status()
	assert.True(t, st.Stale, "cache older than RefreshInterval must be stale")
	assert.Greater(t, st.Age, time.Hour)
}

func TestEUTrustedList_RefreshRespectsInterval(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "eu_lotl_sample.xml"))
	require.NoError(t, err)

	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write(data)
	}))
	t.Cleanup(server.Close)

	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	clock := &atomicClock{value: now.UnixNano()}

	list := NewEUTrustedListWithConfig(EUTrustedListConfig{
		Endpoint:        server.URL,
		RefreshInterval: time.Hour,
		Now:             clock.Now,
		HTTPClient:      &http.Client{Timeout: 5 * time.Second},
	})

	require.NoError(t, list.Refresh(context.Background()))
	assert.Equal(t, int32(1), atomic.LoadInt32(&hits))
	assert.True(t, list.Trust(strings.Repeat("a", 64)))

	// Within the interval: no second hit.
	clock.advance(30 * time.Minute)
	require.NoError(t, list.Refresh(context.Background()))
	assert.Equal(t, int32(1), atomic.LoadInt32(&hits),
		"refresh inside interval must not hit network")

	// Past the interval: refresh fires.
	clock.advance(90 * time.Minute)
	require.NoError(t, list.Refresh(context.Background()))
	assert.Equal(t, int32(2), atomic.LoadInt32(&hits),
		"refresh past interval must hit network")
}

func TestEUTrustedList_RefreshHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	list := NewEUTrustedListWithConfig(EUTrustedListConfig{
		Endpoint:        server.URL,
		RefreshInterval: time.Hour,
		HTTPClient:      &http.Client{Timeout: 5 * time.Second},
	})

	err := list.Refresh(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

func TestEUTrustedList_RefreshMalformedXML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte("<not-trusted-list></not-trusted-list>"))
	}))
	t.Cleanup(server.Close)

	list := NewEUTrustedListWithConfig(EUTrustedListConfig{
		Endpoint:        server.URL,
		RefreshInterval: time.Hour,
		HTTPClient:      &http.Client{Timeout: 5 * time.Second},
	})

	err := list.Refresh(context.Background())
	require.Error(t, err)
}

func TestParseLOTL_RejectsEmpty(t *testing.T) {
	// Well-formed but empty TSL must fail because the cache would be useless.
	doc := lotlDocument{}
	body, err := xml.Marshal(doc)
	require.NoError(t, err)
	_, err = parseLOTL(body)
	assert.Error(t, err)
}

func TestComputeThumbprint_PrefersProvidedSHA(t *testing.T) {
	tp := computeThumbprint("ZZZ-not-base64", "ABC123")
	assert.Equal(t, "abc123", tp)
}

func TestComputeThumbprint_DerivesFromBase64(t *testing.T) {
	// "hello" base64 = "aGVsbG8="
	// SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	tp := computeThumbprint("aGVsbG8=", "")
	assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", tp)
}

func TestComputeThumbprint_EmptyInputReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", computeThumbprint("", ""))
}

// atomicClock is a tiny test helper for monotonic UTC time advancement
// that satisfies the `func() time.Time` signature used by the cache.
type atomicClock struct {
	value int64
}

func (c *atomicClock) Now() time.Time {
	return time.Unix(0, atomic.LoadInt64(&c.value)).UTC()
}

func (c *atomicClock) advance(d time.Duration) {
	atomic.AddInt64(&c.value, int64(d))
}
