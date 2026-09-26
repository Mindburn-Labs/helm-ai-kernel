package jwks

// quantum_posture: tests sign classical RS256 JWTs for a local JWKS endpoint;
// no post-quantum claim.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type refreshTestIssuer struct {
	key       *rsa.PrivateKey
	stranger  *rsa.PrivateKey // signs tokens whose kid the endpoint never publishes
	fetches   atomic.Int64
	down      atomic.Bool
	delay     time.Duration
	server    *httptest.Server
	validator *JWKSValidator
	clock     time.Time
	clockMu   sync.Mutex
}

func newRefreshTestIssuer(t *testing.T, delay time.Duration) *refreshTestIssuer {
	t.Helper()
	i := &refreshTestIssuer{delay: delay, clock: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)}
	var err error
	if i.key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	if i.stranger, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	i.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i.fetches.Add(1)
		time.Sleep(i.delay)
		if i.down.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &i.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	}))
	t.Cleanup(i.server.Close)
	i.validator = NewJWKSValidator(JWKSConfig{
		JWKSURL: i.server.URL, Issuer: "issuer", Audience: "audience", AllowInsecureLoopback: true,
		Now: i.now,
	})
	return i
}

func (i *refreshTestIssuer) now() time.Time {
	i.clockMu.Lock()
	defer i.clockMu.Unlock()
	return i.clock
}

func (i *refreshTestIssuer) advance(d time.Duration) {
	i.clockMu.Lock()
	defer i.clockMu.Unlock()
	i.clock = i.clock.Add(d)
}

// token is signed at the real wall clock: the JWT time checks use it, while
// the validator's refresh schedule uses the test clock.
func (i *refreshTestIssuer) token(t *testing.T, kid string, key *rsa.PrivateKey) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "issuer", "aud": "audience", "sub": "s", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func validationKind(err error) JWKSValidationErrorKind {
	if validationErr, ok := err.(*JWKSValidationError); ok {
		return validationErr.Kind
	}
	return ""
}

// Unauthenticated callers can pick any kid. Concurrent unknown kids must cost
// one fetch, and none at all within MinRefreshInterval of the last one.
func TestJWKSUnknownKidsShareOneRateLimitedFetch(t *testing.T) {
	issuer := newRefreshTestIssuer(t, 50*time.Millisecond)
	if _, err := issuer.validator.ValidateAuthorization(issuer.token(t, "k1", issuer.key)); err != nil {
		t.Fatalf("initial token: %v", err)
	}
	if got := issuer.fetches.Load(); got != 1 {
		t.Fatalf("fetches after the first token = %d, want 1", got)
	}

	for n := range 20 { // within the interval: answered from the cache
		_, err := issuer.validator.ValidateAuthorization(issuer.token(t, "unknown-"+string(rune('a'+n)), issuer.stranger))
		if validationKind(err) != JWKSErrKeyNotFound {
			t.Fatalf("unknown kid within the interval: %v, want key_not_found", err)
		}
	}
	if got := issuer.fetches.Load(); got != 1 {
		t.Fatalf("unknown kids within the refresh interval fetched %d times, want 0 extra", got-1)
	}

	issuer.advance(jwksDefaultMinRefreshInterval + time.Second)
	var wg sync.WaitGroup
	for n := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := issuer.validator.ValidateAuthorization(issuer.token(t, "burst-"+string(rune('a'+n)), issuer.stranger))
			if validationKind(err) != JWKSErrKeyNotFound {
				t.Errorf("unknown kid in a burst: %v, want key_not_found", err)
			}
		}()
	}
	wg.Wait()
	if got := issuer.fetches.Load(); got != 2 {
		t.Fatalf("20 concurrent unknown kids caused %d fetches, want exactly 1", got-1)
	}
}

// A JWKS outage does not take verification down while cached keys are within
// MaxStale, does not retry on every request, and fails closed after MaxStale.
func TestJWKSOutageServesCachedKeysUntilMaxStale(t *testing.T) {
	issuer := newRefreshTestIssuer(t, 0)
	good := func() error {
		_, err := issuer.validator.ValidateAuthorization(issuer.token(t, "k1", issuer.key))
		return err
	}
	if err := good(); err != nil {
		t.Fatal(err)
	}
	issuer.down.Store(true)
	issuer.advance(jwksRefreshInterval + time.Minute) // cache is due for a refresh
	for range 10 {
		if err := good(); err != nil {
			t.Fatalf("cached key during an outage: %v", err)
		}
	}
	if got := issuer.fetches.Load(); got != 2 {
		t.Fatalf("an outage caused %d refresh attempts across 10 requests, want 1", got-1)
	}
	_, err := issuer.validator.ValidateAuthorization(issuer.token(t, "rotated", issuer.stranger))
	if kind := validationKind(err); kind != JWKSErrKeyNotFound && kind != JWKSErrFetchFailed {
		t.Fatalf("unknown kid during an outage: %v", err)
	}
	issuer.advance(jwksDefaultMinRefreshInterval + time.Second)
	if _, err := issuer.validator.ValidateAuthorization(issuer.token(t, "rotated", issuer.stranger)); validationKind(err) != JWKSErrFetchFailed {
		t.Fatalf("unknown kid whose forced refresh failed: %v, want jwks_fetch_failed (503), not a malformed token", err)
	}
	issuer.advance(jwksDefaultMaxStale)
	if err := good(); validationKind(err) != JWKSErrFetchFailed {
		t.Fatalf("cached key past MaxStale: %v, want jwks_fetch_failed", err)
	}
}

func TestJWKSUnreachableWithNoKeysFailsClosed(t *testing.T) {
	issuer := newRefreshTestIssuer(t, 0)
	issuer.down.Store(true)
	if _, err := issuer.validator.ValidateAuthorization(issuer.token(t, "k1", issuer.key)); validationKind(err) != JWKSErrFetchFailed {
		t.Fatalf("no keys and an unreachable endpoint: %v, want jwks_fetch_failed", err)
	}
	if _, err := issuer.validator.ValidateAuthorization(issuer.token(t, "k1", issuer.key)); validationKind(err) != JWKSErrFetchFailed {
		t.Fatalf("second request within the interval: %v, want jwks_fetch_failed without a refetch", err)
	}
	if got := issuer.fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}
}
