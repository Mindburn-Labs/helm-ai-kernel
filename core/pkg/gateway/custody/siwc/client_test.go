package siwc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type oidcFixture struct {
	t                        *testing.T
	server                   *httptest.Server
	client                   *Client
	key                      *rsa.PrivateKey
	request                  url.Values
	mutate                   func(*idClaims)
	scope, subject, clientID string
	tokens, refreshes        atomic.Int32
	revocationStatus         int
	jwksStatus, tokenStatus  atomic.Int32
	tokenError, revokedToken atomic.Value
	expectedRefresh          atomic.Value
	retryRegistration        bool
}

func newOIDC(t *testing.T) *oidcFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &oidcFixture{t: t, key: key, scope: requestedScope, subject: "verified-subject", clientID: "oaiapp_fixture", revocationStatus: http.StatusOK}
	f.tokenError.Store("")
	f.revokedToken.Store("")
	f.expectedRefresh.Store("fixture-refresh-original")
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	f.client = NewClient()
	f.client.http.Transport = f.server.Client().Transport
	f.client.issuer = f.server.URL
	f.client.authorizeURL = f.server.URL + "/authorize"
	f.client.tokenURL = f.server.URL + "/token"
	f.client.jwksURL = f.server.URL + "/jwks"
	f.client.discoveryURL = f.server.URL + "/discovery"
	now := time.Now().UTC().Truncate(time.Second)
	f.client.now = func() time.Time { return now }
	return f
}

func (f *oidcFixture) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/jwks":
		if status := f.jwksStatus.Load(); status != 0 {
			w.WriteHeader(int(status))
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "issuer-key", Algorithm: "RS256", Use: "sig"}}})
	case "/discovery":
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.server.URL, "revocation_endpoint": f.server.URL + "/revoke"})
	case "/revoke":
		if err := r.ParseForm(); err != nil {
			f.t.Error(err)
		}
		if r.Form.Get("token_type_hint") != "refresh_token" || r.Form.Get("client_id") != f.clientID || r.Form.Get("token") == "" {
			f.t.Error("unbound revocation")
		}
		f.revokedToken.Store(r.Form.Get("token"))
		w.WriteHeader(f.revocationStatus)
	case "/token":
		f.tokens.Add(1)
		if err := r.ParseForm(); err != nil {
			f.t.Error(err)
		}
		if r.Method != http.MethodPost || r.Form.Get("client_id") != f.clientID || r.Form.Get("resource") != resource || r.Form.Get("client_secret") != "" {
			f.t.Error("public client exchange lost binding")
		}
		refresh := r.Form.Get("grant_type") == "refresh_token"
		if refresh {
			f.refreshes.Add(1)
			if _, ok := r.Form["scope"]; ok {
				f.t.Error("refresh widened or changed scope")
			}
			if r.Form.Get("refresh_token") != f.expectedRefresh.Load().(string) {
				f.t.Error("refresh did not use the retained current token")
			}
		} else {
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(challenge[:]) != f.request.Get("code_challenge") || r.Form.Get("redirect_uri") != f.request.Get("redirect_uri") || r.Form.Get("code") != "fixture-code" {
				http.Error(w, "invalid grant", http.StatusBadRequest)
				return
			}
		}
		if status := f.tokenStatus.Load(); status != 0 {
			w.WriteHeader(int(status))
			_ = json.NewEncoder(w).Encode(map[string]string{"error": f.tokenError.Load().(string), "error_description": "must-not-leak-fixture-secret"})
			return
		}
		claims := idClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: f.server.URL, Subject: f.subject,
			Audience: []string{f.clientID}, ExpiresAt: jwt.NewNumericDate(f.client.now().Add(time.Hour)), IssuedAt: jwt.NewNumericDate(f.client.now())}, Nonce: f.request.Get("nonce"), Email: "same-display@example.test"}
		if f.mutate != nil {
			f.mutate(&claims)
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "issuer-key"
		signed, err := token.SignedString(f.key)
		if err != nil {
			f.t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		access, renewal := "fixture-access-original", "fixture-refresh-original"
		if refresh {
			access, renewal = "fixture-access-renewed", "fixture-refresh-renewed"
			if count := f.refreshes.Load(); count > 1 {
				renewal += "-" + strconv.Itoa(int(count))
			}
			f.expectedRefresh.Store(renewal)
		}
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: access, RefreshToken: renewal, IDToken: signed, TokenType: "Bearer", ExpiresIn: 3600, Scope: f.scope})
	default:
		http.NotFound(w, r)
	}
}

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *oidcFixture) login(s *Store, selected string, modify func(url.Values)) (Account, error) {
	return s.Login(context.Background(), f.client, selected, func(raw string) error {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		f.request = u.Query()
		if selected == "" && !f.retryRegistration && (f.request.Get("client_id") != dynamicClient || f.request.Get("agent_name_hint") != "HELM AI OS") {
			f.t.Error("new registration did not use the public dynamic client")
		}
		if (selected != "" || f.retryRegistration) && (f.request.Get("client_id") != f.clientID || f.request.Has("agent_name_hint")) {
			f.t.Error("reauthorization created another registration")
		}
		if f.request.Has("id_token_hint") || f.request.Get("ext_agent_host_id") != s.hostID || f.request.Get("code_challenge_method") != "S256" {
			f.t.Error("unexpected secret hint or host/PKCE binding")
		}
		q := url.Values{"state": {f.request.Get("state")}, "code": {"fixture-code"}, "client_id": {f.clientID}, "scope": {requestedScope}}
		if modify != nil {
			modify(q)
		}
		res, err := http.Get(f.request.Get("redirect_uri") + "?" + q.Encode()) // #nosec G107 -- callback is the real literal loopback listener created by Login
		if err != nil {
			return err
		}
		defer func() { _ = res.Body.Close() }()
		_, _ = io.Copy(io.Discard, res.Body)
		return nil
	})
}

func TestLocalLoginBindsPKCEIdentityAndKeepsCredentialsPrivate(t *testing.T) {
	f, s := newOIDC(t), newStore(t)
	a, err := f.login(s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !a.SignedIn || !a.PlanUse || a.Subject != f.subject || a.ClientID != f.clientID {
		t.Fatalf("wrong account metadata: %+v", a)
	}
	got, err := s.AccessToken(context.Background(), f.client, a.Reference())
	if err != nil || got != "fixture-access-original" {
		t.Fatal("authorized local account token unavailable", err)
	}
	status, err := s.Accounts(context.Background())
	if err != nil || len(status) != 1 {
		t.Fatal("status", err)
	}
	public, _ := json.Marshal(status)
	if strings.Contains(string(public), "fixture-access") || strings.Contains(string(public), "fixture-refresh") || strings.Contains(string(public), "id_token") {
		t.Fatal("status exposed credentials")
	}
	info, err := os.Stat(filepath.Join(s.dir, "account-"+a.ID+".json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("credential record is not private", err)
	}
	other, err := OpenStore(s.dir)
	if err != nil || other.hostID != s.hostID {
		t.Fatal("host identity changed on restart", err)
	}
	ref := a.Reference()
	ref.Generation = "unrelated-generation"
	if _, err := other.AccessToken(context.Background(), f.client, ref); !errors.Is(err, ErrChanged) {
		t.Fatal("foreign generation admitted", err)
	}
	ref = a.Reference()
	ref.HostID = "different-runtime"
	if _, err := other.AccessToken(context.Background(), f.client, ref); !errors.Is(err, ErrChanged) {
		t.Fatal("foreign runtime admitted", err)
	}
}

func TestLoginRefusesWrongIssuerAudienceNonceAndExpiry(t *testing.T) {
	for name, mutate := range map[string]func(*idClaims){
		"issuer":                         func(c *idClaims) { c.Issuer = "https://other.invalid" },
		"audience":                       func(c *idClaims) { c.Audience = []string{"other-client"} },
		"nonce":                          func(c *idClaims) { c.Nonce = "other-flow" },
		"expiry":                         func(c *idClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour)) },
		"missing-issued-at":              func(c *idClaims) { c.IssuedAt = nil },
		"future-issued-at":               func(c *idClaims) { c.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour)) },
		"multiple-audiences-without-azp": func(c *idClaims) { c.Audience = append(c.Audience, "other-client") },
	} {
		t.Run(name, func(t *testing.T) {
			f, s := newOIDC(t), newStore(t)
			f.mutate = mutate
			if _, err := f.login(s, "", nil); !errors.Is(err, ErrIdentity) {
				t.Fatalf("wrong identity accepted: %v", err)
			}
			accounts, err := s.Accounts(context.Background())
			if err != nil || len(accounts) != 0 {
				t.Fatal("rejected callback stored credentials", err)
			}
		})
	}
}

func TestCallbackRefusesWrongStateBeforeExchangingCode(t *testing.T) {
	f := newOIDC(t)
	p, _, err := f.client.begin("local-host", "http://127.0.0.1:54321/auth/callback", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range [][]string{{"another-flow"}, {p.state, p.state}, nil} {
		q := url.Values{"code": {"fixture-code"}, "client_id": {f.clientID}, "state": state}
		if _, err := f.client.complete(context.Background(), p, q); !errors.Is(err, ErrAuthorization) {
			t.Fatal("unbound callback admitted", err)
		}
	}
	if f.tokens.Load() != 0 {
		t.Fatal("unbound callback reached token exchange")
	}
}

func TestIdentityRejectsForgedSignatureAndUnknownKey(t *testing.T) {
	f, s := newOIDC(t), newStore(t)
	a, err := f.login(s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.load(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(r.IDToken, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	if _, err := f.client.identity(context.Background(), strings.Join(parts, "."), a.ClientID, f.request.Get("nonce")); !errors.Is(err, ErrIdentity) {
		t.Fatal("forged signature accepted", err)
	}
	claims := idClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: f.server.URL, Subject: f.subject,
		Audience: []string{f.clientID}, IssuedAt: jwt.NewNumericDate(f.client.now()), ExpiresAt: jwt.NewNumericDate(f.client.now().Add(time.Hour))}, Nonce: f.request.Get("nonce")}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "unpublished-key"
	raw, err := token.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.identity(context.Background(), raw, a.ClientID, claims.Nonce); !errors.Is(err, ErrIdentity) {
		t.Fatal("unpublished signing key accepted", err)
	}
}

func TestLoginRefusesMissingRegistrationAndDenialBeforeExchange(t *testing.T) {
	for name, modify := range map[string]func(url.Values){"missing-client": func(q url.Values) { q.Del("client_id") }, "denied": func(q url.Values) { q.Set("error", "access_denied") }, "duplicate-code": func(q url.Values) { q.Add("code", "second") }} {
		t.Run(name, func(t *testing.T) {
			f, s := newOIDC(t), newStore(t)
			if _, err := f.login(s, "", modify); err == nil {
				t.Fatal("invalid callback accepted")
			}
			if f.tokens.Load() != 0 {
				t.Fatal("invalid callback exchanged a code")
			}
		})
	}
}

func TestIdentityOnlyGrantCannotBorrowPlanPermissionFromCallback(t *testing.T) {
	f, s := newOIDC(t), newStore(t)
	f.scope = "openid profile email"
	a, err := f.login(s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.PlanUse {
		t.Fatal("callback scope widened actual token grant")
	}
	if _, err := s.AccessToken(context.Background(), f.client, a.Reference()); !errors.Is(err, ErrPermission) {
		t.Fatal("identity-only login admitted inference", err)
	}
}

func TestReauthorizationCannotReplaceAnotherAccountOrUndoLogout(t *testing.T) {
	f, s := newOIDC(t), newStore(t)
	a, err := f.login(s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(s.dir, "account-"+a.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	f.subject = "different-subject"
	if _, err := f.login(s, a.ID, nil); !errors.Is(err, ErrIdentity) {
		t.Fatal("account substitution accepted", err)
	}
	after, _ := os.ReadFile(filepath.Join(s.dir, "account-"+a.ID+".json"))
	if string(before) != string(after) {
		t.Fatal("failed reauthorization changed retained credentials")
	}
	f.subject = a.Subject
	_, err = f.login(s, a.ID, func(q url.Values) {
		if _, err := s.Logout(context.Background(), f.client, a.Reference()); err != nil {
			t.Error(err)
		}
	})
	if !errors.Is(err, ErrChanged) {
		t.Fatal("pending login resurrected a signed-out generation", err)
	}
	accounts, err := s.Accounts(context.Background())
	if err != nil || accounts[0].SignedIn {
		t.Fatal("logout lost", err)
	}
}

func TestRefreshIsSerializedAcrossStoreInstancesAndPersistsRotation(t *testing.T) {
	f, s := newOIDC(t), newStore(t)
	a, err := f.login(s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.load(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	r.ExpiresAt = f.client.now().Add(-time.Minute)
	if err := s.write("account-"+a.ID+".json", r); err != nil {
		t.Fatal(err)
	}
	other, err := OpenStore(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := s
			if i%2 != 0 {
				store = other
			}
			token, err := store.AccessToken(context.Background(), f.client, a.Reference())
			if err != nil || token != "fixture-access-renewed" {
				t.Errorf("refresh read: %q %v", token, err)
			}
		}(i)
	}
	wg.Wait()
	if f.refreshes.Load() != 1 {
		t.Fatalf("rotation race: %d refreshes", f.refreshes.Load())
	}
	r, err = s.load(a.ID)
	if err != nil || r.RefreshToken != "fixture-refresh-renewed" || r.Generation != a.Generation {
		t.Fatal("rotation was not retained atomically", err)
	}
}

func expireAccount(t *testing.T, s *Store, c *Client, a Account) {
	t.Helper()
	r, err := s.load(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	r.ExpiresAt = c.now().Add(-time.Minute)
	if err := s.write("account-"+a.ID+".json", r); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshRetainsRotatedTokensAcrossJWKSFailureAndRestart(t *testing.T) {
	for name, status := range map[string]int32{"unavailable": 503, "not-found": 404, "forbidden": 403} {
		t.Run(name, func(t *testing.T) {
			f, s := newOIDC(t), newStore(t)
			a, err := f.login(s, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			expireAccount(t, s, f.client, a)
			receivedAt := f.client.now()
			f.jwksStatus.Store(status)
			for i := 0; i < 2; i++ {
				if token, err := s.AccessToken(context.Background(), f.client, a.Reference()); token != "" || !errors.Is(err, ErrUnavailable) {
					t.Fatal("unvalidated rotated token escaped custody", err)
				}
			}
			r, err := s.load(a.ID)
			if err != nil || r.PendingRefresh == nil || r.RefreshToken != "fixture-refresh-renewed" || r.AccessToken != "" || !r.SignedIn || r.PlanUse || !r.RenewalPending {
				t.Fatal("replacement was not durably quarantined", err)
			}
			accounts, err := s.Accounts(context.Background())
			if err != nil || len(accounts) != 1 || !accounts[0].RenewalPending || accounts[0].PlanUse {
				t.Fatal("pending validation missing from safe status", err)
			}
			statusJSON, err := json.Marshal(accounts)
			if err != nil || strings.Contains(string(statusJSON), "fixture-refresh") || strings.Contains(string(statusJSON), "fixture-access") {
				t.Fatal("pending status exposed credentials", err)
			}
			other, err := OpenStore(s.dir)
			if err != nil {
				t.Fatal(err)
			}
			f.jwksStatus.Store(0)
			f.client.now = func() time.Time { return receivedAt.Add(30 * time.Second) }
			if token, err := other.AccessToken(context.Background(), f.client, a.Reference()); err != nil || token != "fixture-access-renewed" {
				t.Fatal("restart did not finish retained validation", err)
			}
			r, err = other.load(a.ID)
			if err != nil || r.PendingRefresh != nil || r.RenewalPending || !r.PlanUse || r.Generation != a.Generation || !r.ExpiresAt.Equal(receivedAt.Add(time.Hour)) {
				t.Fatal("recovery changed expiry or account generation", err)
			}
			if f.refreshes.Load() != 1 {
				t.Fatal("recovery replayed a consumed refresh token")
			}
		})
	}
}

func TestRefreshOnlyConfirmedTerminalOAuthErrorsClearCredentials(t *testing.T) {
	for _, tc := range []struct {
		code     string
		status   int32
		terminal bool
	}{
		{"invalid_grant", 400, true},
		{"invalid_refresh_token", 400, true},
		{"token_expired", 401, true},
		{"refresh_token_expired", 400, true},
		{"refresh_token_invalidated", 400, true},
		{"refresh_token_reused", 400, true},
		{"invalid_client", 400, false},
		{"temporarily_unavailable", 503, false},
		{"invalid_grant", 503, false},
		{"", 404, false},
	} {
		t.Run(tc.code+"/"+http.StatusText(int(tc.status)), func(t *testing.T) {
			f, s := newOIDC(t), newStore(t)
			a, err := f.login(s, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			expireAccount(t, s, f.client, a)
			f.tokenError.Store(tc.code)
			f.tokenStatus.Store(tc.status)
			token, err := s.AccessToken(context.Background(), f.client, a.Reference())
			if token != "" || err == nil || errors.Is(err, ErrReauthorize) != tc.terminal || strings.Contains(err.Error(), "must-not-leak-fixture-secret") {
				t.Fatal("OAuth error lost its bounded meaning", err)
			}
			r, err := s.load(a.ID)
			if err != nil || r.ClientID != a.ClientID || r.Generation != a.Generation {
				t.Fatal("failure lost retained registration", err)
			}
			if tc.terminal {
				if r.SignedIn || r.PlanUse || r.AccessToken != "" || r.RefreshToken != "" || r.IDToken != "" {
					t.Fatal("terminal refresh rejection retained credentials")
				}
			} else if !r.SignedIn || r.RefreshToken != "fixture-refresh-original" || r.AccessToken != "fixture-access-original" {
				t.Fatal("recoverable server/configuration failure erased credentials")
			}
		})
	}
}

func TestExpiredQuarantinedIdentityRenewsOnlyAfterIdentityValidation(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(strconv.FormatBool(mismatch), func(t *testing.T) {
			f, s := newOIDC(t), newStore(t)
			a, err := f.login(s, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			expireAccount(t, s, f.client, a)
			if mismatch {
				f.mutate = func(c *idClaims) { c.Subject = "different-account" }
			}
			f.jwksStatus.Store(http.StatusServiceUnavailable)
			if token, err := s.AccessToken(context.Background(), f.client, a.Reference()); token != "" || !errors.Is(err, ErrUnavailable) {
				t.Fatal("expected quarantined rotation", err)
			}
			recoveredAt := f.client.now().Add(61 * time.Minute)
			f.client.now = func() time.Time { return recoveredAt }
			f.jwksStatus.Store(0)
			other, err := OpenStore(s.dir)
			if err != nil {
				t.Fatal(err)
			}
			token, err := other.AccessToken(context.Background(), f.client, a.Reference())
			if mismatch {
				if token != "" || !errors.Is(err, ErrIdentity) || f.refreshes.Load() != 1 {
					t.Fatal("old mismatched identity authorized another renewal", err)
				}
				return
			}
			if err != nil || token != "fixture-access-renewed" || f.refreshes.Load() != 2 {
				t.Fatal("long outage destroyed the renewable session", err)
			}
			r, err := other.load(a.ID)
			if err != nil || r.RefreshToken != "fixture-refresh-renewed-2" || r.PendingRefresh != nil || !r.ExpiresAt.Equal(recoveredAt.Add(time.Hour)) || r.Generation != a.Generation {
				t.Fatal("renewal did not persist the fresh response", err)
			}
		})
	}
}

func TestFailedInitialExchangeReusesIssuedRegistrationAfterRestart(t *testing.T) {
	f, s := newOIDC(t), newStore(t)
	f.tokenError.Store("invalid_grant")
	f.tokenStatus.Store(http.StatusBadRequest)
	if _, err := f.login(s, "", nil); err == nil {
		t.Fatal("failed exchange accepted")
	}
	accounts, err := s.Accounts(context.Background())
	if err != nil || len(accounts) != 0 {
		t.Fatal("unvalidated registration became an account", err)
	}
	var registration incompleteRegistration
	if err := s.read("registration.json", &registration); err != nil || registration.ClientID != f.clientID || registration.HostID != s.hostID || registration.Issuer != f.server.URL {
		t.Fatal("issued registration was lost", err)
	}
	info, err := os.Stat(filepath.Join(s.dir, "registration.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("incomplete registration is not private", err)
	}
	other, err := OpenStore(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	f.retryRegistration = true
	f.tokenStatus.Store(0)
	if _, err := f.login(other, "", func(q url.Values) { q.Set("client_id", "oaiapp_foreign") }); !errors.Is(err, ErrIdentity) {
		t.Fatal("retry replaced the retained client identity", err)
	}
	if f.tokens.Load() != 1 {
		t.Fatal("mismatched retry reached token exchange")
	}
	a, err := f.login(other, "", nil)
	if err != nil || !a.SignedIn || a.ClientID != f.clientID {
		t.Fatal("issued registration retry failed", err)
	}
	registration = incompleteRegistration{}
	if err := other.read("registration.json", &registration); err != nil || registration.ClientID != "" {
		t.Fatal("validated registration remained incomplete", err)
	}
}

func TestCompletedRegistrationIsReconciledAfterInterruptedRetirement(t *testing.T) {
	f, s := newOIDC(t), newStore(t)
	a, err := f.login(s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	// This is the exact on-disk state after the account's atomic write and
	// before retirement of its incomplete-registration marker.
	if err := s.write("registration.json", incompleteRegistration{ClientID: a.ClientID, Issuer: a.Issuer, HostID: a.HostID}); err != nil {
		t.Fatal(err)
	}
	other, err := OpenStore(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	f.clientID, f.subject = "oaiapp_second", "second-account"
	second, err := f.login(other, "", nil)
	if err != nil || second.ID == a.ID || second.ClientID != "oaiapp_second" {
		t.Fatal("completed registration blocked another account", err)
	}
	first, err := other.load(a.ID)
	if err != nil || first.Generation != a.Generation || first.Subject != a.Subject || !first.SignedIn {
		t.Fatal("registration reconciliation changed the existing account", err)
	}
	accounts, err := other.Accounts(context.Background())
	if err != nil || len(accounts) != 2 {
		t.Fatal("account addition lost a registration", err)
	}
}

func TestLogoutRevokesPendingReplacementAndClearsQuarantine(t *testing.T) {
	f, s := newOIDC(t), newStore(t)
	a, err := f.login(s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	expireAccount(t, s, f.client, a)
	f.jwksStatus.Store(http.StatusServiceUnavailable)
	if token, err := s.AccessToken(context.Background(), f.client, a.Reference()); token != "" || !errors.Is(err, ErrUnavailable) {
		t.Fatal("expected pending identity validation", err)
	}
	confirmed, err := s.Logout(context.Background(), f.client, a.Reference())
	if err != nil || !confirmed || f.revokedToken.Load().(string) != "fixture-refresh-renewed" {
		t.Fatal("logout did not revoke the retained replacement", err)
	}
	r, err := s.load(a.ID)
	if err != nil || r.PendingRefresh != nil || r.RenewalPending || r.RefreshToken != "" || r.AccessToken != "" || r.SignedIn {
		t.Fatal("logout retained quarantined credentials", err)
	}
}

func TestLogoutClearsTokensEvenWhenRemoteRevocationFails(t *testing.T) {
	f, s := newOIDC(t), newStore(t)
	a, err := f.login(s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.revocationStatus = http.StatusServiceUnavailable
	confirmed, err := s.Logout(context.Background(), f.client, a.Reference())
	if err != nil || confirmed {
		t.Fatal("remote failure mislabeled", err)
	}
	r, err := s.load(a.ID)
	if err != nil || r.AccessToken != "" || r.RefreshToken != "" || r.IDToken != "" || r.SignedIn || !r.RemoteRevocationUnconfirmed {
		t.Fatal("local sign-out incomplete", err)
	}
	confirmed, err = s.Logout(context.Background(), f.client, r.Reference())
	if err != nil || confirmed {
		t.Fatal("missing old token falsely became remote revocation proof", err)
	}
}

func TestCredentialPermissionsAndSymlinksAreRefused(t *testing.T) {
	f, s := newOIDC(t), newStore(t)
	a, err := f.login(s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.dir, "account-"+a.ID+".json")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	} // #nosec G302 -- negative test of an unsafe credential mode
	if _, err := s.Accounts(context.Background()); !errors.Is(err, ErrStorage) {
		t.Fatal("public credential file accepted", err)
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".saved", path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Accounts(context.Background()); !errors.Is(err, ErrStorage) {
		t.Fatal("symlink credential accepted", err)
	}
}

func TestCommandRefusesCloudAndHasNoCredentialExport(t *testing.T) {
	var out strings.Builder
	getenv := func(string) string { return "" }
	if err := Run(context.Background(), []string{"login"}, getenv, &out, &out); err == nil {
		t.Fatal("Cloud plan login admitted")
	}
	getenv = func(k string) string {
		if k == "HELM_DEPLOYMENT_MODE" {
			return "selfhost"
		}
		return ""
	}
	if err := Run(context.Background(), []string{"export-token"}, getenv, &out, &out); err == nil {
		t.Fatal("credential export admitted")
	}
}
