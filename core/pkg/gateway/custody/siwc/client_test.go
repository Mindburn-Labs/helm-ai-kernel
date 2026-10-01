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
}

func newOIDC(t *testing.T) *oidcFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &oidcFixture{t: t, key: key, scope: requestedScope, subject: "verified-subject", clientID: "oaiapp_fixture", revocationStatus: http.StatusOK}
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
			if r.Form.Get("refresh_token") != "fixture-refresh-original" {
				f.t.Error("refresh did not use the retained current token")
			}
		} else {
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(challenge[:]) != f.request.Get("code_challenge") || r.Form.Get("redirect_uri") != f.request.Get("redirect_uri") || r.Form.Get("code") != "fixture-code" {
				http.Error(w, "invalid grant", http.StatusBadRequest)
				return
			}
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
		if selected == "" && (f.request.Get("client_id") != dynamicClient || f.request.Get("agent_name_hint") != "HELM AI OS") {
			f.t.Error("new registration did not use the public dynamic client")
		}
		if selected != "" && (f.request.Get("client_id") != f.clientID || f.request.Has("agent_name_hint")) {
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
	p, _, err := f.client.begin("local-host", "http://127.0.0.1:54321/auth/callback", nil)
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
