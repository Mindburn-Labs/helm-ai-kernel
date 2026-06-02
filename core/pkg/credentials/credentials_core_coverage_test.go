package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type credentialsRoundTripFunc func(*http.Request) (*http.Response, error)

func (f credentialsRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type credentialsFakeKMS struct{}

func (credentialsFakeKMS) Encrypt(plaintext string) (string, error) {
	return "kms:" + plaintext, nil
}

func (credentialsFakeKMS) Decrypt(ciphertext string) (string, error) {
	return strings.TrimPrefix(ciphertext, "kms:"), nil
}

func (credentialsFakeKMS) Rotate() (int, error) {
	return 2, nil
}

func (credentialsFakeKMS) ActiveVersion() int {
	return 1
}

func TestCoverageGoogleOAuthBranches(t *testing.T) {
	t.Setenv("GOOGLE_CLIENT_ID", "env-client")
	t.Setenv("GOOGLE_CLIENT_SECRET", "env-secret")
	envOAuth := NewGoogleOAuth("", "")
	if envOAuth.ClientID != "env-client" || envOAuth.ClientSecret != "env-secret" {
		t.Fatalf("env credentials not loaded: %+v", envOAuth)
	}

	ctx := context.Background()
	oauth := NewGoogleOAuth("client", "secret")
	oauth.httpClient = &http.Client{Transport: credentialsRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := ""
		if req.Body != nil {
			data, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			body = string(data)
		}
		switch {
		case req.URL.Host == "oauth2.googleapis.com" && strings.Contains(body, "authorization_code"):
			if req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || !strings.Contains(body, "code=code") {
				t.Fatalf("unexpected exchange request body=%s content-type=%s", body, req.Header.Get("Content-Type"))
			}
			return credentialsHTTPResponse(http.StatusOK, `{"access_token":"access","refresh_token":"refresh","expires_in":3600,"scope":"email","token_type":"Bearer"}`), nil
		case req.URL.Host == "oauth2.googleapis.com" && strings.Contains(body, "refresh_token=refresh"):
			return credentialsHTTPResponse(http.StatusOK, `{"access_token":"new-access","expires_in":120,"scope":"email","token_type":"Bearer"}`), nil
		case req.URL.Host == "www.googleapis.com":
			if req.Header.Get("Authorization") != "Bearer access" {
				t.Fatalf("unexpected user info auth header: %s", req.Header.Get("Authorization"))
			}
			return credentialsHTTPResponse(http.StatusOK, `{"id":"u1","email":"user@example.com","verified_email":true,"picture":"pic"}`), nil
		case req.URL.Host == "oauth2.googleapis.com" && strings.Contains(body, "token=access"):
			return credentialsHTTPResponse(http.StatusOK, `{}`), nil
		default:
			t.Fatalf("unexpected request %s body=%s", req.URL.String(), body)
			return nil, nil
		}
	})}

	token, err := oauth.ExchangeCode(ctx, "code", "verifier", "https://app/callback")
	if err != nil || token.AccessToken != "access" || token.RefreshToken != "refresh" {
		t.Fatalf("ExchangeCode got %+v err=%v", token, err)
	}
	refreshed, err := oauth.RefreshToken(ctx, "refresh")
	if err != nil || refreshed.AccessToken != "new-access" {
		t.Fatalf("RefreshToken got %+v err=%v", refreshed, err)
	}
	user, err := oauth.GetUserInfo(ctx, "access")
	if err != nil || user.Email != "user@example.com" || !user.VerifiedEmail {
		t.Fatalf("GetUserInfo got %+v err=%v", user, err)
	}
	if err := oauth.RevokeToken(ctx, "access"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	for name, fn := range map[string]func(*GoogleOAuth) error{
		"exchange transport": func(g *GoogleOAuth) error {
			_, err := g.ExchangeCode(ctx, "code", "verifier", "redirect")
			return err
		},
		"refresh transport": func(g *GoogleOAuth) error {
			_, err := g.RefreshToken(ctx, "refresh")
			return err
		},
		"userinfo transport": func(g *GoogleOAuth) error {
			_, err := g.GetUserInfo(ctx, "access")
			return err
		},
		"revoke transport": func(g *GoogleOAuth) error {
			return g.RevokeToken(ctx, "access")
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewGoogleOAuth("client", "secret")
			g.httpClient = &http.Client{Transport: credentialsRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("transport failed")
			})}
			if err := fn(g); err == nil {
				t.Fatal("expected transport error")
			}
		})
	}

	for name, tc := range map[string]struct {
		status int
		body   string
		call   func(*GoogleOAuth) error
	}{
		"exchange status": {http.StatusBadRequest, `bad exchange`, func(g *GoogleOAuth) error {
			_, err := g.ExchangeCode(ctx, "code", "verifier", "redirect")
			return err
		}},
		"exchange decode": {http.StatusOK, `{`, func(g *GoogleOAuth) error {
			_, err := g.ExchangeCode(ctx, "code", "verifier", "redirect")
			return err
		}},
		"refresh status": {http.StatusUnauthorized, `bad refresh`, func(g *GoogleOAuth) error {
			_, err := g.RefreshToken(ctx, "refresh")
			return err
		}},
		"refresh decode": {http.StatusOK, `{`, func(g *GoogleOAuth) error {
			_, err := g.RefreshToken(ctx, "refresh")
			return err
		}},
		"userinfo status": {http.StatusForbidden, `{}`, func(g *GoogleOAuth) error {
			_, err := g.GetUserInfo(ctx, "access")
			return err
		}},
		"userinfo decode": {http.StatusOK, `{`, func(g *GoogleOAuth) error {
			_, err := g.GetUserInfo(ctx, "access")
			return err
		}},
		"revoke status": {http.StatusInternalServerError, `{}`, func(g *GoogleOAuth) error {
			return g.RevokeToken(ctx, "access")
		}},
		"revoke already revoked": {http.StatusBadRequest, `{}`, func(g *GoogleOAuth) error {
			return g.RevokeToken(ctx, "access")
		}},
	} {
		t.Run(name, func(t *testing.T) {
			g := NewGoogleOAuth("client", "secret")
			g.httpClient = &http.Client{Transport: credentialsRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return credentialsHTTPResponse(tc.status, tc.body), nil
			})}
			err := tc.call(g)
			if name == "revoke already revoked" {
				if err != nil {
					t.Fatalf("expected 400 revoke to be accepted, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected oauth error")
			}
		})
	}
}

func TestCoverageCredentialHandlers(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store, err := NewStore(db, bytes.Repeat([]byte("h"), 32), WithEnvFallback(false))
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(store)
	handler.googleOAuth.ClientID = "google-client"
	handler.googleOAuth.httpClient = &http.Client{Transport: credentialsRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "oauth2.googleapis.com" && req.URL.Path == "/token" {
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "authorization_code") {
				return credentialsHTTPResponse(http.StatusOK, `{"access_token":"google-access","refresh_token":"google-refresh","expires_in":3600,"scope":"email","token_type":"Bearer"}`), nil
			}
			return credentialsHTTPResponse(http.StatusOK, `{"access_token":"google-access-2","refresh_token":"google-refresh-2","expires_in":1800,"scope":"email","token_type":"Bearer"}`), nil
		}
		if req.URL.Host == "www.googleapis.com" {
			return credentialsHTTPResponse(http.StatusOK, `{"id":"u1","email":"google@example.com","verified_email":true}`), nil
		}
		if req.URL.Host == "oauth2.googleapis.com" && req.URL.Path == "/revoke" {
			return credentialsHTTPResponse(http.StatusOK, `{}`), nil
		}
		t.Fatalf("unexpected handler oauth request: %s", req.URL.String())
		return nil, nil
	})}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	rec := httptest.NewRecorder()
	handler.handleConfig(rec, httptest.NewRequest(http.MethodGet, "/config", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "google-client") {
		t.Fatalf("handleConfig status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handler.handleStoreOpenAI(rec, httptest.NewRequest(http.MethodPost, "/openai", strings.NewReader(`{"apiKey":"sk-test"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("handleStoreOpenAI status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	handler.handleStoreAnthropic(rec, httptest.NewRequest(http.MethodPost, "/anthropic", strings.NewReader(`{"apiKey":"anthropic-key"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("handleStoreAnthropic status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	handler.handleStatus(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("handleStatus status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handler.handleGoogleToken(rec, httptest.NewRequest(http.MethodPost, "/google/token", strings.NewReader(`{"code":"code","codeVerifier":"verifier","redirectUri":"https://app/callback"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("handleGoogleToken status=%d body=%s", rec.Code, rec.Body.String())
	}
	var tokenBody map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tokenBody); err != nil || tokenBody["access_token"] != "google-access" {
		t.Fatalf("unexpected token response %+v err=%v", tokenBody, err)
	}
	rec = httptest.NewRecorder()
	handler.handleGoogleRefresh(rec, httptest.NewRequest(http.MethodPost, "/google/refresh", strings.NewReader(`{}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("handleGoogleRefresh status=%d body=%s", rec.Code, rec.Body.String())
	}

	for name, call := range map[string]func(*httptest.ResponseRecorder){
		"bad google token body": func(rec *httptest.ResponseRecorder) {
			handler.handleGoogleToken(rec, httptest.NewRequest(http.MethodPost, "/google/token", strings.NewReader(`{`)))
		},
		"bad openai body": func(rec *httptest.ResponseRecorder) {
			handler.handleStoreOpenAI(rec, httptest.NewRequest(http.MethodPost, "/openai", strings.NewReader(`{`)))
		},
		"bad anthropic body": func(rec *httptest.ResponseRecorder) {
			handler.handleStoreAnthropic(rec, httptest.NewRequest(http.MethodPost, "/anthropic", strings.NewReader(`{`)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			call(rec)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected bad request, got %d body=%s", rec.Code, rec.Body.String())
			}
		})
	}

	rec = httptest.NewRecorder()
	handler.handleDeleteGoogle(rec, httptest.NewRequest(http.MethodDelete, "/google", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("handleDeleteGoogle status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	handler.handleDeleteOpenAI(rec, httptest.NewRequest(http.MethodDelete, "/openai", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("handleDeleteOpenAI status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	handler.handleDeleteAnthropic(rec, httptest.NewRequest(http.MethodDelete, "/anthropic", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("handleDeleteAnthropic status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCoverageCredentialStoreKMSAndFallbackBranches(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	kmsStore := NewStoreWithKMS(db, credentialsFakeKMS{}, WithEnvFallback(false))
	encrypted, err := kmsStore.encrypt("secret")
	if err != nil || encrypted != "kms:secret" {
		t.Fatalf("kms encrypt got %q err=%v", encrypted, err)
	}
	decrypted, err := kmsStore.decrypt(encrypted)
	if err != nil || decrypted != "secret" {
		t.Fatalf("kms decrypt got %q err=%v", decrypted, err)
	}

	expires := time.Now().UTC().Add(time.Hour)
	if err := kmsStore.SaveCredential(ctx, &Credential{
		ID:           "kms-id",
		OperatorID:   "operator-kms",
		Provider:     ProviderOpenAI,
		TokenType:    TokenTypeApiKey,
		AccessToken:  "openai-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    &expires,
	}); err != nil {
		t.Fatalf("SaveCredential with KMS: %v", err)
	}
	if err := kmsStore.UpdateLastUsed(ctx, "operator-kms", ProviderOpenAI); err != nil {
		t.Fatalf("UpdateLastUsed: %v", err)
	}
	got, err := kmsStore.GetCredential(ctx, "operator-kms", ProviderOpenAI)
	if err != nil || got.AccessToken != "openai-token" || got.RefreshToken != "refresh-token" || got.LastUsedAt == nil {
		t.Fatalf("GetCredential with KMS got %+v err=%v", got, err)
	}

	envStore, err := NewStore(db, bytes.Repeat([]byte("e"), 32), WithEnvFallback(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENAI_API_KEY", "sk-env")
	t.Setenv("ANTHROPIC_API_KEY", "anthropic-env")
	t.Setenv("GEMINI_API_KEY", "gemini-env")
	for provider, want := range map[ProviderType]string{
		ProviderOpenAI:    "sk-env",
		ProviderAnthropic: "anthropic-env",
		ProviderGoogle:    "gemini-env",
	} {
		cred, err := envStore.GetCredential(ctx, "missing", provider)
		if err != nil || cred == nil || cred.AccessToken != want || cred.TokenType != TokenTypeApiKey {
			t.Fatalf("env fallback %s got %+v err=%v", provider, cred, err)
		}
	}
	t.Setenv("OPENAI_API_KEY", "")
	if cred, err := envStore.GetCredential(ctx, "missing", ProviderOpenAI); err != nil || cred != nil {
		t.Fatalf("empty env fallback got %+v err=%v", cred, err)
	}
	if cred, err := envStore.getFromEnv(ProviderType("unknown")); err != nil || cred != nil {
		t.Fatalf("unknown env fallback got %+v err=%v", cred, err)
	}
}

func TestCoverageCredentialRotationSafeDepBranches(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	manager := NewRotationManager(RotationPolicy{MaxAge: time.Hour, GracePeriod: time.Minute}).WithClock(func() time.Time {
		return now
	})
	cred := manager.Issue("tenant", "service")
	if err := manager.ValidateForSafeDep(cred.CredentialID); err != nil {
		t.Fatalf("active credential should validate: %v", err)
	}
	if err := manager.ValidateForSafeDep("missing"); err == nil {
		t.Fatal("expected missing credential error")
	}

	now = now.Add(2 * time.Hour)
	err := manager.ValidateForSafeDep(cred.CredentialID)
	decay, ok := err.(*CredentialDecayError)
	if !ok {
		t.Fatalf("expected CredentialDecayError, got %T %v", err, err)
	}
	if !strings.Contains(decay.Error(), cred.CredentialID) || decay.SafeDepHazardCode() == "" {
		t.Fatalf("unexpected decay error: %v hazard=%s", decay, decay.SafeDepHazardCode())
	}
}

func credentialsHTTPResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}
