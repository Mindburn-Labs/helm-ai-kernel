package siwc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAccountModelsUsesCurrentRegistrationAndProviderOrder(t *testing.T) {
	f, s := newOIDC(t), newStore(t)
	a, err := f.login(s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := s.AccessToken(context.Background(), f.client, a.Reference())
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/v1/models" || r.URL.RawQuery != "" ||
			r.Header.Get("Authorization") != "Bearer "+expected {
			t.Error("catalog request lost the selected account or endpoint")
		}
		_, _ = fmt.Fprint(w, `{"models":[{"slug":"second","display_name":"Second","visibility":"list","instructions":"not returned"},{"slug":"hidden","display_name":"Hidden","visibility":"hide"},{"slug":"first","display_name":"First","visibility":"list"}]}`)
	}))
	defer api.Close()
	f.client.modelsURL = api.URL + "/v1/models"
	got, err := s.Models(context.Background(), f.client, a.Reference())
	if err != nil || len(got) != 2 || got[0].Slug != "second" || got[1].Slug != "first" || got[0].DisplayName != "Second" {
		t.Fatalf("wrong selected account catalog: %+v, %v", got, err)
	}
	ref := a.Reference()
	ref.Generation = "another-selection"
	if _, err := s.Models(context.Background(), f.client, ref); !errors.Is(err, ErrChanged) || calls.Load() != 1 {
		t.Fatal("stale selection contacted upstream", err, calls.Load())
	}
}

func TestAccountModelsRejectsFailuresWithoutRetryOrFallback(t *testing.T) {
	f, s := newOIDC(t), newStore(t)
	a, err := f.login(s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"unauthorized", 401, "provider error body", ErrReauthorize},
		{"forbidden", 403, "provider error body", ErrPermission},
		{"limited", 429, "provider error body", ErrUnavailable},
		{"unavailable", 503, "provider error body", ErrUnavailable},
		{"wrong schema", 200, `{"data":[]}`, ErrUnavailable},
		{"null models", 200, `{"models":null}`, ErrUnavailable},
		{"malformed", 200, `{`, ErrUnavailable},
		{"oversize", 200, strings.Repeat("x", maxResponseBytes+1), ErrUnavailable},
		{"duplicate", 200, `{"models":[{"slug":"m","display_name":"M","visibility":"list"},{"slug":"m","display_name":"Again","visibility":"list"}]}`, ErrUnavailable},
		{"terminal control", 200, `{"models":[{"slug":"m","display_name":"\u001b[31m","visibility":"list"}]}`, ErrUnavailable},
		{"empty available list", 200, `{"models":[]}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer api.Close()
			f.client.modelsURL = api.URL
			models, err := s.Models(context.Background(), f.client, a.Reference())
			if !errors.Is(err, tc.want) || calls.Load() != 1 || len(models) != 0 {
				t.Fatalf("wrong bounded catalog result: count=%d, error=%v, calls=%d", len(models), err, calls.Load())
			}
		})
	}
}

func TestAccountModelsDoesNotRedirectCredentials(t *testing.T) {
	f, s := newOIDC(t), newStore(t)
	a, err := f.login(s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var escaped atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { escaped.Add(1) }))
	defer other.Close()
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer api.Close()
	f.client.modelsURL = api.URL
	if _, err := s.Models(context.Background(), f.client, a.Reference()); !errors.Is(err, ErrUnavailable) || escaped.Load() != 0 {
		t.Fatal("catalog followed redirect", err, escaped.Load())
	}
	if NewClient().modelsURL != "https://api.openai.com/v1/models" {
		t.Fatal("production catalog endpoint drifted")
	}
}

func TestAccountModelsDiscardsCatalogAfterLogout(t *testing.T) {
	f, s := newOIDC(t), newStore(t)
	a, err := f.login(s, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = fmt.Fprint(w, `{"models":[{"slug":"old-account-model","display_name":"Old","visibility":"list"}]}`)
	}))
	defer api.Close()
	f.client.modelsURL = api.URL
	result := make(chan error, 1)
	go func() { _, err := s.Models(context.Background(), f.client, a.Reference()); result <- err }()
	<-started
	_, logoutErr := s.Logout(context.Background(), f.client, a.Reference())
	close(release)
	if logoutErr != nil {
		t.Fatal(logoutErr)
	}
	if err := <-result; !errors.Is(err, ErrChanged) {
		t.Fatal("catalog from signed-out account survived", err)
	}
}

func TestAccountModelsCommandRequiresExplicitSelection(t *testing.T) {
	var out, diagnostic bytes.Buffer
	err := Run(context.Background(), []string{"models"}, func(k string) string {
		if k == "HELM_DEPLOYMENT_MODE" {
			return "selfhost"
		}
		return ""
	}, &out, &diagnostic)
	if err == nil || !strings.Contains(err.Error(), "explicit --account") || out.Len() != 0 {
		t.Fatal("models selected a default account", err)
	}
}
