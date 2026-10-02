package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMindburnAPIKeyEnvPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name            string
		primary, legacy bool
	}{
		{"primary", true, false},
		{"primary overrides legacy", true, true},
		{"legacy fallback", false, true},
		{"unset", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string]string{}
			if tc.primary {
				values["MINDBURN_HELM_API_KEY"] = t.Name() + "/primary"
			}
			if tc.legacy {
				values["HELM_API_KEY"] = t.Name() + "/legacy"
			}
			var warnings bytes.Buffer
			got := mindburnAPIKeyFromEnv(func(name string) string { return values[name] }, &warnings)
			want := values["MINDBURN_HELM_API_KEY"]
			if !tc.primary {
				want = values["HELM_API_KEY"]
			}
			if got != want {
				t.Fatal("wrong environment precedence")
			}
			warned := warnings.String() != ""
			if warned != (!tc.primary && tc.legacy) {
				t.Fatalf("unexpected warning state: %t", warned)
			}
			if warned && strings.Count(warnings.String(), "\n") != 1 {
				t.Fatal("warning must be one line")
			}
			for _, value := range values {
				if strings.Contains(warnings.String(), value) {
					t.Fatal("credential leaked in warning")
				}
			}
		})
	}
}

func TestWrapMCPAuthUsesMindburnKeyWhenBothPresent(t *testing.T) {
	primary, legacy := t.Name()+"/primary", t.Name()+"/legacy"
	t.Setenv("MINDBURN_HELM_API_KEY", primary)
	t.Setenv("HELM_API_KEY", legacy)
	h, err := wrapMCPAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), "static-header", "http://localhost:9194")
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"X-HELM-API-Key", "Authorization"} {
		for _, value := range []string{primary, legacy, ""} {
			r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			provided := value
			if header == "Authorization" && value != "" {
				provided = "Bearer " + value
			}
			r.Header.Set(header, provided)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := http.StatusUnauthorized
			if value == primary {
				want = http.StatusNoContent
			}
			if w.Code != want {
				t.Fatalf("%s status=%d want=%d", header, w.Code, want)
			}
		}
	}
}
