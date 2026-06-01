package account

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientAppendsDecisionPathAndForwardsSession(t *testing.T) {
	var sawCookie bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/account/decisions" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if _, err := r.Cookie("helm_session"); err == nil {
			sawCookie = true
		}
		_ = json.NewEncoder(w).Encode(Decision{
			Allowed:     true,
			UserState:   "available",
			ReasonCode:  "ENTITLEMENT_ALLOWED",
			Reason:      "ok",
			DecisionRef: "ent_test",
			Source:      "test",
			ExpiresAt:   time.Now().UTC().Add(time.Minute),
		})
	}))
	defer server.Close()

	client := &Client{DecisionsURL: decisionsURL(server.URL), Required: true, HTTPClient: server.Client()}
	inbound := httptest.NewRequest(http.MethodGet, "/api/v1/launchpad/apps", nil)
	inbound.AddCookie(&http.Cookie{Name: "helm_session", Value: "sess-test"})
	decision, err := client.Decide(inbound.Context(), inbound, DecisionRequest{Action: "launch", AppID: "openclaw", SubstrateID: "local-container"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision == nil || !decision.Allowed {
		t.Fatalf("decision = %#v", decision)
	}
	if !sawCookie {
		t.Fatal("expected hosted session cookie to be forwarded")
	}
}

func TestRequiredClientFailsClosedWithoutHostedSessionCredential(t *testing.T) {
	client := &Client{DecisionsURL: "https://account.example/api/v1/account/decisions", Required: true}
	_, err := client.Decide(httptest.NewRequest(http.MethodGet, "/", nil).Context(), httptest.NewRequest(http.MethodGet, "/", nil), DecisionRequest{Action: "launch"})
	if err == nil || !strings.Contains(err.Error(), "hosted session credential required") {
		t.Fatalf("err = %v", err)
	}
}
