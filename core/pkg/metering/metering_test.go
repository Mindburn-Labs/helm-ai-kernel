package metering

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func testSubject() Subject {
	return Subject{TenantID: "tenant-a", WorkspaceID: "workspace-a", PrincipalID: "principal-a"}
}

func testAuthorizationRequest() AuthorizationRequest {
	return AuthorizationRequest{
		Subject:           testSubject(),
		Ingress:           IngressOpenAIProxy,
		DecisionReceiptID: "rcpt-decision",
	}
}

func TestDisabledDoesNotEnableHostedMetering(t *testing.T) {
	if (Disabled{}).Enabled() {
		t.Fatal("disabled meter must remain off")
	}
}

func TestFromEnvironmentRequiresExplicitActivation(t *testing.T) {
	t.Setenv(ControlPlaneURLEnv, "http://metering.example")
	client, err := FromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if client.Enabled() {
		t.Fatal("metering must stay disabled until an operator explicitly activates it")
	}
	t.Setenv(ActivationEnv, "1")
	if _, err := FromEnvironment(); err == nil {
		t.Fatal("an activated meter requires a service token")
	}
	t.Setenv(ServiceTokenEnv, "service-token")
	client, err = FromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if !client.Enabled() {
		t.Fatal("metering must enable only with the explicit activation gate")
	}
}

func TestFromEnvironmentRejectsInvalidActivationGate(t *testing.T) {
	t.Setenv(ControlPlaneURLEnv, "http://metering.example")
	t.Setenv(ServiceTokenEnv, "service-token")
	t.Setenv(ActivationEnv, "yes")
	if _, err := FromEnvironment(); err == nil {
		t.Fatal("invalid activation gate must fail closed")
	}
}

func TestHTTPClientUsesReceiptOnlyContract(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		if got := r.Header.Get("Authorization"); got != "Bearer service-token" {
			t.Fatalf("authorization=%q", got)
		}
		for _, header := range []string{"X-Helm-Tenant-ID", "X-Helm-Workspace-ID", "X-Helm-Principal-ID"} {
			if got := r.Header.Get(header); got != "" {
				t.Fatalf("scope header %s must not be forwarded, got %q", header, got)
			}
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		switch r.URL.Path {
		case authorizePath:
			if want := map[string]any{"ingress": IngressOpenAIProxy, "decision_receipt_id": "rcpt-decision"}; !reflect.DeepEqual(payload, want) {
				t.Fatalf("authorize payload=%#v want=%#v", payload, want)
			}
			if got := r.Header.Get("Idempotency-Key"); got != "authorize:rcpt-decision" {
				t.Fatalf("authorize idempotency=%q", got)
			}
			_, _ = w.Write([]byte(`{"authorization_id":"auth-1","approved":true}`))
		case settlePath:
			if want := map[string]any{"authorization_id": "auth-1", "settlement_receipt_id": "rcpt-settlement"}; !reflect.DeepEqual(payload, want) {
				t.Fatalf("settle payload=%#v want=%#v", payload, want)
			}
			if got := r.Header.Get("Idempotency-Key"); got != "settle:rcpt-settlement" {
				t.Fatalf("settle idempotency=%q", got)
			}
			_, _ = w.Write([]byte(`{"settlement_id":"settle-1","settled":true}`))
		default:
			t.Fatalf("unexpected route %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewHTTPClient(Config{BaseURL: server.URL, ServiceToken: "service-token"})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := client.Authorize(context.Background(), testAuthorizationRequest())
	if err != nil {
		t.Fatal(err)
	}
	if authorization.AuthorizationID != "auth-1" {
		t.Fatalf("authorization=%#v", authorization)
	}
	_, err = client.Settle(context.Background(), SettlementRequest{
		Subject:             testSubject(),
		AuthorizationID:     authorization.AuthorizationID,
		SettlementReceiptID: "rcpt-settlement",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, ","); got != authorizePath+","+settlePath {
		t.Fatalf("calls=%s", got)
	}
}

func TestHTTPClientRejectsUnapprovedAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"authorization_id":"auth-1","approved":false}`))
	}))
	defer server.Close()
	client, err := NewHTTPClient(Config{BaseURL: server.URL, ServiceToken: "service-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Authorize(context.Background(), testAuthorizationRequest()); err == nil {
		t.Fatal("unapproved authorization must fail closed")
	}
}

func TestReceiptOnlyRequestsCannotSerializeClientSelectedPricing(t *testing.T) {
	body, err := json.Marshal(testAuthorizationRequest())
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"tenant_id", "workspace_id", "principal_id", "charge_class", "credits", "value", "connector", "oem", "pricing"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("receipt-only authorization serialized forbidden field %q: %s", forbidden, body)
		}
	}
	settlementBody, err := json.Marshal(SettlementRequest{Subject: testSubject(), AuthorizationID: "auth-1", SettlementReceiptID: "rcpt-settlement"})
	if err != nil {
		t.Fatal(err)
	}
	if string(settlementBody) != `{"authorization_id":"auth-1","settlement_receipt_id":"rcpt-settlement"}` {
		t.Fatalf("settlement body=%s", settlementBody)
	}
}

func TestReceiptOnlyRequestsRequireVerifiedSubjectAndReceipt(t *testing.T) {
	if err := (AuthorizationRequest{Ingress: IngressMCP, DecisionReceiptID: "rcpt-1"}).Validate(); err == nil {
		t.Fatal("authorization without verified subject must fail")
	}
	if err := (SettlementRequest{Subject: testSubject(), AuthorizationID: "auth-1"}).Validate(); err == nil {
		t.Fatal("settlement without receipt must fail")
	}
	if err := (SettlementRequest{Subject: testSubject(), SettlementReceiptID: "rcpt-1"}).Validate(); err == nil {
		t.Fatal("settlement without server-issued authorization must fail")
	}
}
