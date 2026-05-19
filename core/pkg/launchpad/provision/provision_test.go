package provision

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCloudIdempotencyKey(t *testing.T) {
	key := IdempotencyKey("digitalocean", "launch-1", "sha256:plan")
	if key == "" || key == IdempotencyKey("hetzner", "launch-1", "sha256:plan") {
		t.Fatal("expected provider-scoped idempotency key")
	}
}

func TestAmbiguousOutcomeRequiresReconcileBeforeRetry(t *testing.T) {
	outcome := ReconcileBeforeRetry(true)
	if outcome.Status != ReconcileRequired || outcome.RequiresRetry {
		t.Fatalf("expected reconcile-required without retry, got %+v", outcome)
	}
}

func TestDigitalOceanCreateDefaultsToDryRun(t *testing.T) {
	provisioner := DigitalOceanProvisioner{}
	result, err := provisioner.Create(context.Background(), DigitalOceanProvisionRequest{
		LaunchID: "launch-dry-run",
		PlanHash: "sha256:plan",
		Name:     "launch-dry-run",
		Region:   "nyc3",
		Size:     "s-1vcpu-1gb",
		Image:    "ubuntu-24-04-x64",
	})
	if err != nil {
		t.Fatalf("Create dry-run error = %v", err)
	}
	if !result.DryRun || result.ResourceRefs["droplet"] != "planned" || result.DropletID != 0 {
		t.Fatalf("unexpected dry-run result: %+v", result)
	}
}

func TestDigitalOceanCreatesTaggedResourcesWithIdempotency(t *testing.T) {
	var dropletChecked, firewallChecked bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("missing authorization header")
		}
		if r.Header.Get("Idempotency-Key") == "" {
			t.Fatalf("missing idempotency key")
		}
		switch r.URL.Path {
		case "/v2/droplets":
			dropletChecked = true
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode droplet body: %v", err)
			}
			if body["name"] != "launch-1" {
				t.Fatalf("unexpected droplet body: %+v", body)
			}
			tags, ok := body["tags"].([]any)
			if !ok || !containsAnyString(tags, "helm-launchpad-launch-1") {
				t.Fatalf("missing launch tag: %+v", body["tags"])
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"droplet":{"id":12345}}`))
		case "/v2/firewalls":
			firewallChecked = true
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode firewall body: %v", err)
			}
			if body["name"] != "launch-1-firewall" {
				t.Fatalf("unexpected firewall body: %+v", body)
			}
			inbound, ok := body["inbound_rules"].([]any)
			if !ok || len(inbound) != 0 {
				t.Fatalf("default firewall must not expose inbound SSH: %+v", body)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"firewall":{"id":"fw-1"}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	provisioner := DigitalOceanProvisioner{AllowLiveWrites: true, Endpoint: server.URL, Token: "test-token", HTTPClient: server.Client()}
	result, err := provisioner.Create(context.Background(), DigitalOceanProvisionRequest{
		LaunchID: "launch-1",
		PlanHash: "sha256:plan",
		Name:     "launch-1",
		Region:   "nyc3",
		Size:     "s-1vcpu-1gb",
		Image:    "ubuntu-24-04-x64",
	})
	if err != nil {
		t.Fatalf("Create error = %v", err)
	}
	if !dropletChecked || !firewallChecked {
		t.Fatalf("expected droplet and firewall calls")
	}
	if result.DropletID != 12345 || result.FirewallID != "fw-1" || result.ResourceRefs["droplet"] != "12345" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestDigitalOceanCreatesScopedSSHFirewallRule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/droplets":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"droplet":{"id":12345}}`))
		case "/v2/firewalls":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode firewall body: %v", err)
			}
			inbound, ok := body["inbound_rules"].([]any)
			if !ok || len(inbound) != 1 {
				t.Fatalf("expected one scoped inbound rule: %+v", body)
			}
			rule, ok := inbound[0].(map[string]any)
			if !ok || rule["ports"] != "22" {
				t.Fatalf("unexpected inbound rule: %+v", inbound[0])
			}
			sources, ok := rule["sources"].(map[string]any)
			if !ok {
				t.Fatalf("missing inbound sources: %+v", rule)
			}
			addresses, ok := sources["addresses"].([]any)
			if !ok || containsAnyString(addresses, "0.0.0.0/0") || !containsAnyString(addresses, "203.0.113.10/32") {
				t.Fatalf("unexpected SSH source addresses: %+v", sources["addresses"])
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"firewall":{"id":"fw-1"}}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	provisioner := DigitalOceanProvisioner{AllowLiveWrites: true, Endpoint: server.URL, Token: "test-token", HTTPClient: server.Client()}
	_, err := provisioner.Create(context.Background(), DigitalOceanProvisionRequest{
		LaunchID:       "launch-ssh",
		PlanHash:       "sha256:plan",
		Name:           "launch-ssh",
		Region:         "nyc3",
		Size:           "s-1vcpu-1gb",
		Image:          "ubuntu-24-04-x64",
		SSHKeys:        []string{"123456"},
		SSHSourceCIDRs: []string{"203.0.113.10/32"},
	})
	if err != nil {
		t.Fatalf("Create with scoped SSH error = %v", err)
	}
}

func TestDigitalOceanRejectsSSHSourceCIDRsWithoutKeys(t *testing.T) {
	provisioner := DigitalOceanProvisioner{}
	_, err := provisioner.Create(context.Background(), DigitalOceanProvisionRequest{
		LaunchID:       "launch-invalid",
		PlanHash:       "sha256:plan",
		Name:           "launch-invalid",
		Region:         "nyc3",
		Size:           "s-1vcpu-1gb",
		Image:          "ubuntu-24-04-x64",
		SSHSourceCIDRs: []string{"203.0.113.10/32"},
	})
	if err == nil {
		t.Fatal("expected ssh_source_cidrs without ssh_keys to fail")
	}
}

func TestDigitalOceanFirewallFailureRollsBackAndRequiresReconcile(t *testing.T) {
	var deleteCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v2/droplets":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"droplet":{"id":999}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v2/firewalls":
			http.Error(w, "internal error with hidden server detail", http.StatusInternalServerError)
		case r.Method == http.MethodDelete && r.URL.Path == "/v2/droplets/999":
			deleteCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	provisioner := DigitalOceanProvisioner{AllowLiveWrites: true, Endpoint: server.URL, Token: "super-secret-token", HTTPClient: server.Client()}
	_, err := provisioner.Create(context.Background(), DigitalOceanProvisionRequest{
		LaunchID: "launch-2",
		PlanHash: "sha256:plan",
		Name:     "launch-2",
		Region:   "nyc3",
		Size:     "s-1vcpu-1gb",
		Image:    "ubuntu-24-04-x64",
	})
	if err == nil {
		t.Fatal("expected firewall failure")
	}
	var doErr *DigitalOceanError
	if !errors.As(err, &doErr) {
		t.Fatalf("expected DigitalOceanError, got %T %v", err, err)
	}
	if !doErr.Ambiguous || doErr.Outcome.Status != ReconcileRequired || !deleteCalled {
		t.Fatalf("expected ambiguous reconcile-required rollback, err=%+v delete=%v", doErr, deleteCalled)
	}
	if strings.Contains(err.Error(), "super-secret-token") {
		t.Fatalf("error leaked token: %v", err)
	}
}

func TestDigitalOceanDeleteRemovesFirewallAndDroplet(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	provisioner := DigitalOceanProvisioner{AllowLiveWrites: true, Endpoint: server.URL, Token: "test-token", HTTPClient: server.Client()}
	result, err := provisioner.Delete(context.Background(), DigitalOceanDeleteRequest{
		LaunchID:   "launch-3",
		PlanHash:   "sha256:plan",
		DropletID:  42,
		FirewallID: "fw-42",
	})
	if err != nil {
		t.Fatalf("Delete error = %v", err)
	}
	if result.Status != "deleted" || result.ReceiptID == "" {
		t.Fatalf("unexpected delete result: %+v", result)
	}
	want := []string{"DELETE /v2/firewalls/fw-42", "DELETE /v2/droplets/42"}
	if strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("delete calls = %v want %v", calls, want)
	}
}

func TestDigitalOceanReconcileFindsTaggedDroplets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/droplets" || r.URL.Query().Get("tag_name") != "helm-launchpad-launch-4" {
			t.Fatalf("unexpected reconcile request: %s", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"droplets":[{"id":88,"name":"launch-4"}]}`))
	}))
	defer server.Close()

	provisioner := DigitalOceanProvisioner{Endpoint: server.URL, Token: "test-token", HTTPClient: server.Client()}
	result, err := provisioner.Reconcile(context.Background(), "launch-4")
	if err != nil {
		t.Fatalf("Reconcile error = %v", err)
	}
	if result.ResourceRefs["droplet:launch-4"] != "88" || result.Outcome.Status != ReconcileRequired {
		t.Fatalf("unexpected reconcile result: %+v", result)
	}
}

func containsAnyString(values []any, want string) bool {
	for _, value := range values {
		if got, ok := value.(string); ok && got == want {
			return true
		}
	}
	return false
}
