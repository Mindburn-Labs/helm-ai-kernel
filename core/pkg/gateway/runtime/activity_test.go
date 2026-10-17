package runtime

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	testkit "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/testkit/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/activitytrail"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

type activityCredentials struct {
	t     *testing.T
	token string
}

func (c activityCredentials) Token(_ context.Context, tenant string, effect adapters.Effect) (string, error) {
	c.t.Helper()
	if tenant != "tenant-a" || effect.EffectType != "github.repository.get" || effect.Target != "github.com/Acme/widget" {
		c.t.Fatalf("activity requested credential outside its configured source: tenant=%q type=%q target=%q", tenant, effect.EffectType, effect.Target)
	}
	return c.token, nil
}

func TestActivityRuntimeRejectsUnboundSourcesAndUnsignedIngress(t *testing.T) {
	db, err := sqlOpen("postgres://127.0.0.1:1/none?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	path := filepath.Join(t.TempDir(), "sources.json")
	write := func(raw string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"sources":[{"tenant_id":"tenant-a","workspace_id":"workspace-a","repository":"github.com/Acme/widget","enabled":true}]}`)
	if _, err := newActivityRuntime(db, env(map[string]string{envActivitySourcesFile: path}), nil); err == nil || !strings.Contains(err.Error(), "GitHub App credentials") {
		t.Fatalf("enabled source without custody = %v", err)
	}
	write(`{"sources":[{"tenant_id":"tenant-a","workspace_id":"workspace-a","repository":"github.com/Acme/widget","enabled":false}]}`)
	secret := filepath.Join(t.TempDir(), "webhook-secret")
	if err := os.WriteFile(secret, []byte("test-webhook-secret-at-least-sixteen-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := newActivityRuntime(db, env(map[string]string{envActivitySourcesFile: path, envActivityWebhookSecretFile: secret}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newActivityRuntime(db, env(map[string]string{envActivitySourcesFile: path,
		"HELM_GATEWAY_GITHUB_API_URL": "https://ghe.example.internal/api/v3"}), nil); err != nil {
		t.Fatalf("GitHub Enterprise API root: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/internal/github/activity", strings.NewReader(`{"repository":{"full_name":"Acme/widget"}}`))
	request.Header.Set("X-GitHub-Event", "push")
	response := httptest.NewRecorder()
	a.webhook.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned delivery = %d", response.Code)
	}
	write(`{"sources":[{"tenant_id":"tenant-a","workspace_id":"workspace-a","repository":"github.com/Acme/widget","enabled":false},{"tenant_id":"tenant-a","workspace_id":"workspace-a","repository":"github.com/acme/widget","enabled":false}]}`)
	if _, err := newActivityRuntime(db, env(map[string]string{envActivitySourcesFile: path}), nil); err == nil || !strings.Contains(err.Error(), "repeats") {
		t.Fatalf("duplicate source scope = %v", err)
	}
}

func TestPostgresActivityRuntimePollAndSignedIngress(t *testing.T) {
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run activity runtime proof")
	}
	admin, err := sqlOpen(base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("helm_activity_runtime_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) }()
	parsed, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	q.Set("search_path", schema)
	parsed.RawQuery = q.Encode()
	if err := Run(context.Background(), []string{"migrate"}, env(map[string]string{envDatabaseURL: parsed.String()}), io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`INSERT INTO ` + schema + `.authority_tenants(tenant_id) VALUES ('tenant-a')`); err != nil {
		t.Fatal(err)
	}
	db, err := sqlOpen(parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	provider := testkit.NewFakeGitHubFor(t, "Acme", "widget")
	sources := filepath.Join(t.TempDir(), "activity-sources.json")
	if err := os.WriteFile(sources, []byte(`{"sources":[{"tenant_id":"tenant-a","workspace_id":"workspace-a","repository":"github.com/Acme/widget","enabled":true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := []byte("test-webhook-secret-at-least-sixteen-bytes")
	secretFile := filepath.Join(t.TempDir(), "activity-secret")
	if err := os.WriteFile(secretFile, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := newActivityRuntime(db, env(map[string]string{
		envActivitySourcesFile: sources, envActivityWebhookSecretFile: secretFile,
		"HELM_GATEWAY_GITHUB_API_URL": provider.URL(),
	}), activityCredentials{t: t, token: provider.Token()})
	if err != nil {
		t.Fatal(err)
	}
	scope := activitytrail.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a", Repository: "github.com/Acme/widget"}
	before := provider.BaseSHA()
	a.pollOnce(context.Background())
	coverage, err := a.trail.CoverageMap(context.Background(), scope)
	if err != nil || !coverage.Enabled || coverage.HeadSHA != before {
		t.Fatalf("source baseline: coverage=%+v error=%v", coverage, err)
	}
	after := provider.AdvanceBranch("main")
	a.pollOnce(context.Background())
	observations, _, err := a.trail.ListObservations(context.Background(), scope, activitytrail.Page{})
	if err != nil || len(observations) != 1 || observations[0].BeforeSHA != before || observations[0].AfterSHA != after {
		t.Fatalf("periodic provider observation: items=%+v error=%v", observations, err)
	}
	body := fmt.Sprintf(`{"ref":"refs/heads/main","before":%q,"after":%q,"repository":{"full_name":"Acme/widget"},"sender":{"login":"outside-user"}}`, before, after)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(body))
	request := httptest.NewRequest(http.MethodPost, "/internal/github/activity", strings.NewReader(body))
	request.Header.Set("X-GitHub-Event", "push")
	request.Header.Set("X-GitHub-Delivery", "delivery-one")
	request.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response := httptest.NewRecorder()
	a.webhook.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("signed delivery = %d %q", response.Code, response.Body.String())
	}
	observations, _, err = a.trail.ListObservations(context.Background(), scope, activitytrail.Page{})
	if err != nil || len(observations) != 1 || observations[0].ActorLogin != "outside-user" {
		t.Fatalf("signed actor attribution: items=%+v error=%v", observations, err)
	}
	disabled := false
	a.sources[0].Enabled = &disabled
	a.pollOnce(context.Background())
	coverage, err = a.trail.CoverageMap(context.Background(), scope)
	if err != nil || coverage.Enabled || coverage.Class != activitytrail.CoverageUnmanaged {
		t.Fatalf("disabled source classification: coverage=%+v error=%v", coverage, err)
	}
	observations, _, err = a.trail.ListObservations(context.Background(), scope, activitytrail.Page{})
	if err != nil || len(observations) != 1 {
		t.Fatalf("disabled source lost history: items=%+v error=%v", observations, err)
	}
}
