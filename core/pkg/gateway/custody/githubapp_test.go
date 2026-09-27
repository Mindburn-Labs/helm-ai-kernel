package custody

// quantum_posture: generates a throwaway RSA key and verifies classical
// RS256 test JWTs; no post-quantum claim.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

const installations = `{"installations":[
	{"tenant_id":"tenant-a","owner":"Mindburn-Labs","installation_id":41,"repositories":["Mindburn-Labs/example","mindburn-labs/other"]},
	{"tenant_id":"tenant-b","owner":"Mindburn-Labs","installation_id":42,"repositories":["Mindburn-Labs/b-only"]}
]}`

// fakeGitHubApps answers POST /app/installations/{id}/access_tokens for a
// JWT signed by key, the way GitHub does.
type fakeGitHubApps struct {
	t       *testing.T
	key     *rsa.PrivateKey
	server  *httptest.Server
	mu      sync.Mutex
	minted  []string // "installation:repository"
	expires time.Duration
}

func newFakeGitHubApps(t *testing.T) *fakeGitHubApps {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGitHubApps{t: t, key: key, expires: time.Hour}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var installation int64
		if _, err := fmt.Sscanf(r.URL.Path, "/app/installations/%d/access_tokens", &installation); err != nil || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		var claims jwt.RegisteredClaims
		token, err := jwt.ParseWithClaims(raw, &claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
			jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("1234"))
		if err != nil || !token.Valid || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > 10*time.Minute {
			http.Error(w, `{"message":"A JSON web token could not be decoded"}`, http.StatusUnauthorized)
			return
		}
		var body struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Repositories) != 1 {
			http.Error(w, `{"message":"one repository"}`, http.StatusUnprocessableEntity)
			return
		}
		f.mu.Lock()
		f.minted = append(f.minted, fmt.Sprintf("%d:%s", installation, body.Repositories[0]))
		n := len(f.minted)
		expires := f.expires
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": fmt.Sprintf("ghs_minted_%d", n), "expires_at": time.Now().Add(expires).UTC()})
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeGitHubApps) keyPEM(pkcs8 bool) []byte {
	if pkcs8 {
		der, err := x509.MarshalPKCS8PrivateKey(f.key)
		if err != nil {
			f.t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.key)})
}

func (f *fakeGitHubApps) mintedList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.minted...)
}

func effect(target string) adapters.Effect {
	return adapters.Effect{EffectType: "github.branch.create_from_changes", Target: target}
}

func TestGitHubAppMintsRepositoryScopedTokensAndCachesThem(t *testing.T) {
	f := newFakeGitHubApps(t)
	app, err := NewGitHubApp("1234", f.keyPEM(false), []byte(installations), f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	token, err := app.Token(ctx, "tenant-a", effect("github.com/Mindburn-Labs/example"))
	if err != nil || token != "ghs_minted_1" {
		t.Fatalf("Token = %q, %v", token, err)
	}
	// Cached until shortly before expiry: a second effect on the repository
	// mints nothing.
	again, err := app.Token(ctx, "tenant-a", effect("github.com/Mindburn-Labs/example"))
	if err != nil || again != token {
		t.Fatalf("a cached token = %q, %v", again, err)
	}
	// Owner and repository match case-insensitively, as GitHub names do.
	if _, err := app.Token(ctx, "tenant-a", effect("github.com/mindburn-labs/Other")); err != nil {
		t.Fatal(err)
	}
	if got := f.mintedList(); len(got) != 2 || got[0] != "41:example" || got[1] != "41:Other" {
		t.Fatalf("minted %v, want one token per repository, each scoped to it", got)
	}
	// A token inside the refresh margin is minted again.
	app.now = func() time.Time { return time.Now().Add(56 * time.Minute) }
	if fresh, err := app.Token(ctx, "tenant-a", effect("github.com/Mindburn-Labs/example")); err != nil || fresh == token {
		t.Fatalf("a token near expiry was reused: %q, %v", fresh, err)
	}
}

func TestGitHubAppRefusesRepositoriesOutsideTheTenantsAllowlist(t *testing.T) {
	f := newFakeGitHubApps(t)
	app, err := NewGitHubApp("1234", f.keyPEM(true), []byte(installations), f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for name, c := range map[string]struct{ tenant, target string }{
		"another tenant's repository": {"tenant-a", "github.com/Mindburn-Labs/b-only"},
		"a repository nobody allows":  {"tenant-a", "github.com/Mindburn-Labs/secret"},
		"another owner":               {"tenant-a", "github.com/evil/example"},
		"an unknown tenant":           {"tenant-c", "github.com/Mindburn-Labs/example"},
		"tenant b on a's repository":  {"tenant-b", "github.com/Mindburn-Labs/example"},
		"not a GitHub target":         {"tenant-a", "gitlab.com/Mindburn-Labs/example"},
		"no repository":               {"tenant-a", "github.com/Mindburn-Labs"},
	} {
		if token, err := app.Token(ctx, c.tenant, effect(c.target)); err == nil || token != "" {
			t.Errorf("%s: minted %q", name, token)
		}
	}
	if got := f.mintedList(); len(got) != 0 {
		t.Fatalf("refused calls reached GitHub: %v", got)
	}
	// Known good after the refusals.
	if _, err := app.Token(ctx, "tenant-b", effect("github.com/Mindburn-Labs/b-only")); err != nil {
		t.Fatal(err)
	}
	// A key GitHub does not accept is an error, never a token.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := NewGitHubApp("1234", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(other)}),
		[]byte(installations), f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if token, err := wrong.Token(ctx, "tenant-a", effect("github.com/Mindburn-Labs/example")); err == nil || token != "" {
		t.Fatalf("a rejected App key minted %q", token)
	}
}

func TestGitHubAppConfiguration(t *testing.T) {
	f := newFakeGitHubApps(t)
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	env := map[string]string{
		EnvGitHubAppIDFile:         write("app-id", "1234\n"),
		EnvGitHubPrivateKeyFile:    write("private-key.pem", string(f.keyPEM(false))),
		EnvGitHubInstallationsFile: write("installations.json", installations),
		EnvGitHubAPIURL:            f.server.URL,
	}
	getenv := func(k string) string { return env[k] }
	app, err := GitHubAppFromEnv(getenv)
	if err != nil || app == nil {
		t.Fatalf("GitHubAppFromEnv = %v, %v", app, err)
	}
	if _, err := app.Token(context.Background(), "tenant-a", effect("github.com/Mindburn-Labs/example")); err != nil {
		t.Fatal(err)
	}
	if app, err := GitHubAppFromEnv(func(string) string { return "" }); app != nil || err != nil {
		t.Fatalf("no configuration = %v, %v, want none", app, err)
	}
	partial := map[string]string{EnvGitHubAppIDFile: env[EnvGitHubAppIDFile]}
	if _, err := GitHubAppFromEnv(func(k string) string { return partial[k] }); err == nil {
		t.Fatal("a partial configuration was accepted")
	}

	key := f.keyPEM(false)
	for name, c := range map[string]struct {
		appID, installations string
		key                  []byte
	}{
		"a non-numeric App ID":   {"app", installations, key},
		"not a key":              {"1234", installations, []byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")},
		"an unknown field":       {"1234", `{"installations":[],"extra":1}`, key},
		"a missing tenant":       {"1234", `{"installations":[{"owner":"o","installation_id":1}]}`, key},
		"another owner's repo":   {"1234", `{"installations":[{"tenant_id":"t","owner":"o","installation_id":1,"repositories":["x/r"]}]}`, key},
		"a nested repo path":     {"1234", `{"installations":[{"tenant_id":"t","owner":"o","installation_id":1,"repositories":["o/r/s"]}]}`, key},
		"a repeated tenant pair": {"1234", `{"installations":[{"tenant_id":"t","owner":"o","installation_id":1},{"tenant_id":"t","owner":"O","installation_id":2}]}`, key},
	} {
		if _, err := NewGitHubApp(c.appID, c.key, []byte(c.installations), f.server.URL); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for raw, ok := range map[string]bool{
		"":                           true,
		"https://ghe.example/api/v3": true,
		"http://127.0.0.1:8080":      true,
		"http://ghe.example/api/v3":  false,
		"ftp://ghe.example":          false,
		"https://":                   false,
	} {
		_, err := GitHubAPIURL(func(string) string { return raw })
		if (err == nil) != ok {
			t.Errorf("GitHubAPIURL(%q) err = %v, want ok=%v", raw, err, ok)
		}
	}
}
