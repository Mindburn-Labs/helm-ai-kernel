// Package custody is the effect gateway's connection custody (target
// architecture §9.6, R8): the only place a provider credential exists. The
// adapters ask it for one per call and never keep it.
//
// GitHubApp mints GitHub App installation tokens. A tenant gets a token only
// for a repository its installation entry allows, and each token is scoped
// to that one repository, so a token handed to the adapter cannot reach any
// other.
package custody

// quantum_posture: the GitHub App JWT is RS256 (classical), the only
// algorithm GitHub accepts for App authentication; installation tokens are
// opaque bearer strings. No post-quantum claim is made.

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// The files the gateway chart mounts into the gateway Pod only (PR #1065),
// and the API root.
const (
	EnvGitHubAppIDFile         = "HELM_GATEWAY_GITHUB_APP_ID_FILE"
	EnvGitHubPrivateKeyFile    = "HELM_GATEWAY_GITHUB_APP_PRIVATE_KEY_FILE"
	EnvGitHubInstallationsFile = "HELM_GATEWAY_GITHUB_INSTALLATIONS_FILE"
	// EnvGitHubAPIURL overrides https://api.github.com, for GitHub
	// Enterprise Server. It must be https, or http on a loopback address.
	EnvGitHubAPIURL = "HELM_GATEWAY_GITHUB_API_URL"
)

const (
	defaultAPIURL = "https://api.github.com"
	apiVersion    = "2022-11-28"
	// A cached token is used until this long before GitHub's expiry, so no
	// call starts with a token about to lapse.
	refreshBefore = 5 * time.Minute
	maxAnswer     = 64 << 10
)

// Installation is one entry of the installations file: the GitHub App
// installation a tenant uses for one owner, and the repositories
// ("owner/name") it may act on.
type Installation struct {
	TenantID       string   `json:"tenant_id"`
	Owner          string   `json:"owner"`
	InstallationID int64    `json:"installation_id"`
	Repositories   []string `json:"repositories"`
}

type installationsFile struct {
	Installations []Installation `json:"installations"`
}

// GitHubApp mints installation tokens for one GitHub App.
type GitHubApp struct {
	appID   string
	key     *rsa.PrivateKey
	baseURL string
	client  *http.Client
	now     func() time.Time
	// by tenant, then lower-case owner
	installations map[string]map[string]Installation

	mu    sync.Mutex
	cache map[cacheKey]cachedToken
}

type cacheKey struct {
	installation int64
	repository   string
}

type cachedToken struct {
	token   string
	expires time.Time
}

// GitHubAPIURL returns the GitHub API root the gateway uses.
func GitHubAPIURL(getenv func(string) string) (string, error) {
	raw := strings.TrimSpace(getenv(EnvGitHubAPIURL))
	if raw == "" {
		return defaultAPIURL, nil
	}
	u, err := url.Parse(raw)
	plainLoopback := u != nil && u.Scheme == "http" && loopback(u.Hostname())
	if err != nil || u.Host == "" || (u.Scheme != "https" && !plainLoopback) {
		return "", fmt.Errorf("%s must be an https URL (http only on a loopback address)", EnvGitHubAPIURL)
	}
	return strings.TrimRight(raw, "/"), nil
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

// GitHubAppFromEnv reads the App ID, private key and installations files the
// environment names. All three are set or none is; none returns nil.
func GitHubAppFromEnv(getenv func(string) string) (*GitHubApp, error) {
	names := []string{EnvGitHubAppIDFile, EnvGitHubPrivateKeyFile, EnvGitHubInstallationsFile}
	var paths []string
	for _, name := range names {
		if p := strings.TrimSpace(getenv(name)); p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return nil, nil
	}
	if len(paths) != len(names) {
		return nil, fmt.Errorf("set all of %s or none", strings.Join(names, ", "))
	}
	var contents [3][]byte
	for i, p := range paths {
		b, err := os.ReadFile(p) // #nosec G304 -- operator-configured secret mount paths
		if err != nil {
			return nil, fmt.Errorf("%s: %w", names[i], err)
		}
		contents[i] = b
	}
	baseURL, err := GitHubAPIURL(getenv)
	if err != nil {
		return nil, err
	}
	return NewGitHubApp(strings.TrimSpace(string(contents[0])), contents[1], contents[2], baseURL)
}

// NewGitHubApp builds the custody for one App: its numeric ID, its PEM
// private key (PKCS#1 or PKCS#8) and the installations file.
func NewGitHubApp(appID string, keyPEM, installationsJSON []byte, baseURL string) (*GitHubApp, error) {
	if id, err := strconv.ParseInt(appID, 10, 64); err != nil || id <= 0 {
		return nil, errors.New("the GitHub App ID must be a positive integer")
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyPEM)
	if err != nil {
		return nil, errors.New("the GitHub App private key is not an RSA PEM key")
	}
	var file installationsFile
	dec := json.NewDecoder(bytes.NewReader(installationsJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("the installations file: %w", err)
	}
	g := &GitHubApp{appID: appID, key: key, baseURL: strings.TrimRight(baseURL, "/"),
		client:        &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		now:           time.Now,
		installations: map[string]map[string]Installation{},
		cache:         map[cacheKey]cachedToken{},
	}
	for i, in := range file.Installations {
		owner := strings.ToLower(in.Owner)
		switch {
		case in.TenantID == "" || in.Owner == "" || in.InstallationID <= 0:
			return nil, fmt.Errorf("installation %d needs tenant_id, owner and a positive installation_id", i)
		case g.installations[in.TenantID][owner].InstallationID != 0:
			return nil, fmt.Errorf("installation %d repeats tenant %q and owner %q", i, in.TenantID, in.Owner)
		}
		for _, repo := range in.Repositories {
			o, name, ok := strings.Cut(repo, "/")
			if !ok || name == "" || strings.Contains(name, "/") || !strings.EqualFold(o, in.Owner) {
				return nil, fmt.Errorf("installation %d: repository %q is not %s/{name}", i, repo, in.Owner)
			}
		}
		if g.installations[in.TenantID] == nil {
			g.installations[in.TenantID] = map[string]Installation{}
		}
		g.installations[in.TenantID][owner] = in
	}
	return g, nil
}

// Token returns an installation token for the one repository the effect
// targets, when the tenant's installation allows it (admission.Credentials).
// The token is never logged.
func (g *GitHubApp) Token(ctx context.Context, tenantID string, effect adapters.Effect) (string, error) {
	owner, name, ok := strings.Cut(strings.TrimPrefix(effect.Target, "github.com/"), "/")
	if !strings.HasPrefix(effect.Target, "github.com/") || !ok || name == "" {
		return "", fmt.Errorf("target %q is not a GitHub repository", effect.Target)
	}
	in, ok := g.installations[tenantID][strings.ToLower(owner)]
	if !ok || !allowed(in.Repositories, owner+"/"+name) {
		return "", fmt.Errorf("tenant %q has no GitHub App installation allowing %s/%s", tenantID, owner, name)
	}
	key := cacheKey{installation: in.InstallationID, repository: strings.ToLower(name)}
	g.mu.Lock()
	defer g.mu.Unlock()
	if c, ok := g.cache[key]; ok && g.now().Add(refreshBefore).Before(c.expires) {
		return c.token, nil
	}
	token, expires, err := g.mint(ctx, in.InstallationID, name)
	if err != nil {
		return "", err
	}
	g.cache[key] = cachedToken{token: token, expires: expires}
	return token, nil
}

func allowed(repositories []string, repo string) bool {
	for _, r := range repositories {
		if strings.EqualFold(r, repo) {
			return true
		}
	}
	return false
}

// mint signs the App JWT and exchanges it for an installation token scoped
// to repository.
func (g *GitHubApp) mint(ctx context.Context, installationID int64, repository string) (string, time.Time, error) {
	now := g.now()
	appJWT, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer: g.appID,
		// GitHub allows 60 s of clock drift back and 10 min of lifetime.
		IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}).SignedString(g.key)
	if err != nil {
		return "", time.Time{}, err
	}
	body, err := json.Marshal(map[string][]string{"repositories": {repository}})
	if err != nil {
		return "", time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/app/installations/%d/access_tokens", g.baseURL, installationID), bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("minting an installation token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil || len(raw) > maxAnswer {
		return "", time.Time{}, errors.New("minting an installation token: the answer is unreadable or too large")
	}
	if resp.StatusCode != http.StatusCreated {
		return "", time.Time{}, fmt.Errorf("minting an installation token: GitHub answered %d", resp.StatusCode)
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Token == "" || out.ExpiresAt.IsZero() {
		return "", time.Time{}, errors.New("minting an installation token: the answer carries no token and expiry")
	}
	return out.Token, out.ExpiresAt, nil
}
