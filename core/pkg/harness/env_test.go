package harness

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// seededProviderEnv is an operator environment with credentials for many
// providers present at once, which is the normal state of a developer
// workstation and the condition the fence has to survive.
func seededProviderEnv() []string {
	return []string{
		"ANTHROPIC_API_KEY=sk-ant-seed",
		"ANTHROPIC_BASE_URL=https://proxy.invalid/anthropic",
		"ANTHROPIC_AUTH_TOKEN=seed",
		"CLAUDE_CODE_OAUTH_TOKEN=seed",
		"OPENAI_API_KEY=sk-openai-seed",
		"OPENAI_BASE_URL=https://proxy.invalid/openai",
		"OPENAI_ORGANIZATION=org-seed",
		"AWS_ACCESS_KEY_ID=akid-seed",
		"AWS_SECRET_ACCESS_KEY=secret-seed",
		"AWS_SESSION_TOKEN=session-seed",
		"GOOGLE_API_KEY=google-seed",
		"GOOGLE_APPLICATION_CREDENTIALS=/tmp/creds.json",
		"GEMINI_API_KEY=gemini-seed",
		"AZURE_OPENAI_API_KEY=azure-seed",
		"MISTRAL_API_KEY=mistral-seed",
		"COHERE_API_KEY=cohere-seed",
		"GROQ_API_KEY=groq-seed",
		"XAI_API_KEY=xai-seed",
		"DEEPSEEK_API_KEY=deepseek-seed",
		"OPENROUTER_API_KEY=openrouter-seed",
		"PERPLEXITY_API_KEY=perplexity-seed",
		"TOGETHER_API_KEY=together-seed",
		"FIREWORKS_API_KEY=fireworks-seed",
		"HF_TOKEN=hf-seed",
		"HUGGINGFACE_HUB_TOKEN=hf-hub-seed",
		"REPLICATE_API_TOKEN=replicate-seed",
		"VERTEX_PROJECT=vertex-seed",
		"BEDROCK_ENDPOINT_URL=https://bedrock.invalid",
		"OLLAMA_HOST=http://localhost:11434",

		// Providers this package has never heard of, caught by convention.
		"ACMELLM_API_KEY=acme-seed",
		"ACMELLM_BASE_URL=https://acme.invalid",
		"WIDGETS_TOKEN=widget-seed",
		"THING_SECRET=thing-seed",
		"OTHER_API_BASE=https://other.invalid",

		// Must survive: the run has no egress at all without these.
		"PATH=/usr/bin:/bin",
		"LANG=en_US.UTF-8",
		"LC_ALL=en_US.UTF-8",
		"TERM=xterm-256color",
		"TZ=UTC",
		"HTTP_PROXY=http://proxy.corp:3128",
		"HTTPS_PROXY=http://proxy.corp:3128",
		"NO_PROXY=localhost,127.0.0.1",
		"http_proxy=http://proxy.corp:3128",
		"https_proxy=http://proxy.corp:3128",
		"no_proxy=localhost,127.0.0.1",
		"NODE_EXTRA_CA_CERTS=/etc/ssl/corp.pem",
		"SSL_CERT_FILE=/etc/ssl/cert.pem",
		"SSL_CERT_DIR=/etc/ssl/certs",
		"REQUESTS_CA_BUNDLE=/etc/ssl/corp.pem",
	}
}

func envNames(env []string) []string {
	names := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, ok := strings.Cut(entry, "=")
		if ok {
			names = append(names, name)
		}
	}
	return names
}

func lookup(env []string, name string) (string, bool) {
	for _, entry := range env {
		if key, value, ok := strings.Cut(entry, "="); ok && key == name {
			return value, true
		}
	}
	return "", false
}

func TestScrubProviderEnvRemovesEveryProviderCredential(t *testing.T) {
	scrubbed := ScrubProviderEnv(seededProviderEnv())
	names := envNames(scrubbed)

	mustBeGone := []string{
		"ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN",
		"CLAUDE_CODE_OAUTH_TOKEN",
		"OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_ORGANIZATION",
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS", "GEMINI_API_KEY",
		"AZURE_OPENAI_API_KEY", "MISTRAL_API_KEY", "COHERE_API_KEY",
		"GROQ_API_KEY", "XAI_API_KEY", "DEEPSEEK_API_KEY", "OPENROUTER_API_KEY",
		"PERPLEXITY_API_KEY", "TOGETHER_API_KEY", "FIREWORKS_API_KEY",
		"HF_TOKEN", "HUGGINGFACE_HUB_TOKEN", "REPLICATE_API_TOKEN",
		"VERTEX_PROJECT", "BEDROCK_ENDPOINT_URL", "OLLAMA_HOST",
		"ACMELLM_API_KEY", "ACMELLM_BASE_URL", "WIDGETS_TOKEN",
		"THING_SECRET", "OTHER_API_BASE",
	}
	for _, name := range mustBeGone {
		if slices.Contains(names, name) {
			t.Errorf("ScrubProviderEnv kept provider variable %s", name)
		}
	}

	mustSurvive := []string{
		"PATH", "LANG", "LC_ALL", "TERM", "TZ",
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
		"http_proxy", "https_proxy", "no_proxy",
		"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
	}
	for _, name := range mustSurvive {
		if !slices.Contains(names, name) {
			t.Errorf("ScrubProviderEnv dropped %s; the run would have no egress or no trust store", name)
		}
	}
}

func TestScrubProviderEnvDropsMalformedEntries(t *testing.T) {
	scrubbed := ScrubProviderEnv([]string{"PATH=/bin", "NOT_AN_ASSIGNMENT", "=orphan"})
	if len(scrubbed) != 1 || scrubbed[0] != "PATH=/bin" {
		t.Fatalf("expected only the well-formed assignment, got %v", scrubbed)
	}
}

// TestComposeEnvFencesTheUnselectedProvider is the cross-provider leak case: a
// run routed to one provider must not be able to reach the other's credentials.
func TestComposeEnvFencesTheUnselectedProvider(t *testing.T) {
	tests := []struct {
		name       string
		route      CredentialRoute
		wantVar    string
		wantSecret string
		wantGone   []string
	}{
		{
			name:       "routed to openai",
			route:      CredentialRoute{ID: "route-openai", EnvVar: "OPENAI_API_KEY", Secret: "sk-openai-routed"},
			wantVar:    "OPENAI_API_KEY",
			wantSecret: "sk-openai-routed",
			wantGone: []string{
				"ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN",
				"CLAUDE_CODE_OAUTH_TOKEN", "OPENAI_BASE_URL", "AWS_SECRET_ACCESS_KEY",
			},
		},
		{
			name:       "routed to anthropic",
			route:      CredentialRoute{ID: "route-anthropic", EnvVar: "ANTHROPIC_API_KEY", Secret: "sk-ant-routed"},
			wantVar:    "ANTHROPIC_API_KEY",
			wantSecret: "sk-ant-routed",
			wantGone: []string{
				"OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_ORGANIZATION",
				"ANTHROPIC_BASE_URL", "GEMINI_API_KEY", "AWS_SECRET_ACCESS_KEY",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, err := ComposeEnv(seededProviderEnv(), RunSpec{
				Tree:       "/runtime/tree",
				HomeDir:    "/runtime/home",
				Credential: tt.route,
			})
			if err != nil {
				t.Fatalf("ComposeEnv: %v", err)
			}

			secret, ok := lookup(env, tt.wantVar)
			if !ok {
				t.Fatalf("selected route variable %s is missing from the child environment", tt.wantVar)
			}
			if secret != tt.wantSecret {
				t.Errorf("%s = %q, want the routed secret %q (the seeded value leaked through)", tt.wantVar, secret, tt.wantSecret)
			}
			for _, name := range tt.wantGone {
				if _, present := lookup(env, name); present {
					t.Errorf("unselected provider variable %s reached the child", name)
				}
			}
			if _, ok := lookup(env, "HTTP_PROXY"); !ok {
				t.Error("HTTP_PROXY did not survive composition")
			}
			if _, ok := lookup(env, "NODE_EXTRA_CA_CERTS"); !ok {
				t.Error("NODE_EXTRA_CA_CERTS did not survive composition")
			}
		})
	}
}

func TestComposeEnvAppliesScopedHome(t *testing.T) {
	env, err := ComposeEnv([]string{"HOME=/Users/operator", "PATH=/bin"}, RunSpec{
		Tree:    "/runtime/tree",
		HomeDir: "/runtime/home",
	})
	if err != nil {
		t.Fatalf("ComposeEnv: %v", err)
	}

	want := map[string]string{
		"HOME":              "/runtime/home",
		"XDG_CONFIG_HOME":   "/runtime/home/.config",
		"CLAUDE_CONFIG_DIR": "/runtime/home/.claude",
		"CODEX_HOME":        "/runtime/home/.codex",
	}
	for name, value := range want {
		got, ok := lookup(env, name)
		if !ok {
			t.Errorf("%s missing from composed environment", name)
			continue
		}
		if got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

// TestComposeEnvScrubsExtraEnv keeps ExtraEnv from becoming the hole in the
// fence: the credential route is the only sanctioned way in.
func TestComposeEnvScrubsExtraEnv(t *testing.T) {
	env, err := ComposeEnv([]string{"PATH=/bin"}, RunSpec{
		Tree:    "/runtime/tree",
		HomeDir: "/runtime/home",
		ExtraEnv: map[string]string{
			"OPENAI_API_KEY":    "sk-smuggled",
			"ANTHROPIC_API_KEY": "sk-smuggled-too",
			"HELM_RUN_ID":       "run-1",
		},
		Credential: CredentialRoute{ID: "route-anthropic", EnvVar: "ANTHROPIC_API_KEY", Secret: "sk-routed"},
	})
	if err != nil {
		t.Fatalf("ComposeEnv: %v", err)
	}

	if _, present := lookup(env, "OPENAI_API_KEY"); present {
		t.Error("ExtraEnv smuggled an unselected provider credential past the fence")
	}
	if secret, _ := lookup(env, "ANTHROPIC_API_KEY"); secret != "sk-routed" {
		t.Errorf("ANTHROPIC_API_KEY = %q, want the routed secret; ExtraEnv overrode the route", secret)
	}
	if value, ok := lookup(env, "HELM_RUN_ID"); !ok || value != "run-1" {
		t.Error("ExtraEnv dropped a non-credential variable")
	}
}

func TestComposeEnvRejectsMissingScopedHome(t *testing.T) {
	if _, err := ComposeEnv([]string{"PATH=/bin"}, RunSpec{}); !errors.Is(err, ErrHomeDirRequired) {
		t.Errorf("err = %v, want ErrHomeDirRequired", err)
	}
}

func TestCleanEnvKeepsProxyAndTLSButNotCredentials(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.corp:3128")
	t.Setenv("NO_PROXY", "localhost")
	t.Setenv("NODE_EXTRA_CA_CERTS", "/etc/ssl/corp.pem")
	t.Setenv("SSL_CERT_FILE", "/etc/ssl/cert.pem")
	t.Setenv("REQUESTS_CA_BUNDLE", "/etc/ssl/corp.pem")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-seed")
	t.Setenv("OPENAI_API_KEY", "sk-openai-seed")

	env := CleanEnv()

	for _, name := range []string{"HTTPS_PROXY", "NO_PROXY", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"} {
		if _, ok := lookup(env, name); !ok {
			t.Errorf("CleanEnv dropped %s; a proxied host would have no egress", name)
		}
	}
	for _, name := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"} {
		if _, ok := lookup(env, name); ok {
			t.Errorf("CleanEnv admitted provider credential %s", name)
		}
	}
}

func TestIsProviderVar(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"ANTHROPIC_API_KEY", true},
		{"openai_api_key", true},
		{"AWS_SECRET_ACCESS_KEY", true},
		{"SOMEVENDOR_TOKEN", true},
		{"SOMEVENDOR_BASE_URL", true},
		{"API_KEY", true},
		{"HF_TOKEN", true},
		{"HUGGINGFACE_HUB_TOKEN", true},
		{"PATH", false},
		{"HTTPS_PROXY", false},
		{"https_proxy", false},
		{"NODE_EXTRA_CA_CERTS", false},
		{"SSL_CERT_DIR", false},
		{"REQUESTS_CA_BUNDLE", false},
		{"HOME", false},
		{"CLAUDE_CONFIG_DIR", false},
		{"CODEX_HOME", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsProviderVar(tt.name); got != tt.want {
			t.Errorf("IsProviderVar(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestCredentialRouteStringHidesSecret guards the accident of a route reaching a
// log line through %v.
func TestCredentialRouteStringHidesSecret(t *testing.T) {
	route := CredentialRoute{ID: "route-anthropic", EnvVar: "ANTHROPIC_API_KEY", Secret: "sk-should-never-print"}
	if formatted := route.String(); strings.Contains(formatted, "sk-should-never-print") {
		t.Errorf("CredentialRoute.String leaked the secret: %q", formatted)
	}
}

// TestPrimeAgentEnvPinsTheAgentDirAndKillsTelemetry pins the overrides that keep
// a run's vendor state inside the envelope. The vendor ships telemetry on and
// posts to a third party, and it resolves its agent directory through a home
// lookup that falls back to the passwd entry when HOME is unset.
func TestPrimeAgentEnvPinsTheAgentDirAndKillsTelemetry(t *testing.T) {
	home := "/run/home"
	agentDir := home + "/.prime/agent"
	spec := RunSpec{
		Tree:    "/run/tree",
		HomeDir: home,
		Prompt:  "hi",
		Access:  AccessWorkspaceWrite,
		// A caller trying to re-enable telemetry or move the agent directory
		// must not win: HELM's overrides are applied after ExtraEnv.
		ExtraEnv: map[string]string{
			"PRIME_AGENT_CODING_AGENT_DIR": "/home/operator/.prime/agent",
			"PRIME_AGENT_TELEMETRY":        "1",
			"DO_NOT_TRACK":                 "0",
			"PI_OFFLINE":                   "0",
		},
	}

	env, err := primeAgentEnv(spec)
	if err != nil {
		t.Fatalf("primeAgentEnv: %v", err)
	}

	for name, want := range map[string]string{
		"PRIME_AGENT_CODING_AGENT_DIR": agentDir,
		"PRIME_AGENT_SESSION_DIR":      agentDir + "/sessions",
		"PI_OFFLINE":                   "1",
		"PI_SKIP_VERSION_CHECK":        "1",
		"DO_NOT_TRACK":                 "1",
		"PRIME_AGENT_TELEMETRY":        "0",
	} {
		if got := envValue(env, name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	// Every one of these must survive the scrub, or the override silently does
	// nothing and the run reads as pinned while it is not.
	for name := range map[string]struct{}{
		"PRIME_AGENT_CODING_AGENT_DIR": {},
		"PRIME_AGENT_SESSION_DIR":      {},
		"PI_OFFLINE":                   {},
		"PI_SKIP_VERSION_CHECK":        {},
		"DO_NOT_TRACK":                 {},
		"PRIME_AGENT_TELEMETRY":        {},
	} {
		if IsProviderVar(name) {
			t.Errorf("%s is provider-shaped and would be scrubbed", name)
		}
	}
}

// TestPrimeAgentRedirectVariablesAreScrubbed pins that the vendor's own endpoint
// overrides stay fenced. A trace endpoint is a content-redirect channel, and a
// download endpoint chooses the bytes the run executes.
func TestPrimeAgentRedirectVariablesAreScrubbed(t *testing.T) {
	spec := RunSpec{
		Tree:    "/run/tree",
		HomeDir: "/run/home",
		Prompt:  "hi",
		Access:  AccessWorkspaceWrite,
		ExtraEnv: map[string]string{
			"PRIME_AGENT_TRACES_BASE_URL":   "https://exfil.example/v1",
			"PRIME_AGENT_DOWNLOAD_BASE_URL": "https://exfil.example/dl",
			"PRIME_API_KEY":                 "sk-smuggled",
			// Not provider-shaped: names an operator-owned interpreter, and
			// passing it is how a caller avoids a network kernel bootstrap.
			"PRIME_AGENT_KERNEL_PYTHON": "/opt/prime/bin/python",
		},
		Credential: CredentialRoute{ID: "route-1", EnvVar: "HELM_GATEWAY_KEY", Secret: "sk-routed"},
	}

	env, err := primeAgentEnv(spec)
	if err != nil {
		t.Fatalf("primeAgentEnv: %v", err)
	}

	for _, name := range []string{
		"PRIME_AGENT_TRACES_BASE_URL",
		"PRIME_AGENT_DOWNLOAD_BASE_URL",
		"PRIME_API_KEY",
	} {
		if got := envValue(env, name); got != "" {
			t.Errorf("%s survived the fence with %q", name, got)
		}
	}
	if got := envValue(env, "PRIME_AGENT_KERNEL_PYTHON"); got != "/opt/prime/bin/python" {
		t.Errorf("PRIME_AGENT_KERNEL_PYTHON = %q, want the caller's interpreter", got)
	}
	if got := envValue(env, "HELM_GATEWAY_KEY"); got != "sk-routed" {
		t.Errorf("credential route = %q, want the one sanctioned secret", got)
	}
}

// TestPrimeAgentGatewayIsConfigurationNotEnvironment pins the design choice that
// keeps INV-021 intact. The gateway endpoint reaches the child as a vendor
// config file inside the scoped HOME; nothing on this path sets a
// provider-shaped variable, so the credential fence is neither widened nor
// bypassed.
func TestPrimeAgentGatewayIsConfigurationNotEnvironment(t *testing.T) {
	runtime := t.TempDir()
	home := filepath.Join(runtime, "home")
	tree := filepath.Join(runtime, "tree")
	spec := RunSpec{
		Tree:    tree,
		HomeDir: home,
		Prompt:  "hi",
		Access:  AccessWorkspaceWrite,
		Model:   "helm/gpt-5.1-codex:high",
		ModelGateway: ModelGateway{
			BaseURL: "http://127.0.0.1:9095/v1",
			Headers: map[string]string{
				"X-HELM-Workspace":      "ws-1",
				"X-HELM-Agent":          "agent-1",
				"X-HELM-Spend-Envelope": "env-1",
			},
		},
		Credential: CredentialRoute{ID: "route-1", EnvVar: "HELM_GATEWAY_KEY", Secret: "sk-routed"},
	}

	if err := writePrimeAgentGateway(spec); err != nil {
		t.Fatalf("writePrimeAgentGateway: %v", err)
	}

	path := filepath.Join(home, ".prime", "agent", "models.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("catalog not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("catalog mode = %v, want 0600", perm)
	}
	if strings.HasPrefix(path, tree+string(filepath.Separator)) {
		t.Errorf("catalog %q is inside the tree and would land in the captured diff", path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	var catalog primeAgentCatalog
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatalf("catalog is not valid json: %v", err)
	}
	provider, ok := catalog.Providers[primeAgentGatewayProvider]
	if !ok {
		t.Fatalf("catalog has no %q provider", primeAgentGatewayProvider)
	}
	if provider.BaseURL != "http://127.0.0.1:9095/v1" {
		t.Errorf("baseUrl = %q", provider.BaseURL)
	}
	// The vendor resolves apiKey as an environment-variable name, so the secret
	// itself never enters the file.
	if provider.APIKey != "HELM_GATEWAY_KEY" {
		t.Errorf("apiKey = %q, want the credential variable name", provider.APIKey)
	}
	if strings.Contains(string(raw), "sk-routed") {
		t.Error("catalog contains the credential secret in plaintext")
	}
	if provider.Headers["X-HELM-Spend-Envelope"] != "env-1" {
		t.Errorf("governance headers = %v", provider.Headers)
	}
	// RunSpec.Model is a selector; the catalog must carry the bare id.
	if len(provider.Models) != 1 || provider.Models[0].ID != "gpt-5.1-codex" {
		t.Errorf("models = %v, want the bare id from the selector", provider.Models)
	}

	env, err := primeAgentEnv(spec)
	if err != nil {
		t.Fatalf("primeAgentEnv: %v", err)
	}
	for _, entry := range env {
		name, value, _ := strings.Cut(entry, "=")
		if strings.Contains(value, "127.0.0.1:9095") {
			t.Errorf("%s carries the gateway endpoint; the base URL must not become an environment variable", name)
		}
	}
}

// TestPrimeAgentGatewayRefusesIncompleteSpecs pins that a half-specified gateway
// is refused rather than written. A catalog naming an endpoint the child cannot
// authenticate to, or serving no model, produces a run that fails at the first
// inference call with nothing recorded about why.
func TestPrimeAgentGatewayRefusesIncompleteSpecs(t *testing.T) {
	base := func() RunSpec {
		return RunSpec{
			Tree:         "/run/tree",
			HomeDir:      t.TempDir(),
			Prompt:       "hi",
			Access:       AccessWorkspaceWrite,
			Model:        "helm/gpt-5.1-codex",
			ModelGateway: ModelGateway{BaseURL: "http://127.0.0.1:9095/v1"},
			Credential:   CredentialRoute{ID: "r", EnvVar: "HELM_GATEWAY_KEY", Secret: "s"},
		}
	}

	noCredential := base()
	noCredential.Credential = CredentialRoute{}
	if err := writePrimeAgentGateway(noCredential); !errors.Is(err, ErrModelGatewayIncomplete) {
		t.Errorf("err = %v, want ErrModelGatewayIncomplete for a gateway with no credential route", err)
	}

	noModel := base()
	noModel.Model = ""
	if err := writePrimeAgentGateway(noModel); !errors.Is(err, ErrModelGatewayIncomplete) {
		t.Errorf("err = %v, want ErrModelGatewayIncomplete for a gateway serving no model", err)
	}

	// An unpinned gateway is not an error: the run simply proves nothing about
	// where its inference went, and writes no catalog.
	unpinned := base()
	unpinned.ModelGateway = ModelGateway{}
	if err := writePrimeAgentGateway(unpinned); err != nil {
		t.Errorf("unpinned gateway returned %v, want no error", err)
	}
	if _, err := os.Stat(filepath.Join(unpinned.HomeDir, ".prime", "agent", "models.json")); !os.IsNotExist(err) {
		t.Error("unpinned gateway wrote a catalog")
	}
}

// envValue returns the value of name in a composed environment, or "" when it is
// absent. The fence removes a variable by omitting it, so absent and empty are
// the same answer here.
func envValue(env []string, name string) string {
	for _, entry := range env {
		if key, value, ok := strings.Cut(entry, "="); ok && key == name {
			return value
		}
	}
	return ""
}
