package harness

import (
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
			env := ComposeEnv(seededProviderEnv(), RunSpec{
				Tree:       "/runtime/tree",
				HomeDir:    "/runtime/home",
				Credential: tt.route,
			})

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
	env := ComposeEnv([]string{"HOME=/Users/operator", "PATH=/bin"}, RunSpec{
		Tree:    "/runtime/tree",
		HomeDir: "/runtime/home",
	})

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
	env := ComposeEnv([]string{"PATH=/bin"}, RunSpec{
		Tree:    "/runtime/tree",
		HomeDir: "/runtime/home",
		ExtraEnv: map[string]string{
			"OPENAI_API_KEY":    "sk-smuggled",
			"ANTHROPIC_API_KEY": "sk-smuggled-too",
			"HELM_RUN_ID":       "run-1",
		},
		Credential: CredentialRoute{ID: "route-anthropic", EnvVar: "ANTHROPIC_API_KEY", Secret: "sk-routed"},
	})

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
