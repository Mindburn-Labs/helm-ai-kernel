package harness

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// providerPrefixes are variable-name prefixes owned by a model provider.
//
// The list covers every provider, not only the vendor being routed to. Scrubbing
// just the selected vendor's variables is the bug this function exists to
// prevent: a run routed to one provider would otherwise inherit the operator's
// credentials for the other, and a CLI that supports multiple providers can be
// steered onto that inherited key by a config file, a base-URL redirect, or a
// fallback path. The run would then be billed to, and attributable to, a
// principal HELM never selected.
var providerPrefixes = []string{
	"ANTHROPIC_",
	"OPENAI_",
	"AWS_",
	"GOOGLE_",
	"GCLOUD_",
	"GCP_",
	"GEMINI_",
	"VERTEX_",
	"AZURE_",
	"MISTRAL_",
	"COHERE_",
	"GROQ_",
	"XAI_",
	"DEEPSEEK_",
	"OPENROUTER_",
	"PERPLEXITY_",
	"TOGETHER_",
	"FIREWORKS_",
	"REPLICATE_",
	"HUGGING",
	"BEDROCK_",
	"OLLAMA_",
}

// providerSuffixes catch the credential and base-URL naming conventions used by
// providers this package has never heard of. A base-URL redirect is treated as
// credential-class on purpose: it silently reroutes the run's traffic, which
// defeats route proof just as effectively as a stolen key.
var providerSuffixes = []string{
	"_API_KEY",
	"_API_BASE",
	"_API_SECRET",
	"_API_TOKEN",
	"_BASE_URL",
	"_ACCESS_KEY",
	"_SECRET_KEY",
	"_TOKEN",
	"_SECRET",
}

// providerExact catch bare names that match no prefix or suffix rule.
var providerExact = map[string]bool{
	"API_KEY":   true,
	"API_BASE":  true,
	"API_TOKEN": true,
	"BASE_URL":  true,
	"TOKEN":     true,
	"SECRET":    true,
	"HF_TOKEN":  true,
}

// runtimeAllowlist is the minimal environment a vendor CLI needs to run at all.
//
// The proxy and TLS entries are kept deliberately. A corporate-proxy or
// TLS-inspecting host reaches the provider only through HTTP(S)_PROXY and a
// custom CA bundle; dropping them in the name of a clean environment leaves
// those operators with a run that cannot make a single request, and the failure
// looks like a credential problem rather than an egress one. Locale and TERM
// are kept because vendor CLIs change output encoding without them.
var runtimeAllowlist = []string{
	"PATH",
	"LANG",
	"LC_ALL",
	"TERM",
	"TZ",

	"HTTP_PROXY",
	"HTTPS_PROXY",
	"ALL_PROXY",
	"NO_PROXY",
	"http_proxy",
	"https_proxy",
	"all_proxy",
	"no_proxy",

	"NODE_EXTRA_CA_CERTS",
	"SSL_CERT_FILE",
	"SSL_CERT_DIR",
	"REQUESTS_CA_BUNDLE",
}

// IsProviderVar reports whether a variable name carries provider credential or
// routing authority.
func IsProviderVar(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	if upper == "" {
		return false
	}
	if providerExact[upper] {
		return true
	}
	for _, prefix := range providerPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	for _, suffix := range providerSuffixes {
		if strings.HasSuffix(upper, suffix) {
			return true
		}
	}
	return false
}

// ScrubProviderEnv removes every provider credential and base-URL redirect from
// a "KEY=VALUE" environment slice, regardless of which provider the run is
// routed to. Entries that are not well-formed assignments are dropped, since a
// name that cannot be evaluated cannot be cleared.
func ScrubProviderEnv(base []string) []string {
	out := make([]string, 0, len(base))
	for _, entry := range base {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == "" {
			continue
		}
		if IsProviderVar(name) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// CleanEnv builds the child's base environment from the current process
// environment, keeping only runtimeAllowlist.
//
// The result is passed through ScrubProviderEnv as well. The allowlist is
// already credential-free, so this is redundant today and intentionally so: it
// means a future entry added to runtimeAllowlist cannot reopen the fence by
// itself.
func CleanEnv() []string {
	out := make([]string, 0, len(runtimeAllowlist))
	for _, name := range runtimeAllowlist {
		if value, ok := os.LookupEnv(name); ok {
			out = append(out, name+"="+value)
		}
	}
	return ScrubProviderEnv(out)
}

// scopedHomeEnv mirrors worktree.Envelope.Env: the four variables that move a
// vendor CLI's sessions, config, and credential cache out of the operator's
// real HOME and into the run's scoped one.
func scopedHomeEnv(homeDir string) map[string]string {
	if strings.TrimSpace(homeDir) == "" {
		return nil
	}
	return map[string]string{
		"HOME":              homeDir,
		"XDG_CONFIG_HOME":   filepath.Join(homeDir, ".config"),
		"CLAUDE_CONFIG_DIR": filepath.Join(homeDir, ".claude"),
		"CODEX_HOME":        filepath.Join(homeDir, ".codex"),
	}
}

// ComposeEnv builds the child environment in the one order that keeps the
// credential fence intact:
//
//  1. the base environment, scrubbed of every provider credential;
//  2. the scoped-HOME overrides that redirect vendor state into the run;
//  3. the caller's extra variables, themselves scrubbed;
//  4. exactly the one variable the selected credential route needs.
//
// Step 3 is scrubbed for the same reason step 1 is. ExtraEnv is a convenience
// channel, and letting a provider key through it would mean the fence held
// everywhere except the place a caller in a hurry would reach for.
func ComposeEnv(base []string, spec RunSpec) []string {
	env := ScrubProviderEnv(base)

	scoped := scopedHomeEnv(spec.HomeDir)
	for _, name := range sortedKeys(scoped) {
		env = setEnv(env, name, scoped[name])
	}
	for _, name := range sortedKeys(spec.ExtraEnv) {
		if IsProviderVar(name) {
			continue
		}
		env = setEnv(env, name, spec.ExtraEnv[name])
	}

	// The credential is applied last so it is the only provider variable that
	// survives, whatever the base environment contained.
	if name := strings.TrimSpace(spec.Credential.EnvVar); name != "" {
		env = setEnv(env, name, spec.Credential.Secret)
	}
	return env
}

// setEnv replaces an assignment in place, or appends it. Replacing in place
// keeps the composed environment deterministic for a given input, which matters
// because the argv and environment of a run are part of what HELM recorded
// about it.
func setEnv(env []string, name, value string) []string {
	entry := name + "=" + value
	for i, existing := range env {
		if key, _, ok := strings.Cut(existing, "="); ok && key == name {
			env[i] = entry
			return env
		}
	}
	return append(env, entry)
}

func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
