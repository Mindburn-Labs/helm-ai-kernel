package modelproviders

import (
	"strings"
	"testing"
)

func TestProviderHelpersCoverFallbacksCredentialsAndDynamicBaseURLs(t *testing.T) {
	provider := Provider{
		ID:                  "alpha",
		Protocols:           []string{"openai-compatible"},
		Env:                 []string{"ALPHA_KEY", "ALPHA_BASE", "ALT_BASE"},
		CredentialEnv:       []string{"ALPHA_KEY"},
		RequiredEnvGroups:   [][]string{{"ALPHA_BASE", "ALPHA_KEY", "ALPHA_KEY"}},
		BaseURLs:            []string{"https://static.alpha.test/v1"},
		BaseURLEnv:          []string{"EMPTY", "INVALID", "HTTP", "DENIED", "ALPHA_BASE", "ALT_BASE", "STATIC"},
		AllowedHostSuffixes: []string{".alpha.dynamic.test"},
	}

	if provider.HasProtocol("") || provider.HasProtocol("anthropic-compatible") {
		t.Fatal("HasProtocol accepted empty or missing protocol")
	}
	if !provider.HasProtocol("openai-compatible") {
		t.Fatal("HasProtocol rejected declared protocol")
	}
	if (Provider{}).PreferredBaseURL() != "" {
		t.Fatal("PreferredBaseURL without base URLs should be empty")
	}
	if got := (Provider{BaseURLs: []string{"https://fallback.test/root"}}).PreferredBaseURL(); got != "https://fallback.test/root" {
		t.Fatalf("PreferredBaseURL fallback = %q", got)
	}

	requiredGroups := provider.RequiredGroups()
	if len(requiredGroups) != 1 || strings.Join(requiredGroups[0], ",") != "ALPHA_BASE,ALPHA_KEY" {
		t.Fatalf("RequiredGroups = %#v, want sorted unique explicit group", requiredGroups)
	}
	requiredGroups[0][0] = "MUTATED"
	if provider.RequiredEnvGroups[0][0] != "ALPHA_BASE" {
		t.Fatalf("RequiredGroups leaked mutable backing slice: %#v", provider.RequiredEnvGroups)
	}
	fallbackGroups := (Provider{Env: []string{"", " ZED ", "ALPHA_KEY"}}).RequiredGroups()
	if len(fallbackGroups) != 2 || fallbackGroups[0][0] != "ZED" || fallbackGroups[1][0] != "ALPHA_KEY" {
		t.Fatalf("fallback RequiredGroups = %#v", fallbackGroups)
	}

	if provider.DynamicBaseURLs(nil) != nil {
		t.Fatal("DynamicBaseURLs(nil) should be nil")
	}
	lookup := func(name string) (string, bool) {
		switch name {
		case "EMPTY":
			return "   ", true
		case "INVALID":
			return "://bad", true
		case "HTTP":
			return "http://api.alpha.dynamic.test", true
		case "DENIED":
			return "https://denied.example.test", true
		case "ALPHA_BASE", "ALT_BASE":
			return "https://tenant.alpha.dynamic.test/v1/", true
		case "STATIC":
			return "https://static.alpha.test/v1", true
		default:
			return "", false
		}
	}
	dynamic := provider.DynamicBaseURLs(lookup)
	wantDynamic := []string{"https://static.alpha.test/v1", "https://tenant.alpha.dynamic.test/v1"}
	if strings.Join(dynamic, ",") != strings.Join(wantDynamic, ",") {
		t.Fatalf("DynamicBaseURLs = %#v, want %#v", dynamic, wantDynamic)
	}
	if got := provider.PreferredBaseURLFromEnv(lookup); got != "https://static.alpha.test/v1" {
		t.Fatalf("PreferredBaseURLFromEnv = %q, want static dynamic URL first after sorting", got)
	}
	if got := provider.PreferredBaseURLFromEnv(nil); got != "https://static.alpha.test/v1" {
		t.Fatalf("PreferredBaseURLFromEnv nil = %q, want preferred static URL", got)
	}

	if provider.HasEnv("") || provider.HasEnv("MISSING") || !provider.HasEnv("ALPHA_KEY") {
		t.Fatal("HasEnv did not distinguish empty, missing, and declared env keys")
	}
	if provider.CanProjectCredential("") || provider.CanProjectCredential("ALPHA_BASE") || !provider.CanProjectCredential("ALPHA_KEY") {
		t.Fatal("CanProjectCredential did not honor explicit credential_env")
	}
	fallbackCredential := Provider{Env: []string{"TOKEN", "BASE_URL"}, BaseURLEnv: []string{"BASE_URL"}}
	if !fallbackCredential.CanProjectCredential("TOKEN") || fallbackCredential.CanProjectCredential("BASE_URL") {
		t.Fatal("CanProjectCredential fallback should exclude base URL env keys")
	}
}

func TestCatalogValidationRejectsMalformedProviders(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Catalog)
		wantErr string
	}{
		{
			name:    "bad schema",
			mutate:  func(c *Catalog) { c.SchemaVersion = "v0" },
			wantErr: `unsupported model provider catalog schema_version "v0"`,
		},
		{
			name:    "no providers",
			mutate:  func(c *Catalog) { c.Providers = nil },
			wantErr: "model provider catalog has no providers",
		},
		{
			name:    "blank id",
			mutate:  func(c *Catalog) { c.Providers[0].ID = " " },
			wantErr: "model provider id is required",
		},
		{
			name:    "duplicate id",
			mutate:  func(c *Catalog) { c.Providers = append(c.Providers, c.Providers[0]) },
			wantErr: `duplicate model provider id "alpha"`,
		},
		{
			name:    "missing regions",
			mutate:  func(c *Catalog) { c.Providers[0].Regions = nil },
			wantErr: "must declare at least one region",
		},
		{
			name:    "missing env",
			mutate:  func(c *Catalog) { c.Providers[0].Env = nil },
			wantErr: "must declare at least one env key",
		},
		{
			name: "missing base url and env",
			mutate: func(c *Catalog) {
				c.Providers[0].BaseURLs = nil
				c.Providers[0].BaseURLEnv = nil
			},
			wantErr: "must declare at least one base_url or base_url_env",
		},
		{
			name:    "empty env group",
			mutate:  func(c *Catalog) { c.Providers[0].RequiredEnvGroups = [][]string{{}} },
			wantErr: "empty required_env_groups entry",
		},
		{
			name:    "env group unknown env",
			mutate:  func(c *Catalog) { c.Providers[0].RequiredEnvGroups = [][]string{{"MISSING"}} },
			wantErr: `required_env_groups references undeclared env "MISSING"`,
		},
		{
			name:    "credential env unknown",
			mutate:  func(c *Catalog) { c.Providers[0].CredentialEnv = []string{"MISSING"} },
			wantErr: `credential_env references undeclared env "MISSING"`,
		},
		{
			name:    "base url env unknown",
			mutate:  func(c *Catalog) { c.Providers[0].BaseURLEnv = []string{"MISSING"} },
			wantErr: `base_url_env references undeclared env "MISSING"`,
		},
		{
			name:    "invalid base url",
			mutate:  func(c *Catalog) { c.Providers[0].BaseURLs = []string{"ftp://api.alpha.test"} },
			wantErr: `invalid base_url "ftp://api.alpha.test"`,
		},
		{
			name:    "shared destination",
			mutate:  func(c *Catalog) { c.Providers[1].BaseURLs = []string{"api.alpha.test:443"} },
			wantErr: "is shared by alpha and beta",
		},
		{
			name:    "invalid probe url",
			mutate:  func(c *Catalog) { c.Providers[0].ProbeURLs = []string{"ftp://probe.alpha.test"} },
			wantErr: `invalid probe_url "ftp://probe.alpha.test"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			catalog := modelProviderCoverageCatalog()
			tc.mutate(&catalog)
			requireModelProviderErrorContains(t, catalog.Validate(), tc.wantErr)
		})
	}
}

func TestCatalogSelectionDestinationAndEnvGroupHelpers(t *testing.T) {
	catalog := modelProviderCoverageCatalog()
	if ids := catalog.ProviderIDs(); strings.Join(ids, ",") != "alpha,beta" {
		t.Fatalf("ProviderIDs = %#v, want sorted alpha,beta", ids)
	}

	all, err := catalog.ProvidersForIDs(nil)
	if err != nil {
		t.Fatalf("ProvidersForIDs(nil): %v", err)
	}
	all[0].ID = "mutated"
	if catalog.Providers[0].ID != "alpha" {
		t.Fatal("ProvidersForIDs(nil) returned mutable catalog backing slice")
	}
	all, err = catalog.ProvidersForIDs([]string{" * "})
	if err != nil || len(all) != 2 {
		t.Fatalf("ProvidersForIDs wildcard = (%#v, %v), want all providers", all, err)
	}
	selected, err := catalog.ProvidersForIDs([]string{"", "beta", "alpha", "beta"})
	if err != nil {
		t.Fatalf("ProvidersForIDs selected: %v", err)
	}
	if providerIDs(selected) != "alpha,beta" {
		t.Fatalf("ProvidersForIDs selected IDs = %s, want alpha,beta", providerIDs(selected))
	}
	_, err = catalog.ProvidersForIDs([]string{"missing"})
	requireModelProviderErrorContains(t, err, `unknown model provider id "missing"`)

	groups, err := catalog.EnvGroupsForProviderIDs([]string{"alpha", "beta"})
	if err != nil {
		t.Fatalf("EnvGroupsForProviderIDs: %v", err)
	}
	if len(groups) != 2 || strings.Join(groups[0], ",") != "ALPHA_BASE,ALPHA_KEY" || strings.Join(groups[1], ",") != "SHARED_ENV" {
		t.Fatalf("EnvGroupsForProviderIDs = %#v, want deduped sorted groups", groups)
	}
	_, err = catalog.EnvGroupsForProviderIDs([]string{"missing"})
	requireModelProviderErrorContains(t, err, `unknown model provider id "missing"`)

	envNames, err := catalog.EnvNamesForProviderIDs([]string{"alpha", "beta"})
	if err != nil {
		t.Fatalf("EnvNamesForProviderIDs: %v", err)
	}
	if strings.Join(envNames, ",") != "ALPHA_BASE,ALPHA_KEY,BETA_KEY,SHARED_ENV" {
		t.Fatalf("EnvNamesForProviderIDs = %#v", envNames)
	}
	_, err = catalog.EnvNamesForProviderIDs([]string{"missing"})
	requireModelProviderErrorContains(t, err, `unknown model provider id "missing"`)

	baseURLs, err := catalog.BaseURLsForProviderIDsWithEnv([]string{"alpha", "beta"}, coverageEnvLookup)
	if err != nil {
		t.Fatalf("BaseURLsForProviderIDsWithEnv: %v", err)
	}
	wantBaseURLs := "https://api.alpha.test/v1,https://api.beta.test/v2,https://tenant.alpha.dynamic.test/v1"
	if strings.Join(baseURLs, ",") != wantBaseURLs {
		t.Fatalf("BaseURLsForProviderIDsWithEnv = %#v, want %s", baseURLs, wantBaseURLs)
	}
	_, err = catalog.BaseURLsForProviderIDsWithEnv([]string{"missing"}, nil)
	requireModelProviderErrorContains(t, err, `unknown model provider id "missing"`)

	destinations := catalog.AllowedDestinationsWithEnv(coverageEnvLookup)
	wantDestinations := "api.alpha.test:443,api.beta.test:443,tenant.alpha.dynamic.test:443"
	if strings.Join(destinations, ",") != wantDestinations {
		t.Fatalf("AllowedDestinationsWithEnv = %#v, want %s", destinations, wantDestinations)
	}
	staticDestinations := catalog.AllowedDestinationsWithEnv(nil)
	if strings.Join(staticDestinations, ",") != "api.alpha.test:443,api.beta.test:443" {
		t.Fatalf("AllowedDestinationsWithEnv nil = %#v", staticDestinations)
	}
	if catalog.Allows("") || catalog.Allows("ftp://api.alpha.test") {
		t.Fatal("Allows accepted empty or unsupported destination")
	}
	if !catalog.Allows("https://api.alpha.test/v1/chat") || !catalog.Allows("https://foo.alpha.dynamic.test/path") {
		t.Fatal("Allows rejected exact static or suffix destination")
	}
	if catalog.Allows("https://alpha.dynamic.test/path") || catalog.Allows("https://example.test") {
		t.Fatal("Allows accepted suffix root or unrelated destination")
	}

	if catalog.ProviderIDsForEnv("") != nil {
		t.Fatal("ProviderIDsForEnv empty should be nil")
	}
	if ids := catalog.ProviderIDsForEnv("SHARED_ENV"); strings.Join(ids, ",") != "alpha,beta" {
		t.Fatalf("ProviderIDsForEnv shared = %#v, want alpha,beta", ids)
	}
	if provider, ok := catalog.ProviderForEnv(" "); ok || provider.ID != "" {
		t.Fatalf("ProviderForEnv empty = (%#v, %v), want empty false", provider, ok)
	}
	if provider, ok := catalog.ProviderForEnv("BETA_KEY"); !ok || provider.ID != "beta" {
		t.Fatalf("ProviderForEnv BETA_KEY = (%#v, %v), want beta true", provider, ok)
	}
	if provider, ok := catalog.ProviderForEnv("MISSING"); ok || provider.ID != "" {
		t.Fatalf("ProviderForEnv missing = (%#v, %v), want false", provider, ok)
	}
	if provider, ok := catalog.ProviderForID(" "); ok || provider.ID != "" {
		t.Fatalf("ProviderForID empty = (%#v, %v), want empty false", provider, ok)
	}
	if provider, ok := catalog.ProviderForID("alpha"); !ok || provider.ID != "alpha" {
		t.Fatalf("ProviderForID alpha = (%#v, %v), want alpha true", provider, ok)
	}
	if provider, ok := catalog.ProviderForID("missing"); ok || provider.ID != "" {
		t.Fatalf("ProviderForID missing = (%#v, %v), want false", provider, ok)
	}

	if provider, group, ok := catalog.ProviderForCompleteEnvGroup(nil); ok || provider.ID != "" || group != nil {
		t.Fatalf("ProviderForCompleteEnvGroup nil = (%#v, %#v, %v), want empty false", provider, group, ok)
	}
	if provider, group, ok := catalog.ProviderForCompleteEnvGroup(func(string) (string, bool) { return "", false }); ok || provider.ID != "" || group != nil {
		t.Fatalf("ProviderForCompleteEnvGroup missing = (%#v, %#v, %v), want empty false", provider, group, ok)
	}
	provider, group, ok := catalog.ProviderForCompleteEnvGroup(func(name string) (string, bool) {
		switch name {
		case "ALPHA_KEY", "ALPHA_BASE":
			return "set", true
		default:
			return "", false
		}
	})
	if !ok || provider.ID != "alpha" || strings.Join(group, ",") != "ALPHA_BASE,ALPHA_KEY" {
		t.Fatalf("ProviderForCompleteEnvGroup = (%#v, %#v, %v), want alpha sorted group true", provider, group, ok)
	}
}

func TestDestinationNormalizationAndSuffixHelpers(t *testing.T) {
	cases := map[string]string{
		"":                              "",
		" https://Example.COM/v1/chat ": "example.com:443",
		"http://Example.COM/v1":         "example.com:80",
		"ftp://example.com":             "",
		"://bad":                        "",
		"api.example.com":               "api.example.com:443",
		"API.EXAMPLE.COM:8443":          "api.example.com:8443",
	}
	for input, want := range cases {
		if got := NormalizeDestination(input); got != want {
			t.Fatalf("NormalizeDestination(%q) = %q, want %q", input, got, want)
		}
	}

	if got := normalizeHTTPSURL(" https://Example.COM/path/?q=1 "); got != "https://example.com/path" {
		t.Fatalf("normalizeHTTPSURL valid = %q", got)
	}
	for _, input := range []string{"://bad", "http://example.com", "https://"} {
		if got := normalizeHTTPSURL(input); got != "" {
			t.Fatalf("normalizeHTTPSURL(%q) = %q, want empty", input, got)
		}
	}

	suffixCases := []struct {
		host, suffix string
		want         bool
	}{
		{"", ".example.com", false},
		{"api.example.com", "", false},
		{"api.example.com", "api.example.com", true},
		{"sub.example.com", "*.example.com", true},
		{"example.com", ".example.com", false},
		{"tenant-openai.azure.com", "-openai.azure.com", true},
		{"openai.azure.com", "-openai.azure.com", false},
	}
	for _, tc := range suffixCases {
		if got := hostMatchesSuffix(tc.host, tc.suffix); got != tc.want {
			t.Fatalf("hostMatchesSuffix(%q, %q) = %v, want %v", tc.host, tc.suffix, got, tc.want)
		}
	}

	provider := Provider{
		BaseURLs:            []string{"https://static.example.test/v1"},
		AllowedHostSuffixes: []string{".dynamic.example.test"},
	}
	if providerAllowsDynamicBaseURL(provider, "ftp://static.example.test") {
		t.Fatal("providerAllowsDynamicBaseURL accepted invalid URL")
	}
	if !providerAllowsDynamicBaseURL(provider, "https://static.example.test/v1/chat") {
		t.Fatal("providerAllowsDynamicBaseURL rejected static destination match")
	}
	if !providerAllowsDynamicBaseURL(provider, "https://tenant.dynamic.example.test/v1") {
		t.Fatal("providerAllowsDynamicBaseURL rejected suffix match")
	}
	if providerAllowsDynamicBaseURL(provider, "https://example.test/v1") {
		t.Fatal("providerAllowsDynamicBaseURL accepted unrelated host")
	}
}

func TestMustDefaultCatalogReturnsEmbeddedCatalog(t *testing.T) {
	catalog := MustDefaultCatalog()
	if len(catalog.Providers) == 0 {
		t.Fatal("MustDefaultCatalog returned empty provider list")
	}
}

func modelProviderCoverageCatalog() Catalog {
	return Catalog{
		SchemaVersion: "helm.launchpad.model_providers.v1",
		Providers: []Provider{
			{
				ID:                  "alpha",
				Name:                "Alpha",
				Regions:             []string{"US"},
				Protocols:           []string{"openai-compatible"},
				Env:                 []string{"ALPHA_KEY", "ALPHA_BASE", "SHARED_ENV"},
				CredentialEnv:       []string{"ALPHA_KEY"},
				RequiredEnvGroups:   [][]string{{"ALPHA_KEY", "ALPHA_BASE", "ALPHA_KEY"}},
				BaseURLs:            []string{"https://api.alpha.test/v1"},
				BaseURLEnv:          []string{"ALPHA_BASE"},
				ProbeURLs:           []string{"https://api.alpha.test/health"},
				AllowedHostSuffixes: []string{".alpha.dynamic.test"},
				SourceURLs:          []string{"https://docs.alpha.test"},
			},
			{
				ID:                "beta",
				Name:              "Beta",
				Regions:           []string{"EU"},
				Protocols:         []string{"anthropic-compatible"},
				Env:               []string{"BETA_KEY", "SHARED_ENV"},
				RequiredEnvGroups: [][]string{{"SHARED_ENV"}},
				BaseURLs:          []string{"https://api.beta.test/v2"},
				SourceURLs:        []string{"https://docs.beta.test"},
			},
		},
	}
}

func coverageEnvLookup(name string) (string, bool) {
	if name == "ALPHA_BASE" {
		return "https://tenant.alpha.dynamic.test/v1/", true
	}
	return "", false
}

func requireModelProviderErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want substring %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}

func providerIDs(providers []Provider) string {
	ids := make([]string, 0, len(providers))
	for _, provider := range providers {
		ids = append(ids, provider.ID)
	}
	return strings.Join(ids, ",")
}
