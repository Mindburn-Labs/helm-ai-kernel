package modelproviders

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

//go:embed catalog.json
var embeddedCatalog embed.FS

type Catalog struct {
	SchemaVersion string     `json:"schema_version"`
	GeneratedAt   string     `json:"generated_at"`
	SourcePolicy  string     `json:"source_policy"`
	Providers     []Provider `json:"providers"`
}

type Provider struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	Regions             []string   `json:"regions"`
	Protocols           []string   `json:"protocols"`
	Env                 []string   `json:"env"`
	CredentialEnv       []string   `json:"credential_env,omitempty"`
	RequiredEnvGroups   [][]string `json:"required_env_groups,omitempty"`
	BaseURLs            []string   `json:"base_urls"`
	BaseURLEnv          []string   `json:"base_url_env,omitempty"`
	ProbeURLs           []string   `json:"probe_urls,omitempty"`
	AllowedHostSuffixes []string   `json:"allowed_host_suffixes,omitempty"`
	SourceURLs          []string   `json:"source_urls"`
}

func (p Provider) HasProtocol(protocol string) bool {
	protocol = strings.TrimSpace(protocol)
	if protocol == "" {
		return false
	}
	for _, candidate := range p.Protocols {
		if candidate == protocol {
			return true
		}
	}
	return false
}

func (p Provider) PreferredBaseURL() string {
	if len(p.BaseURLs) == 0 {
		return ""
	}
	nonAnthropic := make([]string, 0, len(p.BaseURLs))
	for _, baseURL := range p.BaseURLs {
		if !strings.Contains(baseURL, "anthropic") {
			nonAnthropic = append(nonAnthropic, baseURL)
		}
	}
	for _, candidates := range [][]string{nonAnthropic, p.BaseURLs} {
		for _, baseURL := range candidates {
			if strings.HasSuffix(baseURL, "/v1") || strings.HasSuffix(baseURL, "/v2") || strings.HasSuffix(baseURL, "/v3") || strings.HasSuffix(baseURL, "/v4") {
				return baseURL
			}
		}
	}
	return p.BaseURLs[0]
}

func (p Provider) RequiredGroups() [][]string {
	if len(p.RequiredEnvGroups) > 0 {
		return cloneEnvGroups(p.RequiredEnvGroups)
	}
	groups := make([][]string, 0, len(p.Env))
	for _, envName := range p.Env {
		envName = strings.TrimSpace(envName)
		if envName == "" {
			continue
		}
		groups = append(groups, []string{envName})
	}
	return groups
}

func (p Provider) DynamicBaseURLs(lookup func(string) (string, bool)) []string {
	if lookup == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, envName := range p.BaseURLEnv {
		value, ok := lookup(envName)
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		normalized := normalizeHTTPSURL(value)
		if normalized == "" {
			continue
		}
		if !providerAllowsDynamicBaseURL(p, normalized) {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func (p Provider) PreferredBaseURLFromEnv(lookup func(string) (string, bool)) string {
	dynamic := p.DynamicBaseURLs(lookup)
	if len(dynamic) > 0 {
		return dynamic[0]
	}
	return p.PreferredBaseURL()
}

func (p Provider) HasEnv(envName string) bool {
	envName = strings.TrimSpace(envName)
	if envName == "" {
		return false
	}
	for _, candidate := range p.Env {
		if candidate == envName {
			return true
		}
	}
	return false
}

func (p Provider) CanProjectCredential(envName string) bool {
	envName = strings.TrimSpace(envName)
	if envName == "" {
		return false
	}
	credentialEnv := p.CredentialEnv
	if len(credentialEnv) == 0 {
		for _, candidate := range p.Env {
			if containsString(p.BaseURLEnv, candidate) {
				continue
			}
			credentialEnv = append(credentialEnv, candidate)
		}
	}
	for _, candidate := range credentialEnv {
		if candidate == envName {
			return true
		}
	}
	return false
}

func DefaultCatalog() (Catalog, error) {
	data, err := embeddedCatalog.ReadFile("catalog.json")
	if err != nil {
		return Catalog{}, err
	}
	var catalog Catalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return Catalog{}, err
	}
	if err := catalog.Validate(); err != nil {
		return Catalog{}, err
	}
	return catalog, nil
}

func MustDefaultCatalog() Catalog {
	catalog, err := DefaultCatalog()
	if err != nil {
		panic(err)
	}
	return catalog
}

func (c Catalog) Validate() error {
	if strings.TrimSpace(c.SchemaVersion) != "helm.launchpad.model_providers.v1" {
		return fmt.Errorf("unsupported model provider catalog schema_version %q", c.SchemaVersion)
	}
	if len(c.Providers) == 0 {
		return fmt.Errorf("model provider catalog has no providers")
	}
	ids := map[string]struct{}{}
	destinations := map[string]string{}
	for _, provider := range c.Providers {
		if strings.TrimSpace(provider.ID) == "" {
			return fmt.Errorf("model provider id is required")
		}
		if _, exists := ids[provider.ID]; exists {
			return fmt.Errorf("duplicate model provider id %q", provider.ID)
		}
		ids[provider.ID] = struct{}{}
		if len(provider.Regions) == 0 {
			return fmt.Errorf("model provider %s must declare at least one region", provider.ID)
		}
		if len(provider.Env) == 0 {
			return fmt.Errorf("model provider %s must declare at least one env key", provider.ID)
		}
		if len(provider.BaseURLs) == 0 && len(provider.BaseURLEnv) == 0 {
			return fmt.Errorf("model provider %s must declare at least one base_url or base_url_env", provider.ID)
		}
		if len(provider.RequiredEnvGroups) > 0 {
			for _, group := range provider.RequiredEnvGroups {
				if len(group) == 0 {
					return fmt.Errorf("model provider %s has an empty required_env_groups entry", provider.ID)
				}
				for _, envName := range group {
					if !provider.HasEnv(envName) {
						return fmt.Errorf("model provider %s required_env_groups references undeclared env %q", provider.ID, envName)
					}
				}
			}
		}
		for _, envName := range provider.CredentialEnv {
			if !provider.HasEnv(envName) {
				return fmt.Errorf("model provider %s credential_env references undeclared env %q", provider.ID, envName)
			}
		}
		for _, envName := range provider.BaseURLEnv {
			if !provider.HasEnv(envName) {
				return fmt.Errorf("model provider %s base_url_env references undeclared env %q", provider.ID, envName)
			}
		}
		for _, baseURL := range provider.BaseURLs {
			destination := NormalizeDestination(baseURL)
			if destination == "" {
				return fmt.Errorf("model provider %s has invalid base_url %q", provider.ID, baseURL)
			}
			if owner, exists := destinations[destination]; exists && owner != provider.ID {
				return fmt.Errorf("model provider destination %s is shared by %s and %s", destination, owner, provider.ID)
			}
			destinations[destination] = provider.ID
		}
		for _, probeURL := range provider.ProbeURLs {
			if NormalizeDestination(probeURL) == "" {
				return fmt.Errorf("model provider %s has invalid probe_url %q", provider.ID, probeURL)
			}
		}
	}
	return nil
}

func (c Catalog) AllowedDestinations() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, provider := range c.Providers {
		for _, baseURL := range provider.BaseURLs {
			destination := NormalizeDestination(baseURL)
			if destination == "" {
				continue
			}
			if _, exists := seen[destination]; exists {
				continue
			}
			seen[destination] = struct{}{}
			out = append(out, destination)
		}
	}
	sort.Strings(out)
	return out
}

func (c Catalog) AllowedDestinationsWithEnv(lookup func(string) (string, bool)) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, destination := range c.AllowedDestinations() {
		seen[destination] = struct{}{}
		out = append(out, destination)
	}
	if lookup != nil {
		for _, provider := range c.Providers {
			for _, baseURL := range provider.DynamicBaseURLs(lookup) {
				destination := NormalizeDestination(baseURL)
				if destination == "" {
					continue
				}
				if _, exists := seen[destination]; exists {
					continue
				}
				seen[destination] = struct{}{}
				out = append(out, destination)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (c Catalog) ProviderIDs() []string {
	out := make([]string, 0, len(c.Providers))
	for _, provider := range c.Providers {
		out = append(out, provider.ID)
	}
	sort.Strings(out)
	return out
}

func (c Catalog) ProvidersForIDs(providerIDs []string) ([]Provider, error) {
	if len(providerIDs) == 0 {
		out := make([]Provider, len(c.Providers))
		copy(out, c.Providers)
		return out, nil
	}
	requested := map[string]struct{}{}
	for _, id := range providerIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if id == "*" {
			out := make([]Provider, len(c.Providers))
			copy(out, c.Providers)
			return out, nil
		}
		requested[id] = struct{}{}
	}
	var out []Provider
	seen := map[string]struct{}{}
	for _, provider := range c.Providers {
		if _, ok := requested[provider.ID]; !ok {
			continue
		}
		out = append(out, provider)
		seen[provider.ID] = struct{}{}
	}
	for id := range requested {
		if _, ok := seen[id]; !ok {
			return nil, fmt.Errorf("unknown model provider id %q", id)
		}
	}
	return out, nil
}

func (c Catalog) EnvGroupsForProviderIDs(providerIDs []string) ([][]string, error) {
	providers, err := c.ProvidersForIDs(providerIDs)
	if err != nil {
		return nil, err
	}
	var out [][]string
	seen := map[string]struct{}{}
	for _, provider := range providers {
		for _, group := range provider.RequiredGroups() {
			group = uniqueSorted(group)
			if len(group) == 0 {
				continue
			}
			key := strings.Join(group, "\x00")
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, group)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Join(out[i], "\x00") < strings.Join(out[j], "\x00")
	})
	return out, nil
}

func (c Catalog) EnvNamesForProviderIDs(providerIDs []string) ([]string, error) {
	providers, err := c.ProvidersForIDs(providerIDs)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []string
	for _, provider := range providers {
		for _, envName := range provider.Env {
			if _, exists := seen[envName]; exists {
				continue
			}
			seen[envName] = struct{}{}
			out = append(out, envName)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (c Catalog) BaseURLsForProviderIDs(providerIDs []string) ([]string, error) {
	return c.BaseURLsForProviderIDsWithEnv(providerIDs, nil)
}

func (c Catalog) BaseURLsForProviderIDsWithEnv(providerIDs []string, lookup func(string) (string, bool)) ([]string, error) {
	providers, err := c.ProvidersForIDs(providerIDs)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []string
	for _, provider := range providers {
		for _, baseURL := range provider.BaseURLs {
			if _, exists := seen[baseURL]; exists {
				continue
			}
			seen[baseURL] = struct{}{}
			out = append(out, baseURL)
		}
		for _, baseURL := range provider.DynamicBaseURLs(lookup) {
			if _, exists := seen[baseURL]; exists {
				continue
			}
			seen[baseURL] = struct{}{}
			out = append(out, baseURL)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (c Catalog) Allows(destination string) bool {
	normalized := NormalizeDestination(destination)
	if normalized == "" {
		return false
	}
	for _, allowed := range c.AllowedDestinations() {
		if normalized == allowed {
			return true
		}
	}
	host := destinationHost(normalized)
	for _, provider := range c.Providers {
		for _, suffix := range provider.AllowedHostSuffixes {
			if hostMatchesSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

func (c Catalog) ProviderIDsForEnv(envName string) []string {
	envName = strings.TrimSpace(envName)
	if envName == "" {
		return nil
	}
	var out []string
	for _, provider := range c.Providers {
		for _, candidate := range provider.Env {
			if candidate == envName {
				out = append(out, provider.ID)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func (c Catalog) ProviderForEnv(envName string) (Provider, bool) {
	envName = strings.TrimSpace(envName)
	if envName == "" {
		return Provider{}, false
	}
	for _, provider := range c.Providers {
		for _, candidate := range provider.Env {
			if candidate == envName {
				return provider, true
			}
		}
	}
	return Provider{}, false
}

func (c Catalog) ProviderForID(providerID string) (Provider, bool) {
	providerID = strings.TrimSpace(providerID)
	if providerID == "" {
		return Provider{}, false
	}
	for _, provider := range c.Providers {
		if provider.ID == providerID {
			return provider, true
		}
	}
	return Provider{}, false
}

func (c Catalog) ProviderForCompleteEnvGroup(lookup func(string) (string, bool)) (Provider, []string, bool) {
	if lookup == nil {
		return Provider{}, nil, false
	}
	for _, provider := range c.Providers {
		for _, group := range provider.RequiredGroups() {
			complete := true
			for _, envName := range group {
				value, ok := lookup(envName)
				if !ok || value == "" {
					complete = false
					break
				}
			}
			if complete {
				return provider, uniqueSorted(group), true
			}
		}
	}
	return Provider{}, nil, false
}

func ValidateAllowlist(allowlist []string) error {
	catalog, err := DefaultCatalog()
	if err != nil {
		return err
	}
	for _, allowed := range allowlist {
		if !catalog.Allows(allowed) {
			return fmt.Errorf("local-container egress allowlist can only contain registered model provider HTTPS endpoints, got %q", allowed)
		}
	}
	return nil
}

func NormalizeDestination(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err == nil && parsed.Host != "" {
		host := parsed.Host
		if !strings.Contains(host, ":") {
			switch parsed.Scheme {
			case "https":
				host += ":443"
			case "http":
				host += ":80"
			default:
				return ""
			}
		}
		return strings.ToLower(host)
	}
	if strings.Contains(trimmed, "://") {
		return ""
	}
	if !strings.Contains(trimmed, ":") {
		trimmed += ":443"
	}
	return strings.ToLower(trimmed)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func normalizeHTTPSURL(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return ""
	}
	path := strings.TrimRight(parsed.EscapedPath(), "/")
	return "https://" + strings.ToLower(parsed.Host) + path
}

func destinationHost(destination string) string {
	host := strings.TrimSpace(destination)
	if idx := strings.LastIndex(host, ":"); idx > -1 {
		host = host[:idx]
	}
	return strings.ToLower(host)
}

func hostMatchesSuffix(host, suffix string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	suffix = strings.ToLower(strings.TrimSpace(suffix))
	if host == "" || suffix == "" {
		return false
	}
	suffix = strings.TrimPrefix(suffix, "*")
	if strings.HasPrefix(suffix, ".") || strings.HasPrefix(suffix, "-") {
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return host == suffix
}

func providerAllowsDynamicBaseURL(provider Provider, baseURL string) bool {
	destination := NormalizeDestination(baseURL)
	if destination == "" {
		return false
	}
	for _, staticBaseURL := range provider.BaseURLs {
		if NormalizeDestination(staticBaseURL) == destination {
			return true
		}
	}
	host := destinationHost(destination)
	for _, suffix := range provider.AllowedHostSuffixes {
		if hostMatchesSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func cloneEnvGroups(groups [][]string) [][]string {
	out := make([][]string, 0, len(groups))
	for _, group := range groups {
		out = append(out, uniqueSorted(group))
	}
	return out
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
