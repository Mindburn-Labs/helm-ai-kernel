// Package manifest defines the Integration Manifest v1 schema for HELM's
// Integration Fabric. A manifest is the single source of truth for a connector:
// its provider metadata, auth methods, capabilities, runtime binding, default
// policies, evidence rules, tests, and UI metadata for non-technical installation.
package manifest

import (
	"encoding/json"
	"time"
)

// APIVersion is the current manifest schema version.
const APIVersion = "integrations.helm.mindburn.run/v1"

// IntegrationManifest is the top-level manifest for an integration connector.
// It describes everything needed to install, connect, certify, operate, drift-check,
// upgrade, and decommission a connector.
type IntegrationManifest struct {
	APIVersion string           `json:"api_version"` // Must be APIVersion.
	Provider   ProviderMeta     `json:"provider"`
	Connector  ConnectorMeta    `json:"connector"`
	Auth       AuthSpec         `json:"auth"`
	Caps       []CapabilitySpec `json:"capabilities"`
	Runtime    RuntimeBinding   `json:"runtime"`
	Policies   DefaultPolicies  `json:"policies_default"`
	Evidence   EvidenceDefaults `json:"evidence_default"`
	Tests      TestSuite        `json:"tests"`
	UI         UIMetadata       `json:"ui"`
}

// ProviderMeta identifies the external service provider.
type ProviderMeta struct {
	ID       string `json:"id"`       // e.g. "github"
	Name     string `json:"name"`     // e.g. "GitHub"
	Category string `json:"category"` // e.g. "developer_tools", "crm", "payments"
	Homepage string `json:"homepage,omitempty"`
	IconURL  string `json:"icon_url,omitempty"`
}

// ConnectorMeta describes the connector package itself.
type ConnectorMeta struct {
	ID             string    `json:"id"`              // e.g. "github-v1"
	Version        string    `json:"version"`         // semver, e.g. "1.2.0"
	Packaging      string    `json:"packaging"`       // "builtin", "manifest", "pack"
	ArtifactDigest string    `json:"artifact_digest"` // "sha256:<hex>"
	CreatedAt      time.Time `json:"created_at,omitempty"`
}

// AuthSpec describes the authentication requirements for a connector.
type AuthSpec struct {
	Methods []AuthMethod `json:"methods"` // At least one required.
	Scopes  []string     `json:"scopes,omitempty"`
}

// AuthMethod describes a single authentication method.
type AuthMethod struct {
	Type          string            `json:"type"` // "oauth2", "apikey", "basic", "none", "mtls", "webauthn"
	OAuthConfig   *OAuthMethodSpec  `json:"oauth_config,omitempty"`
	APIKeyConfig  *APIKeyMethodSpec `json:"apikey_config,omitempty"`
	ExtraHeaders  map[string]string `json:"extra_headers,omitempty"`
	ExtraParams   map[string]string `json:"extra_params,omitempty"`
	TokenEndpoint string            `json:"token_endpoint,omitempty"`
	TokenMethod   string            `json:"token_method,omitempty"` // "post_body", "basic_auth"
	PKCESupported bool              `json:"pkce_supported,omitempty"`
}

// OAuthMethodSpec contains OAuth-specific configuration — absorbs provider_config.go quirks.
type OAuthMethodSpec struct {
	AuthorizationURL string   `json:"authorization_url"`
	TokenURL         string   `json:"token_url"`
	UserInfoURL      string   `json:"user_info_url,omitempty"`
	RevokeURL        string   `json:"revoke_url,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	// Provider-specific quirks.
	AcceptHeader       string `json:"accept_header,omitempty"`        // e.g. "application/json" for GitHub
	TokenResponseStyle string `json:"token_response_style,omitempty"` // "json" or "form"
}

// APIKeyMethodSpec contains API key configuration.
type APIKeyMethodSpec struct {
	Header string `json:"header"` // e.g. "Authorization", "X-API-Key"
	Prefix string `json:"prefix"` // e.g. "Bearer ", "token "
}

// CapabilitySpec describes a single capability exposed by the connector.
type CapabilitySpec struct {
	URN          string          `json:"urn"`                    // cap://<provider>/<action>@<version>
	Name         string          `json:"name"`                   // Human-readable name.
	Description  string          `json:"description"`            // What this capability does.
	RiskClass    string          `json:"risk_class"`             // "E0", "E1", "E2", "E3", "E4"
	InputSchema  json.RawMessage `json:"input_schema,omitempty"` // JSON Schema for inputs.
	OutputSchema json.RawMessage `json:"output_schema,omitempty"`
	Idempotent   bool            `json:"idempotent"`
	Rollback     bool            `json:"rollback"` // True if the effect can be reversed.
}

// RuntimeBinding specifies which runtime executes this connector's capabilities.
type RuntimeBinding struct {
	Kind   RuntimeKind     `json:"kind"`             // mcp, http, webhook, scrape, browser, cli, infra, llm_spec
	Config json.RawMessage `json:"config,omitempty"` // Kind-specific configuration.
}

// RuntimeKind is the type of runtime that executes a connector's capabilities.
type RuntimeKind string

const (
	RuntimeMCP     RuntimeKind = "mcp"
	RuntimeHTTP    RuntimeKind = "http"
	RuntimeLLMSpec RuntimeKind = "llm_spec"
	RuntimeWebhook RuntimeKind = "webhook"
	RuntimeScrape  RuntimeKind = "scrape"
	RuntimeBrowser RuntimeKind = "browser"
	RuntimeCLI     RuntimeKind = "cli"
	RuntimeInfra   RuntimeKind = "infra"
)

// AllRuntimeKinds returns every defined runtime kind.
func AllRuntimeKinds() []RuntimeKind {
	return []RuntimeKind{
		RuntimeMCP, RuntimeHTTP, RuntimeLLMSpec, RuntimeWebhook,
		RuntimeScrape, RuntimeBrowser, RuntimeCLI, RuntimeInfra,
	}
}

// DefaultPolicies are the connector's recommended budget/policy defaults.
type DefaultPolicies struct {
	MaxRequestsPerMinute int      `json:"max_requests_per_minute,omitempty"`
	MaxCostCentsPerDay   int64    `json:"max_cost_cents_per_day,omitempty"`
	HostAllowlist        []string `json:"host_allowlist,omitempty"`
	DataClassRestriction []string `json:"data_class_restriction,omitempty"` // e.g. "pii", "financial"
}

// EvidenceDefaults specify how evidence from this connector should be retained.
type EvidenceDefaults struct {
	RetentionDays  int      `json:"retention_days,omitempty"`
	RedactionRules []string `json:"redaction_rules,omitempty"` // Fields to redact in evidence.
}

// TestSuite defines test probes for the connector.
type TestSuite struct {
	Smoke    []TestProbe `json:"smoke,omitempty"`    // Quick health/connectivity checks.
	Contract []TestProbe `json:"contract,omitempty"` // Schema conformance assertions.
	Drift    []TestProbe `json:"drift,omitempty"`    // Periodic drift detection probes.
}

// TestProbe describes a single test assertion for a connector.
type TestProbe struct {
	Name           string          `json:"name"`
	CapabilityURN  string          `json:"capability_urn"`
	Input          json.RawMessage `json:"input,omitempty"`
	ExpectStatus   int             `json:"expect_status,omitempty"`
	ExpectSchema   json.RawMessage `json:"expect_schema,omitempty"`
	TimeoutSeconds int             `json:"timeout_seconds,omitempty"`
}

// UIMetadata provides information for non-technical users in the Library and
// inline install proposals in chat.
type UIMetadata struct {
	Category         string            `json:"category"`                   // For Library grouping.
	IconURL          string            `json:"icon_url,omitempty"`         // Provider icon.
	ShortDescription string            `json:"short_description"`          // One-line for search results.
	LongDescription  string            `json:"long_description,omitempty"` // Markdown for detail view.
	InstallSteps     []InstallStep     `json:"install_steps,omitempty"`    // Ordered steps.
	PermissionCopy   map[string]string `json:"permission_copy,omitempty"`  // Scope → human-readable description.
	Warnings         []string          `json:"warnings,omitempty"`         // Risk warnings.
}

// InstallStep describes a single step in the connector installation flow.
type InstallStep struct {
	Order       int    `json:"order"`
	ActionType  string `json:"action_type"` // "oauth_connect", "api_key_input", "scope_approval", "custom"
	Title       string `json:"title"`
	Description string `json:"description"`
	Optional    bool   `json:"optional,omitempty"`
}
