package csr

import (
	"time"
)

// AdapterCapabilities describes what a source adapter can do.
type AdapterCapabilities struct {
	SupportsETag              bool `json:"supports_etag"`
	SupportsConditionalGET    bool `json:"supports_conditional_get"`
	SupportsIncremental       bool `json:"supports_incremental"`
	SupportsSignatureVerify   bool `json:"supports_signature_verify"`
	SupportsStructuredParsing bool `json:"supports_structured_parsing"`
	SupportsFullTextSearch    bool `json:"supports_full_text_search"`
}

// FetchPolicy governs how HELM retrieves data from compliance sources.
// This is a first-class concern because upstream sites actively rate-limit,
// bot-challenge, or restrict access.
type FetchPolicy struct {
	DomainsAllowlist []string      `json:"domains_allowlist"`   // Permitted domains
	MaxBytesPerFetch int64         `json:"max_bytes_per_fetch"` // Max response size
	TimeoutPerFetch  time.Duration `json:"timeout_per_fetch"`   // Per-request timeout
	UserAgent        string        `json:"user_agent"`          // Declared user agent
	RobotsPolicy     string        `json:"robots_policy"`       // "respect", "ignore", "custom"
	RetryPolicy      RetryPolicy   `json:"retry_policy"`
	RateLimitRPS     int           `json:"rate_limit_rps"`           // Max requests/second
	CachePolicy      string        `json:"cache_policy"`             // "always", "etag", "ttl", "none"
	AcceptFormats    []string      `json:"accept_formats,omitempty"` // e.g., ["application/json", "application/xml"]
}

// RetryPolicy defines retry behavior for failed fetches.
type RetryPolicy struct {
	MaxRetries   int           `json:"max_retries"`
	InitialDelay time.Duration `json:"initial_delay"`
	MaxDelay     time.Duration `json:"max_delay"`
	BackoffType  string        `json:"backoff_type"` // "exponential", "linear", "constant"
}

// ChangeDetector defines how HELM detects changes in source content.
type ChangeDetector struct {
	Strategy         string `json:"strategy"`          // "hash", "etag", "last_modified", "sequence", "semantic_version", "structural_diff"
	HashAlgorithm    string `json:"hash_algorithm"`    // "sha256", "sha384", "sha512"
	VersionExtractor string `json:"version_extractor"` // JSONPath or regex for extracting version from response
	DiffMode         string `json:"diff_mode"`         // "full", "incremental", "field_level"
}

// NormalizationProfile defines how to map raw source data into canonical records.
type NormalizationProfile struct {
	ProfileID       string            `json:"profile_id"`
	TargetSchema    string            `json:"target_schema"`   // e.g., "helm://schemas/compliance/GuidanceRecord.v1"
	ParserType      string            `json:"parser_type"`     // "json", "xml", "html", "pdf", "csv"
	FieldMappings   map[string]string `json:"field_mappings"`  // Source field → canonical field
	Transformations []string          `json:"transformations"` // Ordered transform pipeline
	ParserHints     map[string]string `json:"parser_hints"`    // Parser-specific configuration
}

// Bindingness classifies how binding a source's content is.
type Bindingness string

const (
	BindingnessLaw        Bindingness = "LAW"        // Legally binding
	BindingnessRegulation Bindingness = "REGULATION" // Regulatory binding
	BindingnessGuidance   Bindingness = "GUIDANCE"   // Soft law / interpretation
	BindingnessStandard   Bindingness = "STANDARD"   // Industry standard
	BindingnessAdvisory   Bindingness = "ADVISORY"   // Non-binding recommendation
)

// DefaultFetchPolicy returns a sensible default fetch policy.
func DefaultFetchPolicy() FetchPolicy {
	return FetchPolicy{
		MaxBytesPerFetch: 50 * 1024 * 1024, // 50 MB
		TimeoutPerFetch:  30 * time.Second,
		UserAgent:        "HELM-CSR/1.0 (compliance-monitor)",
		RobotsPolicy:     "respect",
		RateLimitRPS:     2,
		CachePolicy:      "etag",
		RetryPolicy: RetryPolicy{
			MaxRetries:   3,
			InitialDelay: 1 * time.Second,
			MaxDelay:     30 * time.Second,
			BackoffType:  "exponential",
		},
	}
}
