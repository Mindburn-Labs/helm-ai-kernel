// Package kernel provides SecretRef handling per Normative Addendum 8.X.
package kernel

import (
	"fmt"
	"regexp"
	"time"
)

// SecretProvider identifiers for supported secret stores.
type SecretProvider string

const (
	SecretProviderVault      SecretProvider = "vault"
	SecretProviderAWSSecrets SecretProvider = "aws-secretsmanager"
	SecretProviderGCPSecrets SecretProvider = "gcp-secretmanager"
	SecretProviderAzureKV    SecretProvider = "azure-keyvault"
	SecretProviderK8sSecrets SecretProvider = "kubernetes-secrets" //nolint:gosec // Identifier, not a secret
	SecretProviderEnv        SecretProvider = "env"
)

// MaterializationScope defines when a secret is resolved.
type MaterializationScope string

const (
	// MaterializationScopeRuntime indicates runtime resolution.
	MaterializationScopeRuntime MaterializationScope = "runtime"
	// MaterializationScopeBuildTime indicates build-time injection.
	MaterializationScopeBuildTime MaterializationScope = "build_time"
)

// SecretRef references a secret without containing the actual value.
// Per Addendum 8.X: Secrets MUST NOT appear in EvidencePacks.
type SecretRef struct {
	RefID                string               `json:"ref_id"`
	Provider             SecretProvider       `json:"provider"`
	Path                 string               `json:"path"`
	Version              string               `json:"version,omitempty"`
	MaterializationScope MaterializationScope `json:"materialization_scope"`
	AuditOnAccess        bool                 `json:"audit_on_access"`
	RotationPolicyID     string               `json:"rotation_policy_id,omitempty"`
}

// ValidateSecretRef validates a secret reference.
func ValidateSecretRef(ref SecretRef) error {
	if ref.RefID == "" {
		return fmt.Errorf("secret_ref: ref_id is required")
	}
	if ref.Provider == "" {
		return fmt.Errorf("secret_ref: provider is required")
	}
	if ref.Path == "" {
		return fmt.Errorf("secret_ref: path is required")
	}
	if ref.MaterializationScope == "" {
		return fmt.Errorf("secret_ref: materialization_scope is required")
	}

	// Validate provider
	validProviders := map[SecretProvider]bool{
		SecretProviderVault:      true,
		SecretProviderAWSSecrets: true,
		SecretProviderGCPSecrets: true,
		SecretProviderAzureKV:    true,
		SecretProviderK8sSecrets: true,
		SecretProviderEnv:        true,
	}
	if !validProviders[ref.Provider] {
		return fmt.Errorf("secret_ref: unknown provider %q", ref.Provider)
	}

	// Validate scope
	if ref.MaterializationScope != MaterializationScopeRuntime &&
		ref.MaterializationScope != MaterializationScopeBuildTime {
		return fmt.Errorf("secret_ref: invalid materialization_scope %q", ref.MaterializationScope)
	}

	return nil
}

// EnvelopeRef references envelope-encrypted data.
// Per Addendum 8.X.5: Large data encrypted under DEK, wrapped by KEK.
type EnvelopeRef struct {
	RefID           string `json:"ref_id"`
	WrappedKeyID    string `json:"wrapped_key_id"`
	Algorithm       string `json:"algorithm"`
	CiphertextHash  string `json:"ciphertext_hash"`
	StorageLocation string `json:"storage_location"`
}

// ValidateEnvelopeRef validates an envelope reference.
// NOTE: Function intentionally removed - was dead code.

// CryptoShredPolicy defines when data encryption keys should be deleted.
type CryptoShredPolicy struct {
	PolicyID          string        `json:"policy_id"`
	Scope             string        `json:"scope"`              // "record", "tenant", "jurisdiction"
	TriggerConditions []string      `json:"trigger_conditions"` // Events that trigger shredding
	RetentionPeriod   time.Duration `json:"retention_period"`
	GracePeriod       time.Duration `json:"grace_period"`
}

// CryptoShredEvent records a crypto-shredding operation.
type CryptoShredEvent struct {
	EventID          string    `json:"event_id"`
	PolicyID         string    `json:"policy_id"`
	KeyIDs           []string  `json:"key_ids"` // DEKs that were shredded
	Scope            string    `json:"scope"`
	ScopeIdentifier  string    `json:"scope_identifier"` // tenant_id, record_id, etc.
	ShreddedAt       time.Time `json:"shredded_at"`
	VerificationHash string    `json:"verification_hash"` // Proof that keys were destroyed
}

// RetentionPolicy defines data retention rules.
type RetentionPolicy struct {
	PolicyID           string        `json:"policy_id"`
	DataClassification string        `json:"data_classification"` // PII, financial, etc.
	RetentionPeriod    time.Duration `json:"retention_period"`
	LegalHoldOverride  bool          `json:"legal_hold_override"`
	DeletionMethod     string        `json:"deletion_method"` // "soft", "crypto_shred", "hard"
	JurisdictionRules  []string      `json:"jurisdiction_rules,omitempty"`
}

// SecretAccessAuditEntry records secret access for audit.
type SecretAccessAuditEntry struct {
	EntryID           string    `json:"entry_id"`
	RefID             string    `json:"ref_id"`
	ActorID           string    `json:"actor_id"`
	AccessedAt        time.Time `json:"accessed_at"`
	AccessType        string    `json:"access_type"` // "read", "rotate", "delete"
	EffectID          string    `json:"effect_id,omitempty"`
	SessionID         string    `json:"session_id"`
	JustificationHash string    `json:"justification_hash,omitempty"`
}

// ScanForPlaintextSecrets recurses through an artifact to find plaintext secrets.
// Implements Addendum 8.X.7 logic.
func ScanForPlaintextSecrets(artifact interface{}) error {
	return walkJSON(artifact, func(path string, value interface{}) error {
		// Check if key suggests sensitivity
		if isSecretKey(path) {
			if _, ok := value.(string); ok {
				return fmt.Errorf("plaintext secret detected at %s (key implies secret)", path)
			}
		}

		// Check if value looks like a secret
		if looksLikeSecret(value) {
			return fmt.Errorf("plaintext secret detected at %s", path)
		}
		return nil
	})
}

func isSecretKey(path string) bool {
	// Simple heuristic: check suffix of path
	// In a robust implementation, we'd split path by '.' and check the last segment
	// Since we don't have strings imported, we rely on regex or simple checks.
	// But let's assume we can use regex.
	// Or check the mock patterns.

	sensitiveKeys := []string{
		`password$`,
		`api_key$`,
		`secret$`,
		`secret_key$`,
	}

	for _, p := range sensitiveKeys {
		if regexp.MustCompile("(?i)" + p).MatchString(path) {
			return true
		}
	}
	return false
}

func looksLikeSecret(value interface{}) bool {
	str, ok := value.(string)
	if !ok {
		return false
	}

	patterns := []string{
		`-----BEGIN.*PRIVATE KEY-----`,
		`^sk_live_`,
		`^AKIA[0-9A-Z]{16}$`,
		`(?i)password\W*[:=]\W*\w+`,
		`(?i)secret\W*[:=]\W*\w+`,
	}

	for _, p := range patterns {
		if regexp.MustCompile(p).MatchString(str) {
			return true
		}
	}
	return false
}

// walkJSON is a helper for recursive traversal
func walkJSON(v interface{}, visit func(path string, value interface{}) error) error {
	return walkJSONRecursive(v, "", visit)
}

func walkJSONRecursive(v interface{}, path string, visit func(path string, value interface{}) error) error {
	if err := visit(path, v); err != nil {
		return err
	}

	switch val := v.(type) {
	case map[string]interface{}:
		for k, elem := range val {
			newPath := k
			if path != "" {
				newPath = path + "." + k
			}
			if err := walkJSONRecursive(elem, newPath, visit); err != nil {
				return err
			}
		}
	case []interface{}:
		for i, elem := range val {
			newPath := fmt.Sprintf("%s[%d]", path, i)
			if err := walkJSONRecursive(elem, newPath, visit); err != nil {
				return err
			}
		}
	}
	return nil
}
