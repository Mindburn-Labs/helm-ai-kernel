package tooling

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalJSON produces RFC 8785 JCS-compatible canonical JSON.
// This ensures byte-for-byte reproducibility for policy normalization.
func CanonicalJSON(v interface{}) ([]byte, error) {
	// First serialize to intermediate form to work with generic structures
	intermediate, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("initial marshal failed: %w", err)
	}

	var parsed interface{}
	if err := json.Unmarshal(intermediate, &parsed); err != nil {
		return nil, fmt.Errorf("intermediate unmarshal failed: %w", err)
	}

	// Process to canonical form
	canonical, err := canonicalize(parsed)
	if err != nil {
		return nil, err
	}

	// Final marshal without extra whitespace (compact)
	return json.Marshal(canonical)
}

// canonicalize recursively processes values to canonical form.
func canonicalize(v interface{}) (interface{}, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		return canonicalizeObject(val)
	case []interface{}:
		return canonicalizeArray(val)
	case float64:
		// JSON numbers: handle integer vs float
		if val == float64(int64(val)) {
			return int64(val), nil
		}
		return val, nil
	case string, bool, nil:
		return val, nil
	default:
		// For other types, try to marshal/unmarshal
		return val, nil
	}
}

// canonicalizeObject sorts keys and recursively canonicalizes values.
func canonicalizeObject(m map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// Get sorted keys
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Process values in key order
	for _, k := range keys {
		canonical, err := canonicalize(m[k])
		if err != nil {
			return nil, fmt.Errorf("failed to canonicalize key %q: %w", k, err)
		}
		result[k] = canonical
	}

	return result, nil
}

// canonicalizeArray recursively canonicalizes array elements.
func canonicalizeArray(arr []interface{}) ([]interface{}, error) {
	result := make([]interface{}, len(arr))
	for i, v := range arr {
		canonical, err := canonicalize(v)
		if err != nil {
			return nil, fmt.Errorf("failed to canonicalize array index %d: %w", i, err)
		}
		result[i] = canonical
	}
	return result, nil
}

// PolicyInputBundle represents a normalized firewall policy input.
// This is a simplified version for tooling package independence.
type PolicyInputBundle struct {
	RequestID       string                 `json:"request_id"`
	EffectType      string                 `json:"effect_type"`
	ToolID          string                 `json:"tool_id,omitempty"`
	ToolFingerprint string                 `json:"tool_fingerprint,omitempty"`
	Principal       string                 `json:"principal"`
	Target          string                 `json:"target"`
	Payload         map[string]interface{} `json:"payload"`
	Context         map[string]interface{} `json:"context,omitempty"`
}

// NormalizeBundle produces a canonical JSON representation of a PolicyInputBundle.
// The output is deterministic and suitable for hashing.
func NormalizeBundle(bundle *PolicyInputBundle) ([]byte, error) {
	if bundle == nil {
		return nil, fmt.Errorf("bundle cannot be nil")
	}

	// Canonicalize the bundle
	canonical, err := CanonicalJSON(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize bundle: %w", err)
	}

	return canonical, nil
}

// BundleHash computes a SHA-256 hash of a normalized bundle.
func BundleHash(bundle *PolicyInputBundle) (string, error) {
	normalized, err := NormalizeBundle(bundle)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(normalized)
	return hex.EncodeToString(hash[:]), nil
}

// NormalizationEquivalent checks if two bundles normalize to the same bytes.
func NormalizationEquivalent(a, b *PolicyInputBundle) (bool, error) {
	normA, err := NormalizeBundle(a)
	if err != nil {
		return false, err
	}
	normB, err := NormalizeBundle(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(normA, normB), nil
}
