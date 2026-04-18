package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"gopkg.in/yaml.v3"
)

// VerificationResult captures the outcome of verifying a PackManifestV2
// against its raw bytes and optionally a claimed manifest hash.
type VerificationResult struct {
	Verified         bool
	VerificationMode string // "signed" or "integrity"
	ManifestHash     string
	Checks           []string
	Errors           []string
}

// LoadManifest reads a manifest from disk (routing YAML/JSON by file
// extension) and returns the parsed PackManifestV2 plus the raw file bytes.
func LoadManifest(path string) (contracts.PackManifestV2, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return contracts.PackManifestV2{}, nil, fmt.Errorf("read manifest: %w", err)
	}
	manifest, err := ParseManifest(data, filepath.Ext(path))
	if err != nil {
		return contracts.PackManifestV2{}, data, err
	}
	return manifest, data, nil
}

// ParseManifest parses manifest bytes as YAML or JSON. ext is the file
// extension (including dot) and routes decoding. YAML is decoded into
// map[string]any, then re-encoded as JSON and decoded into the struct — so
// every field routes through the struct's json tags without a parallel
// yaml-only decoder path.
func ParseManifest(data []byte, ext string) (contracts.PackManifestV2, error) {
	var manifest contracts.PackManifestV2
	switch strings.ToLower(ext) {
	case ".yaml", ".yml":
		var raw map[string]any
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return manifest, fmt.Errorf("parse yaml manifest: %w", err)
		}
		raw = normalizeYAMLMap(raw)
		bridge, err := json.Marshal(raw)
		if err != nil {
			return manifest, fmt.Errorf("re-encode yaml manifest: %w", err)
		}
		if err := json.Unmarshal(bridge, &manifest); err != nil {
			return manifest, fmt.Errorf("decode yaml manifest: %w", err)
		}
	case ".json", "":
		if err := json.Unmarshal(data, &manifest); err != nil {
			return manifest, fmt.Errorf("parse json manifest: %w", err)
		}
	default:
		return manifest, fmt.Errorf("parse manifest: unsupported extension %q", ext)
	}

	// Default channel to community when absent; matches prior behaviour for
	// unsigned/unclassified packs.
	if strings.TrimSpace(string(manifest.Channel)) == "" {
		manifest.Channel = contracts.PackChannelCommunity
	}
	return manifest, nil
}

// Verify checks that data hashes to claimedHash (when non-empty) and that
// the manifest contains the minimum fields required to install it.
func Verify(manifest contracts.PackManifestV2, data []byte, claimedHash string) VerificationResult {
	result := VerificationResult{
		Verified:     true,
		ManifestHash: ComputeManifestHash(data),
		Checks:       []string{"manifest loaded", "manifest hash recomputed"},
	}
	if claimedHash != "" && claimedHash != result.ManifestHash {
		result.Verified = false
		result.Errors = append(result.Errors, fmt.Sprintf("manifest hash mismatch: claimed=%s computed=%s", claimedHash, result.ManifestHash))
	}
	if strings.TrimSpace(manifest.PackID) == "" {
		result.Verified = false
		result.Errors = append(result.Errors, "manifest missing pack_id")
	}
	if strings.TrimSpace(manifest.Name) == "" {
		result.Verified = false
		result.Errors = append(result.Errors, "manifest missing name")
	}
	if strings.TrimSpace(manifest.Version) == "" {
		result.Verified = false
		result.Errors = append(result.Errors, "manifest missing version")
	}
	if strings.TrimSpace(string(manifest.Channel)) == "" {
		result.Verified = false
		result.Errors = append(result.Errors, "manifest missing channel")
	}

	if len(manifest.Signatures) > 0 {
		result.VerificationMode = "signed"
		result.Checks = append(result.Checks, "publisher signature present")
	} else {
		result.VerificationMode = "integrity"
		result.Checks = append(result.Checks, "no publisher signature; integrity-only verification")
	}
	return result
}

// ComputeManifestHash returns the "sha256:<hex>" content hash for data.
func ComputeManifestHash(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// canonicalManifestBytes returns a stable JSON encoding of manifest for
// hashing. Fields are encoded via the struct's json tags.
func canonicalManifestBytes(manifest contracts.PackManifestV2) []byte {
	data, err := json.Marshal(manifest)
	if err != nil {
		// Unreachable for a valid PackManifestV2, but surface a deterministic
		// fallback rather than panic.
		return []byte(fmt.Sprintf("ERROR:%s", err.Error()))
	}
	return data
}

// normalizeYAMLMap recursively converts map[any]any values emitted by
// yaml.v3 for nested maps into map[string]any so downstream json.Marshal
// works without custom marshalers. []any elements are normalized in place.
func normalizeYAMLMap(in map[string]any) map[string]any {
	for k, v := range in {
		in[k] = normalizeYAMLValue(v)
	}
	return in
}

func normalizeYAMLValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return normalizeYAMLMap(t)
	case map[any]any:
		converted := make(map[string]any, len(t))
		for k, inner := range t {
			converted[fmt.Sprintf("%v", k)] = normalizeYAMLValue(inner)
		}
		return converted
	case []any:
		for i, item := range t {
			t[i] = normalizeYAMLValue(item)
		}
		return t
	default:
		return v
	}
}
