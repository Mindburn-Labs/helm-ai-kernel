package collateral

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Provider identifies a TEE collateral source.
type Provider string

const (
	ProviderAMDKDS   Provider = "amd-kds"
	ProviderIntelPCS Provider = "intel-pcs"
)

// Document records one offline collateral blob and its expected digest.
type Document struct {
	Name      string    `json:"name"`
	Provider  Provider  `json:"provider"`
	URL       string    `json:"url,omitempty"`
	SHA256    string    `json:"sha256"`
	NotAfter  time.Time `json:"not_after"`
	Body      string    `json:"body"`
	FetchedAt time.Time `json:"fetched_at"`
}

// Bundle is an offline, reviewable collateral fixture.
type Bundle struct {
	GeneratedAt time.Time  `json:"generated_at"`
	Documents   []Document `json:"documents"`
}

// Load reads a collateral bundle from disk.
func Load(path string) (Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Bundle{}, err
	}
	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return Bundle{}, fmt.Errorf("tee/collateral: decode bundle: %w", err)
	}
	return bundle, nil
}

// Validate verifies provider names, expiry, and embedded body digests.
func Validate(bundle Bundle, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if bundle.GeneratedAt.IsZero() {
		return fmt.Errorf("tee/collateral: generated_at is required")
	}
	if len(bundle.Documents) == 0 {
		return fmt.Errorf("tee/collateral: at least one document is required")
	}
	for _, doc := range bundle.Documents {
		if strings.TrimSpace(doc.Name) == "" {
			return fmt.Errorf("tee/collateral: document name is required")
		}
		switch doc.Provider {
		case ProviderAMDKDS, ProviderIntelPCS:
		default:
			return fmt.Errorf("tee/collateral: unsupported provider %q", doc.Provider)
		}
		if doc.NotAfter.IsZero() || !now.Before(doc.NotAfter) {
			return fmt.Errorf("tee/collateral: document %q is expired or missing not_after", doc.Name)
		}
		if strings.TrimSpace(doc.Body) == "" {
			return fmt.Errorf("tee/collateral: document %q body is required", doc.Name)
		}
		if normalizeDigest(doc.SHA256) != digest(doc.Body) {
			return fmt.Errorf("tee/collateral: document %q sha256 mismatch", doc.Name)
		}
	}
	return nil
}

func digest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func normalizeDigest(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "sha256:")
	return value
}
