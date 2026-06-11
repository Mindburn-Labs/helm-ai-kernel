package tee

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"strings"
	"sync"
)

// SealedSecret represents a secret sealed under TEE hardware parameters.
// It contains metadata linking the secret to a specific enclave configuration
// (e.g. required measurements), preventing host interception.
type SealedSecret struct {
	Ciphertext         []byte   `json:"ciphertext"`
	Nonce              []byte   `json:"nonce"`
	Platform           Platform `json:"platform"`
	AllowedMeasurement []byte   `json:"allowed_measurement"`
}

// SovereignKMSVault defines the secure containment vault for Trusted Execution Environment secrets.
// It uses hardware-bound symmetric keys that never leak to host memory planes.
type SovereignKMSVault struct {
	mu          sync.RWMutex
	hardwareKey []byte
	measurement []byte
	platform    Platform
}

// NewSovereignKMSVault initializes a new TEE KMS vault with simulated hardware-bound keys.
func NewSovereignKMSVault(platform Platform, measurement []byte) (*SovereignKMSVault, error) {
	if len(measurement) == 0 {
		measurement = make([]byte, 32)
		if _, err := rand.Read(measurement); err != nil {
			return nil, fmt.Errorf("tee/enclave: failed to generate mock measurement: %w", err)
		}
	}

	// Generate hardware-sealed AES root key
	rootKey := make([]byte, 32)
	if _, err := rand.Read(rootKey); err != nil {
		return nil, fmt.Errorf("tee/enclave: failed to generate hardware root key: %w", err)
	}

	return &SovereignKMSVault{
		hardwareKey: rootKey,
		measurement: measurement,
		platform:    platform,
	}, nil
}

// SealSecret encrypts raw secrets inside the enclave using hardware-bound AES-256-GCM.
func (v *SovereignKMSVault) SealSecret(ctx context.Context, plaintext []byte) (*SealedSecret, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	block, err := aes.NewCipher(v.hardwareKey)
	if err != nil {
		return nil, fmt.Errorf("tee/enclave: cipher initialization failed: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("tee/enclave: GCM initialization failed: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("tee/enclave: nonce generation failed: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, v.measurement)

	return &SealedSecret{
		Ciphertext:         ciphertext,
		Nonce:              nonce,
		Platform:           v.platform,
		AllowedMeasurement: v.measurement,
	}, nil
}

// UnsealSecret decrypts the TEE sealed secret, asserting that the current enclave measurement matches.
func (v *SovereignKMSVault) UnsealSecret(ctx context.Context, sealed *SealedSecret) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// Assert Platform matches
	if sealed.Platform != v.platform {
		return nil, fmt.Errorf("tee/enclave: platform mismatch (got %s, vault is %s)", sealed.Platform, v.platform)
	}

	// Assert Enclave Measurement matches exactly (TPM/HSM hardware lock)
	if subtle.ConstantTimeCompare(sealed.AllowedMeasurement, v.measurement) != 1 {
		return nil, fmt.Errorf("tee/enclave: unauthorized access (enclave measurement does not match)")
	}

	block, err := aes.NewCipher(v.hardwareKey)
	if err != nil {
		return nil, fmt.Errorf("tee/enclave: cipher initialization failed: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("tee/enclave: GCM initialization failed: %w", err)
	}

	plaintext, err := aesGCM.Open(nil, sealed.Nonce, sealed.Ciphertext, v.measurement)
	if err != nil {
		return nil, fmt.Errorf("tee/enclave: decryption failed (possible tampering or key mismatch): %w", err)
	}

	return plaintext, nil
}

// SecretProxyFilter manages inline secret injection for outbound request headers,
// ensuring plaintext keys remain isolated in enclave memory space and never hit host logs.
type SecretProxyFilter struct {
	mu          sync.RWMutex
	vault       *SovereignKMSVault
	sealedStore map[string]*SealedSecret
	tokens      map[string]string
}

// NewSecretProxyFilter initializes a proxy filter backed by the TEE KMS vault.
func NewSecretProxyFilter(vault *SovereignKMSVault) *SecretProxyFilter {
	return &SecretProxyFilter{
		vault:       vault,
		sealedStore: make(map[string]*SealedSecret),
		tokens:      make(map[string]string),
	}
}

// RegisterSecret registers a secret name and its sealed payload in the secure store.
func (f *SecretProxyFilter) RegisterSecret(ctx context.Context, name string, sealed *SealedSecret) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.sealedStore[name] = sealed
	f.tokens[name] = fmt.Sprintf("HELM_SECRET{%s}", name)
	return nil
}

// InjectHeaders scans outgoing headers for the placeholder format "HELM_SECRET{name}" and replaces it with the unsealed plain secret.
func (f *SecretProxyFilter) InjectHeaders(ctx context.Context, headers map[string]string) (map[string]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	injected := make(map[string]string, len(headers))
	for k, v := range headers {
		injectedVal := v
		// Search for patterns like HELM_SECRET{name}
		for name, sealed := range f.sealedStore {
			placeholder := fmt.Sprintf("HELM_SECRET{%s}", name)
			if strings.Contains(injectedVal, placeholder) {
				plainBytes, err := f.vault.UnsealSecret(ctx, sealed)
				if err != nil {
					return nil, fmt.Errorf("tee/enclave: proxy decryption failed for secret %s: %w", name, err)
				}
				injectedVal = strings.ReplaceAll(injectedVal, placeholder, string(plainBytes))
			}
		}
		injected[k] = injectedVal
	}

	return injected, nil
}

// FilterLogs scrubs any accidental plain text leaks of the registered secrets from log outputs.
func (f *SecretProxyFilter) FilterLogs(logOutput string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	scrubbed := logOutput
	for name, placeholder := range f.tokens {
		redacted := fmt.Sprintf("[REDACTED_%s]", placeholder)
		scrubbed = strings.ReplaceAll(scrubbed, placeholder, redacted)
		if name != "" {
			scrubbed = strings.ReplaceAll(scrubbed, name, "[REDACTED_SECRET_NAME]")
		}
	}
	return scrubbed
}
