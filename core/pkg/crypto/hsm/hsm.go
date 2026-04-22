// Package hsm provides Hardware Security Module abstraction for HELM.
// This package enables hardware-backed cryptographic key protection for
// high-security deployments requiring FIPS 140-2/3 compliance.
//
// Two providers ship with HELM OSS:
//   - SoftwareProvider: uses real crypto/ed25519 for development and testing
//   - PKCS11Provider: interface + config for production HSM integration
//     (requires platform-specific PKCS#11 library)
package hsm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Common errors
var (
	ErrNotInitialized    = errors.New("hsm: not initialized")
	ErrSessionClosed     = errors.New("hsm: session closed")
	ErrKeyNotFound       = errors.New("hsm: key not found")
	ErrOperationFailed   = errors.New("hsm: operation failed")
	ErrInvalidKeyHandle  = errors.New("hsm: invalid key handle")
	ErrNotSupported      = errors.New("hsm: operation not supported")
	ErrAuthenticationReq = errors.New("hsm: authentication required")
	ErrPKCS11NotLinked   = errors.New("hsm: PKCS#11 library not linked — use SoftwareProvider for development or provide a PKCS#11 shared library")
)

// KeyHandle is an opaque reference to a key stored in the HSM.
type KeyHandle string

// Algorithm represents supported key algorithms.
type Algorithm int

const (
	AlgorithmEd25519   Algorithm = iota // Default for HELM — deterministic, fast
	AlgorithmECDSAP256                  // NIST P-256
	AlgorithmECDSAP384                  // NIST P-384
	AlgorithmRSA2048                    // RSA 2048-bit
	AlgorithmRSA4096                    // RSA 4096-bit
)

func (a Algorithm) String() string {
	names := map[Algorithm]string{
		AlgorithmEd25519:   "Ed25519",
		AlgorithmECDSAP256: "ECDSA-P256",
		AlgorithmECDSAP384: "ECDSA-P384",
		AlgorithmRSA2048:   "RSA-2048",
		AlgorithmRSA4096:   "RSA-4096",
	}
	if name, ok := names[a]; ok {
		return name
	}
	return "Unknown"
}

// KeyUsage specifies permitted key operations.
type KeyUsage int

const (
	KeyUsageSign KeyUsage = 1 << iota
	KeyUsageVerify
	KeyUsageEncrypt
	KeyUsageDecrypt
)

// KeyInfo provides metadata about a stored key.
type KeyInfo struct {
	Handle      KeyHandle
	Label       string
	Algorithm   Algorithm
	Usage       KeyUsage
	Extractable bool
	CreatedAt   time.Time
	ExpiresAt   *time.Time
}

// KeyGenOpts specifies key generation options.
type KeyGenOpts struct {
	Algorithm   Algorithm
	Label       string
	Extractable bool
	Usage       KeyUsage
	ExpiresIn   time.Duration
}

// SignOpts specifies signing options.
type SignOpts struct {
	HashAlgorithm crypto.Hash
}

// Provider defines the HSM abstraction interface.
type Provider interface {
	Open(ctx context.Context) error
	Close() error
	IsOpen() bool
	GenerateKey(ctx context.Context, opts KeyGenOpts) (KeyHandle, error)
	Sign(ctx context.Context, handle KeyHandle, message []byte, opts SignOpts) ([]byte, error)
	Verify(ctx context.Context, handle KeyHandle, message, signature []byte) (bool, error)
	GetKeyInfo(ctx context.Context, handle KeyHandle) (*KeyInfo, error)
	ListKeys(ctx context.Context) ([]KeyInfo, error)
	DeleteKey(ctx context.Context, handle KeyHandle) error
	Name() string
	Capabilities() Capabilities
}

// Capabilities describes what the provider supports.
type Capabilities struct {
	SupportsEd25519     bool
	SupportsECDSA       bool
	MaxKeySize          int
	SupportedAlgorithms []Algorithm
	FIPSLevel           int // 0 = not certified, 2 = Level 2, 3 = Level 3
}

// ===== Software Provider (real crypto) =====

// SoftwareProvider implements Provider using real software-based cryptography.
// Uses crypto/ed25519 for signing and verification — real cryptographic
// operations, not stubs.
type SoftwareProvider struct {
	keys       map[KeyHandle]*softwareKey
	keyCounter int
	isOpen     bool
	mu         sync.RWMutex
}

type softwareKey struct {
	info    *KeyInfo
	privKey crypto.PrivateKey
	pubKey  crypto.PublicKey
}

// NewSoftwareProvider creates a software-only provider with real
// Ed25519 and ECDSA-P256 cryptography.
func NewSoftwareProvider() *SoftwareProvider {
	return &SoftwareProvider{
		keys: make(map[KeyHandle]*softwareKey),
	}
}

func (p *SoftwareProvider) Name() string { return "Software (Ed25519)" }
func (p *SoftwareProvider) Capabilities() Capabilities {
	return Capabilities{
		SupportsEd25519:     true,
		SupportsECDSA:       true,
		MaxKeySize:          256,
		SupportedAlgorithms: []Algorithm{AlgorithmEd25519, AlgorithmECDSAP256},
		FIPSLevel:           0,
	}
}

func (p *SoftwareProvider) Open(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.isOpen = true
	return nil
}

func (p *SoftwareProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.isOpen = false
	return nil
}

func (p *SoftwareProvider) IsOpen() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.isOpen
}

func (p *SoftwareProvider) GenerateKey(ctx context.Context, opts KeyGenOpts) (KeyHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.isOpen {
		return "", ErrNotInitialized
	}

	p.keyCounter++
	handle := KeyHandle(fmt.Sprintf("sw-%d", p.keyCounter))

	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey

	switch opts.Algorithm {
	case AlgorithmEd25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", fmt.Errorf("hsm: ed25519 keygen: %w", err)
		}
		privKey = priv
		pubKey = pub
	case AlgorithmECDSAP256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", fmt.Errorf("hsm: ecdsa keygen: %w", err)
		}
		privKey = key
		pubKey = &key.PublicKey
	default:
		return "", fmt.Errorf("hsm: unsupported algorithm %s for software provider", opts.Algorithm)
	}

	info := &KeyInfo{
		Handle:      handle,
		Label:       opts.Label,
		Algorithm:   opts.Algorithm,
		Usage:       opts.Usage,
		Extractable: true,
		CreatedAt:   time.Now(),
	}
	if opts.ExpiresIn > 0 {
		expiry := time.Now().Add(opts.ExpiresIn)
		info.ExpiresAt = &expiry
	}

	p.keys[handle] = &softwareKey{info: info, privKey: privKey, pubKey: pubKey}
	return handle, nil
}

func (p *SoftwareProvider) Sign(ctx context.Context, handle KeyHandle, message []byte, opts SignOpts) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.isOpen {
		return nil, ErrNotInitialized
	}
	k, ok := p.keys[handle]
	if !ok {
		return nil, ErrKeyNotFound
	}
	if k.info.Usage&KeyUsageSign == 0 {
		return nil, fmt.Errorf("hsm: key %s does not permit signing", handle)
	}

	switch priv := k.privKey.(type) {
	case ed25519.PrivateKey:
		return ed25519.Sign(priv, message), nil
	case *ecdsa.PrivateKey:
		hash := sha256.Sum256(message)
		return ecdsa.SignASN1(rand.Reader, priv, hash[:])
	default:
		return nil, ErrNotSupported
	}
}

func (p *SoftwareProvider) Verify(ctx context.Context, handle KeyHandle, message, signature []byte) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.isOpen {
		return false, ErrNotInitialized
	}
	k, ok := p.keys[handle]
	if !ok {
		return false, ErrKeyNotFound
	}

	switch pub := k.pubKey.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(pub, message, signature), nil
	case *ecdsa.PublicKey:
		hash := sha256.Sum256(message)
		return ecdsa.VerifyASN1(pub, hash[:], signature), nil
	default:
		return false, ErrNotSupported
	}
}

func (p *SoftwareProvider) GetKeyInfo(ctx context.Context, handle KeyHandle) (*KeyInfo, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.isOpen {
		return nil, ErrNotInitialized
	}
	k, ok := p.keys[handle]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return k.info, nil
}

func (p *SoftwareProvider) ListKeys(ctx context.Context) ([]KeyInfo, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.isOpen {
		return nil, ErrNotInitialized
	}
	keys := make([]KeyInfo, 0, len(p.keys))
	for _, k := range p.keys {
		keys = append(keys, *k.info)
	}
	return keys, nil
}

func (p *SoftwareProvider) DeleteKey(ctx context.Context, handle KeyHandle) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.isOpen {
		return ErrNotInitialized
	}
	delete(p.keys, handle)
	return nil
}

// ===== PKCS#11 Provider (integration point) =====

// PKCS11Config configures the PKCS#11 provider.
type PKCS11Config struct {
	LibraryPath string // Path to PKCS#11 shared library (.so / .dylib)
	SlotID      uint
	PIN         string // Should come from environment/secret manager
	TokenLabel  string
}

// PKCS11Provider implements Provider using an external PKCS#11 library.
// This is the production integration point for hardware HSMs (Thales Luna,
// AWS CloudHSM, YubiHSM, etc.).
//
// To use: provide a PKCS#11 shared library path in config. The provider
// delegates all cryptographic operations to the HSM hardware via PKCS#11.
//
// Note: HELM OSS ships this as an integration interface. The actual PKCS#11
// binding requires a platform-specific library (e.g., github.com/miekg/pkcs11).
// For development and testing, use SoftwareProvider instead.
type PKCS11Provider struct {
	config PKCS11Config
}

// NewPKCS11Provider creates a PKCS#11 provider.
// Returns ErrPKCS11NotLinked because HELM OSS does not bundle a PKCS#11
// library. To use hardware HSMs, implement the Provider interface with
// your platform's PKCS#11 binding.
func NewPKCS11Provider(cfg PKCS11Config) (*PKCS11Provider, error) {
	return nil, ErrPKCS11NotLinked
}
