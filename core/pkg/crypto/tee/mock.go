package tee

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// MockAttester is a deterministic non-TEE attester for the dev/test loop.
//
// The mock produces a self-signed Ed25519 quote with a stable but explicit
// "MOCK" header. Production verifiers MUST refuse the mock platform unless
// configured to allow it (TrustRoots.AllowMock). This is the only acceptable
// posture: we ship an end-to-end attester for non-confidential dev hosts so
// the rest of the kernel works, but a TrustRoots set without AllowMock cannot
// be satisfied by a mock quote.
//
// Quote format (fixed-size, total 133 bytes):
//
//	magic       [4]byte = 'H','M','O','K'
//	version     uint8   = 1
//	measurement [32]byte
//	nonce       [32]byte
//	sig         [64]byte (ed25519 over magic..nonce)
//
// Determinism: a mock built with NewDeterministicMockAttester(seed) will produce
// byte-identical quotes for the same nonce. This is what powers cross-OS replay
// determinism in tests.
type MockAttester struct {
	measurement [32]byte
	priv        ed25519.PrivateKey
	pub         ed25519.PublicKey
}

// MockQuoteHeader is exposed so tests and verifiers can locate the magic bytes.
const MockQuoteHeader = "HMOK"

// MockQuoteSize is the total fixed size of a mock quote.
const MockQuoteSize = 4 + 1 + 32 + 32 + 64

// NewMockAttester returns a new mock attester with a freshly generated key.
// The measurement is a 32-byte hash of the public key — every mock instance
// has a stable, derivable measurement that test verifiers can pin.
func NewMockAttester() (*MockAttester, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tee/mock: generate key: %w", err)
	}
	return newMockAttesterFromKey(pub, priv), nil
}

// NewDeterministicMockAttester returns a mock attester whose key (and therefore
// measurement) is derived deterministically from seed. Useful in tests that
// rely on byte-identical quotes across runs.
func NewDeterministicMockAttester(seed []byte) *MockAttester {
	h := sha256.Sum256(seed)
	priv := ed25519.NewKeyFromSeed(h[:])
	pub := priv.Public().(ed25519.PublicKey)
	return newMockAttesterFromKey(pub, priv)
}

func newMockAttesterFromKey(pub ed25519.PublicKey, priv ed25519.PrivateKey) *MockAttester {
	measurement := sha256.Sum256(pub)
	return &MockAttester{measurement: measurement, priv: priv, pub: pub}
}

// Platform reports PlatformMock.
func (m *MockAttester) Platform() Platform { return PlatformMock }

// Measurement returns the 32-byte SHA-256(public key) measurement.
func (m *MockAttester) Measurement() ([]byte, error) {
	out := make([]byte, len(m.measurement))
	copy(out, m.measurement[:])
	return out, nil
}

// PublicKey exposes the Ed25519 public key used by this mock instance. Verifiers
// need it to validate the embedded signature.
func (m *MockAttester) PublicKey() ed25519.PublicKey {
	out := make(ed25519.PublicKey, len(m.pub))
	copy(out, m.pub)
	return out
}

// Quote builds a deterministic mock quote bound to nonce.
func (m *MockAttester) Quote(_ context.Context, nonce []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("tee/mock: nonce length %d, expected %d", len(nonce), NonceSize)
	}
	buf := make([]byte, 0, MockQuoteSize)
	buf = append(buf, MockQuoteHeader...)
	buf = append(buf, byte(1))
	buf = append(buf, m.measurement[:]...)
	buf = append(buf, nonce...)
	// The signed pre-image is the entire prefix (magic..nonce). The signature
	// is appended in the trailing 64 bytes.
	sig := ed25519.Sign(m.priv, buf)
	buf = append(buf, sig...)
	return buf, nil
}

// ParseMockQuote breaks a raw mock quote into its fields. Used by the verifier.
func ParseMockQuote(raw []byte) (measurement, nonce, signature []byte, err error) {
	if len(raw) != MockQuoteSize {
		return nil, nil, nil, fmt.Errorf("%w: mock quote size %d, expected %d", ErrMalformedQuote, len(raw), MockQuoteSize)
	}
	if string(raw[0:4]) != MockQuoteHeader {
		return nil, nil, nil, fmt.Errorf("%w: mock quote magic mismatch", ErrMalformedQuote)
	}
	if raw[4] != 1 {
		return nil, nil, nil, fmt.Errorf("%w: mock quote version %d not supported", ErrMalformedQuote, raw[4])
	}
	measurement = make([]byte, 32)
	copy(measurement, raw[5:37])
	nonce = make([]byte, 32)
	copy(nonce, raw[37:69])
	signature = make([]byte, 64)
	copy(signature, raw[69:133])
	return measurement, nonce, signature, nil
}

// VerifyMockQuote checks that a raw mock quote is structurally valid, that its
// nonce matches expectedNonce, and that its signature verifies under pub. It is
// the primitive used by the vendor-agnostic Verify when AllowMock is enabled.
func VerifyMockQuote(raw []byte, expectedNonce []byte, pub ed25519.PublicKey) error {
	_, nonce, sig, err := ParseMockQuote(raw)
	if err != nil {
		return err
	}
	if len(expectedNonce) != NonceSize {
		return fmt.Errorf("tee/mock: expected nonce length %d, got %d", NonceSize, len(expectedNonce))
	}
	if !bytesEqual(nonce, expectedNonce) {
		return ErrNonceMismatch
	}
	signed := raw[:len(raw)-64]
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("tee/mock: pub is not an ed25519 public key")
	}
	if !ed25519.Verify(pub, signed, sig) {
		return fmt.Errorf("%w: mock quote signature verification failed", ErrChainUntrusted)
	}
	return nil
}

// Stable encoding helpers. Avoid importing bytes for a single comparison.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
