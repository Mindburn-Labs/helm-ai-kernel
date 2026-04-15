package crypto

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHybridSigner_NewHybridSigner(t *testing.T) {
	signer, err := NewHybridSigner("hybrid-key-1")
	require.NoError(t, err)
	require.NotNil(t, signer)
	assert.NotNil(t, signer.Ed25519Signer())
	assert.NotNil(t, signer.MLDSASigner())
}

func TestHybridSigner_SignProducesHybridFormat(t *testing.T) {
	signer, err := NewHybridSigner("hybrid-key-1")
	require.NoError(t, err)

	data := []byte("test data for hybrid signing")
	sig, err := signer.Sign(data)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(sig, HybridSigPrefix+HybridSigSeparator),
		"signature should start with %q, got %q", HybridSigPrefix+HybridSigSeparator, sig[:20])

	// Must have three colon-separated parts after the prefix:
	// "hybrid" : <ed25519_hex> : <mldsa_hex>
	// But we parse by fixed ed25519 length to be robust.
	edSig, mldsaSig, parseErr := parseHybridSignature(sig)
	require.NoError(t, parseErr)
	assert.Len(t, edSig, 128, "ed25519 hex signature should be 128 chars")
	assert.True(t, len(mldsaSig) > 0, "ml-dsa-65 signature should be non-empty")
}

func TestHybridSigner_VerifyValidSignature(t *testing.T) {
	signer, err := NewHybridSigner("hybrid-key-1")
	require.NoError(t, err)

	data := []byte("hello hybrid world")
	sig, err := signer.Sign(data)
	require.NoError(t, err)

	valid, err := signer.Verify(data, sig)
	require.NoError(t, err)
	assert.True(t, valid, "Verify should return true for valid composite signature")
}

func TestHybridSigner_VerifyFailsIfEd25519Invalid(t *testing.T) {
	signer, err := NewHybridSigner("hybrid-key-1")
	require.NoError(t, err)

	data := []byte("authentic data")
	sig, err := signer.Sign(data)
	require.NoError(t, err)

	// Corrupt the ed25519 portion (first 128 hex chars after "hybrid:")
	prefix := HybridSigPrefix + HybridSigSeparator
	rest := sig[len(prefix):]
	// Flip a character in the ed25519 hex
	corrupted := make([]byte, len(rest))
	copy(corrupted, rest)
	if corrupted[0] == 'a' {
		corrupted[0] = 'b'
	} else {
		corrupted[0] = 'a'
	}
	corruptedSig := prefix + string(corrupted)

	valid, err := signer.Verify(data, corruptedSig)
	// Either err != nil (invalid hex) or valid == false
	if err == nil {
		assert.False(t, valid, "Verify should fail when ed25519 sub-signature is corrupted")
	}
}

func TestHybridSigner_VerifyFailsIfMLDSAInvalid(t *testing.T) {
	signer, err := NewHybridSigner("hybrid-key-1")
	require.NoError(t, err)

	data := []byte("authentic data")
	sig, err := signer.Sign(data)
	require.NoError(t, err)

	// Parse to get parts
	edSig, mldsaSig, parseErr := parseHybridSignature(sig)
	require.NoError(t, parseErr)

	// Corrupt the ML-DSA-65 portion
	corrupted := make([]byte, len(mldsaSig))
	copy(corrupted, mldsaSig)
	if corrupted[0] == 'a' {
		corrupted[0] = 'b'
	} else {
		corrupted[0] = 'a'
	}
	corruptedSig := HybridSigPrefix + HybridSigSeparator + edSig + HybridSigSeparator + string(corrupted)

	valid, err := signer.Verify(data, corruptedSig)
	// Either err != nil (invalid hex) or valid == false
	if err == nil {
		assert.False(t, valid, "Verify should fail when ml-dsa-65 sub-signature is corrupted")
	}
}

func TestHybridSigner_VerifyFailsWithTamperedData(t *testing.T) {
	signer, err := NewHybridSigner("hybrid-key-1")
	require.NoError(t, err)

	data := []byte("original data")
	sig, err := signer.Sign(data)
	require.NoError(t, err)

	valid, err := signer.Verify([]byte("tampered data"), sig)
	require.NoError(t, err)
	assert.False(t, valid, "Verify should fail for tampered data")
}

func TestHybridSigner_SignDecision(t *testing.T) {
	signer, err := NewHybridSigner("hybrid-key-1")
	require.NoError(t, err)

	d := &contracts.DecisionRecord{
		ID:                "dec-hybrid-001",
		Verdict:           "ALLOW",
		Reason:            "policy-match",
		PhenotypeHash:     "sha256:pheno",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      "sha256:effect",
		Timestamp:         time.Now(),
	}

	err = signer.SignDecision(d)
	require.NoError(t, err)

	// Signature must be hybrid format
	assert.True(t, strings.HasPrefix(d.Signature, HybridSigPrefix+HybridSigSeparator),
		"decision signature should be hybrid format")

	// SignatureType must be "Hybrid-Ed25519-MLDSA65:hybrid-key-1"
	expectedSigType := SigPrefixHybrid + SigSeparator + "hybrid-key-1"
	assert.Equal(t, expectedSigType, d.SignatureType)

	// Verify the composite signature
	payload := CanonicalizeDecision(d.ID, d.Verdict, d.Reason, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)
	valid, err := signer.Verify([]byte(payload), d.Signature)
	require.NoError(t, err)
	assert.True(t, valid, "hybrid decision signature should verify")
}

func TestHybridSigner_SignIntent(t *testing.T) {
	signer, err := NewHybridSigner("hybrid-key-2")
	require.NoError(t, err)

	intent := &contracts.AuthorizedExecutionIntent{
		ID:          "intent-hybrid-001",
		DecisionID:  "dec-hybrid-001",
		AllowedTool: "read_file",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	err = signer.SignIntent(intent)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(intent.Signature, HybridSigPrefix+HybridSigSeparator))
	assert.Equal(t, SigPrefixHybrid+SigSeparator+"hybrid-key-2", intent.SignatureType)

	// Verify
	payload := CanonicalizeIntent(intent.ID, intent.DecisionID, intent.AllowedTool)
	valid, err := signer.Verify([]byte(payload), intent.Signature)
	require.NoError(t, err)
	assert.True(t, valid)

	// Tamper
	intent.AllowedTool = "delete_file"
	payloadTampered := CanonicalizeIntent(intent.ID, intent.DecisionID, intent.AllowedTool)
	valid, err = signer.Verify([]byte(payloadTampered), intent.Signature)
	require.NoError(t, err)
	assert.False(t, valid, "should fail for tampered intent")
}

func TestHybridSigner_SignReceiptRoundTrip(t *testing.T) {
	signer, err := NewHybridSigner("hybrid-key-3")
	require.NoError(t, err)

	receipt := &contracts.Receipt{
		ReceiptID:    "rcpt-hybrid-001",
		DecisionID:   "dec-hybrid-001",
		EffectID:     "eff-hybrid-001",
		Status:       "EXECUTED",
		OutputHash:   "sha256:out",
		PrevHash:     "sha256:prev",
		LamportClock: 42,
		ArgsHash:     "sha256:args",
		Timestamp:    time.Now(),
	}

	err = signer.SignReceipt(receipt)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(receipt.Signature, HybridSigPrefix+HybridSigSeparator))

	// Verify round-trip
	payload := CanonicalizeReceipt(receipt.ReceiptID, receipt.DecisionID, receipt.EffectID, receipt.Status, receipt.OutputHash, receipt.PrevHash, receipt.LamportClock, receipt.ArgsHash)
	valid, err := signer.Verify([]byte(payload), receipt.Signature)
	require.NoError(t, err)
	assert.True(t, valid, "receipt hybrid signature should verify")

	// Tamper the status
	receipt.Status = "FAILED"
	payloadTampered := CanonicalizeReceipt(receipt.ReceiptID, receipt.DecisionID, receipt.EffectID, receipt.Status, receipt.OutputHash, receipt.PrevHash, receipt.LamportClock, receipt.ArgsHash)
	valid, err = signer.Verify([]byte(payloadTampered), receipt.Signature)
	require.NoError(t, err)
	assert.False(t, valid, "should fail for tampered receipt")
}

func TestHybridSigner_PublicKeyHybridFormat(t *testing.T) {
	signer, err := NewHybridSigner("hybrid-key-1")
	require.NoError(t, err)

	pubKey := signer.PublicKey()
	assert.True(t, strings.HasPrefix(pubKey, HybridSigPrefix+HybridSigSeparator),
		"PublicKey should have hybrid prefix")

	// Should contain both sub-keys separated by ":"
	parts := strings.SplitN(pubKey, HybridSigSeparator, 3)
	require.Len(t, parts, 3, "PublicKey should have 3 parts: prefix, ed25519, mldsa")
	assert.Equal(t, HybridSigPrefix, parts[0])
	assert.Equal(t, signer.Ed25519Signer().PublicKey(), parts[1])
	assert.Equal(t, signer.MLDSASigner().PublicKey(), parts[2])
}

func TestHybridSigner_PublicKeyBytesBackwardCompat(t *testing.T) {
	signer, err := NewHybridSigner("hybrid-key-1")
	require.NoError(t, err)

	pubBytes := signer.PublicKeyBytes()
	edPubBytes := signer.Ed25519Signer().PublicKeyBytes()

	assert.Equal(t, edPubBytes, pubBytes,
		"PublicKeyBytes should return ed25519 key for backward compat")
	assert.Len(t, pubBytes, 32, "ed25519 public key should be 32 bytes")
}

func TestHybridSigner_SubSignersAccessible(t *testing.T) {
	signer, err := NewHybridSigner("hybrid-key-1")
	require.NoError(t, err)

	edSigner := signer.Ed25519Signer()
	require.NotNil(t, edSigner)
	assert.Equal(t, "hybrid-key-1", edSigner.GetKeyID())

	mldsaSigner := signer.MLDSASigner()
	require.NotNil(t, mldsaSigner)
	assert.Equal(t, "hybrid-key-1", mldsaSigner.GetKeyID())
}

func TestHybridSigner_ImplementsSignerInterface(t *testing.T) {
	signer, err := NewHybridSigner("hybrid-key-1")
	require.NoError(t, err)

	// Compile-time check is via var _ Signer = (*HybridSigner)(nil)
	// but also verify at runtime.
	var iface Signer = signer
	assert.NotNil(t, iface)
}

func TestHybridSigner_VerifyRejectsMalformedSignature(t *testing.T) {
	signer, err := NewHybridSigner("hybrid-key-1")
	require.NoError(t, err)

	data := []byte("test data")

	tests := []struct {
		name string
		sig  string
	}{
		{"empty", ""},
		{"no prefix", "ed25519:aabbcc"},
		{"prefix only", "hybrid:"},
		{"too short", "hybrid:aabb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := signer.Verify(data, tt.sig)
			assert.Error(t, err, "should return error for malformed signature %q", tt.sig)
			assert.False(t, valid)
		})
	}
}

func TestHybridSigner_ConcurrentSigning(t *testing.T) {
	signer, err := NewHybridSigner("concurrent-key")
	require.NoError(t, err)

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errors := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			data := []byte("concurrent data " + string(rune('0'+n)))
			sig, signErr := signer.Sign(data)
			if signErr != nil {
				errors <- signErr
				return
			}
			valid, verifyErr := signer.Verify(data, sig)
			if verifyErr != nil {
				errors <- verifyErr
				return
			}
			if !valid {
				errors <- fmt.Errorf("goroutine %d: verify failed", n)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent error: %v", err)
	}
}

func TestHybridSigner_ParseHybridSignature(t *testing.T) {
	// Valid signature structure
	edHex := strings.Repeat("ab", 64)   // 128 hex chars
	mldsaHex := strings.Repeat("cd", 50) // arbitrary length

	sig := HybridSigPrefix + HybridSigSeparator + edHex + HybridSigSeparator + mldsaHex
	edResult, mldsaResult, err := parseHybridSignature(sig)
	require.NoError(t, err)
	assert.Equal(t, edHex, edResult)
	assert.Equal(t, mldsaHex, mldsaResult)
}

func TestHybridSigner_Constants(t *testing.T) {
	assert.Equal(t, "hybrid", HybridSigPrefix)
	assert.Equal(t, ":", HybridSigSeparator)
	assert.Equal(t, "Hybrid-Ed25519-MLDSA65", SigPrefixHybrid)
}
