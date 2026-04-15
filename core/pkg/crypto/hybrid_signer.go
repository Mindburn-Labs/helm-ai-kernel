package crypto

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// HybridSigner implements the Signer interface using both Ed25519 (classical)
// and ML-DSA-65 (post-quantum) signatures. Every signing operation produces
// a composite signature containing both algorithms.
//
// Paper basis: ePrint 2025/2025 recommends hybrid mode during PQ transition.
// When quantum computers arrive, the Ed25519 signature is broken but the
// ML-DSA-65 signature remains valid, ensuring continuity.
//
// Design invariants:
//   - Both signatures are always produced (fail-closed: if either fails, error)
//   - Composite signature format: "hybrid:<ed25519_hex>:<mldsa_hex>"
//   - Verification requires both signatures to be valid
//   - Compatible with existing Signer interface consumers
const (
	HybridSigPrefix    = "hybrid"
	HybridSigSeparator = ":"
)

// SigPrefixHybrid is the signature type prefix for hybrid Ed25519+ML-DSA-65.
const SigPrefixHybrid = "Hybrid-Ed25519-MLDSA65"

// HybridSigner wraps an Ed25519Signer and an MLDSASigner, producing composite
// signatures that bind both classical and post-quantum proofs to every artifact.
type HybridSigner struct {
	ed25519 *Ed25519Signer
	mldsa   *MLDSASigner
	keyID   string
}

// NewHybridSigner generates fresh Ed25519 and ML-DSA-65 keypairs and returns
// a HybridSigner that produces composite signatures from both.
func NewHybridSigner(keyID string) (*HybridSigner, error) {
	edSigner, err := NewEd25519Signer(keyID)
	if err != nil {
		return nil, fmt.Errorf("hybrid: ed25519 key generation failed: %w", err)
	}
	mldsaSigner, err := NewMLDSASigner(keyID)
	if err != nil {
		return nil, fmt.Errorf("hybrid: ml-dsa-65 key generation failed: %w", err)
	}
	return &HybridSigner{
		ed25519: edSigner,
		mldsa:   mldsaSigner,
		keyID:   keyID,
	}, nil
}

// Sign produces a composite signature in the format "hybrid:<ed25519_hex>:<mldsa_hex>".
// Both sub-signatures must succeed; if either fails, the entire operation fails (fail-closed).
func (h *HybridSigner) Sign(data []byte) (string, error) {
	edSig, err := h.ed25519.Sign(data)
	if err != nil {
		return "", fmt.Errorf("hybrid: ed25519 sign failed: %w", err)
	}
	mldsaSig, err := h.mldsa.Sign(data)
	if err != nil {
		return "", fmt.Errorf("hybrid: ml-dsa-65 sign failed: %w", err)
	}
	return HybridSigPrefix + HybridSigSeparator + edSig + HybridSigSeparator + mldsaSig, nil
}

// PublicKey returns a composite public key in the format "hybrid:<ed25519_pub_hex>:<mldsa_pub_hex>".
func (h *HybridSigner) PublicKey() string {
	return HybridSigPrefix + HybridSigSeparator + h.ed25519.PublicKey() + HybridSigSeparator + h.mldsa.PublicKey()
}

// PublicKeyBytes returns the Ed25519 public key bytes for backward compatibility
// with systems that only understand classical keys.
func (h *HybridSigner) PublicKeyBytes() []byte {
	return h.ed25519.PublicKeyBytes()
}

// SignDecision signs a DecisionRecord using both Ed25519 and ML-DSA-65.
// The composite signature is stored in d.Signature and the SignatureType is
// set to "Hybrid-Ed25519-MLDSA65:<keyID>".
func (h *HybridSigner) SignDecision(d *contracts.DecisionRecord) error {
	payload := CanonicalizeDecision(d.ID, d.Verdict, d.Reason, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)
	sig, err := h.Sign([]byte(payload))
	if err != nil {
		return err
	}
	d.Signature = sig
	d.SignatureType = SigPrefixHybrid + SigSeparator + h.keyID
	return nil
}

// SignIntent signs an AuthorizedExecutionIntent using both Ed25519 and ML-DSA-65.
func (h *HybridSigner) SignIntent(i *contracts.AuthorizedExecutionIntent) error {
	payload := CanonicalizeIntent(i.ID, i.DecisionID, i.AllowedTool)
	sig, err := h.Sign([]byte(payload))
	if err != nil {
		return err
	}
	i.Signature = sig
	i.SignatureType = SigPrefixHybrid + SigSeparator + h.keyID
	return nil
}

// SignReceipt signs a Receipt using both Ed25519 and ML-DSA-65.
func (h *HybridSigner) SignReceipt(r *contracts.Receipt) error {
	payload := CanonicalizeReceipt(r.ReceiptID, r.DecisionID, r.EffectID, r.Status, r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash)
	sig, err := h.Sign([]byte(payload))
	if err != nil {
		return err
	}
	r.Signature = sig
	return nil
}

// Verify checks a composite signature against data. Both the Ed25519 and ML-DSA-65
// sub-signatures must be valid; if either fails, verification fails (fail-closed).
func (h *HybridSigner) Verify(data []byte, compositeSig string) (bool, error) {
	edSigHex, mldsaSigHex, err := parseHybridSignature(compositeSig)
	if err != nil {
		return false, err
	}

	// Verify Ed25519
	edValid, err := Verify(h.ed25519.PublicKey(), edSigHex, data)
	if err != nil {
		return false, fmt.Errorf("hybrid: ed25519 verification error: %w", err)
	}
	if !edValid {
		return false, nil
	}

	// Verify ML-DSA-65
	mldsaSigBytes, err := hex.DecodeString(mldsaSigHex)
	if err != nil {
		return false, fmt.Errorf("hybrid: invalid ml-dsa-65 signature hex: %w", err)
	}
	if !h.mldsa.Verify(data, mldsaSigBytes) {
		return false, nil
	}

	return true, nil
}

// Ed25519Signer returns the underlying Ed25519 signer for direct access.
func (h *HybridSigner) Ed25519Signer() *Ed25519Signer {
	return h.ed25519
}

// MLDSASigner returns the underlying ML-DSA-65 signer for direct access.
func (h *HybridSigner) MLDSASigner() *MLDSASigner {
	return h.mldsa
}

// parseHybridSignature splits a composite signature "hybrid:<ed25519_hex>:<mldsa_hex>"
// into its Ed25519 and ML-DSA-65 components.
func parseHybridSignature(compositeSig string) (edSigHex, mldsaSigHex string, err error) {
	if !strings.HasPrefix(compositeSig, HybridSigPrefix+HybridSigSeparator) {
		return "", "", fmt.Errorf("hybrid: signature does not have %q prefix", HybridSigPrefix)
	}

	// Remove prefix "hybrid:"
	rest := compositeSig[len(HybridSigPrefix)+len(HybridSigSeparator):]

	// Ed25519 signatures are always 64 bytes = 128 hex chars.
	// Split on that boundary to avoid ambiguity with the separator appearing in hex.
	const ed25519HexLen = 128
	if len(rest) < ed25519HexLen+len(HybridSigSeparator) {
		return "", "", fmt.Errorf("hybrid: composite signature too short")
	}

	edSigHex = rest[:ed25519HexLen]
	if rest[ed25519HexLen:ed25519HexLen+len(HybridSigSeparator)] != HybridSigSeparator {
		return "", "", fmt.Errorf("hybrid: missing separator after ed25519 component")
	}
	mldsaSigHex = rest[ed25519HexLen+len(HybridSigSeparator):]

	if mldsaSigHex == "" {
		return "", "", fmt.Errorf("hybrid: missing ml-dsa-65 signature component")
	}

	return edSigHex, mldsaSigHex, nil
}

// Compile-time interface check: HybridSigner must implement Signer.
var _ Signer = (*HybridSigner)(nil)
