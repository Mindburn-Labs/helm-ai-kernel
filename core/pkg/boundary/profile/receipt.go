// quantum_posture: boundary profile records use classical Ed25519 signatures;
// this preview contract makes no hybrid or post-quantum claim.
package profile

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// CompileReceiptSchemaVersion identifies the compile receipt record format.
const CompileReceiptSchemaVersion = "profile_compile_receipt.v1"

// ArtifactRef pins one emitted artifact file by relative path and content hash.
type ArtifactRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// CompileReceipt is the proof object of a boundary compile: these exact OS
// artifacts were compiled from this exact policy input at this mode tier by
// this kernel version. It is JCS-canonical, hash-sealed, Ed25519-signed, and
// offline-verifiable.
type CompileReceipt struct {
	SchemaVersion   string        `json:"schema_version"`
	ReceiptID       string        `json:"receipt_id"`
	ProfileID       string        `json:"profile_id"`
	ModeTier        string        `json:"mode_tier"`
	PolicyInputHash string        `json:"policy_input_hash"`
	Artifacts       []ArtifactRef `json:"artifacts"`
	ArtifactSetHash string        `json:"artifact_set_hash"`
	KernelVersion   string        `json:"kernel_version"`
	CompiledAt      string        `json:"compiled_at"`
	SignerKeyID     string        `json:"signer_key_id"`
	RecordHash      string        `json:"record_hash"`
	Signature       string        `json:"signature"`
}

var validSHA256 = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// CompileReceiptSigningBytes is the RFC 8785 payload signed by the compiling
// kernel. RecordHash and Signature are excluded to avoid self-reference.
func CompileReceiptSigningBytes(record CompileReceipt) ([]byte, error) {
	record.RecordHash = ""
	record.Signature = ""
	if err := validateCompileReceiptShape(record, false); err != nil {
		return nil, err
	}
	return canonicalize.JCS(record)
}

// SealCompileReceipt computes the record hash over the signing payload and
// signs it. The sealed record round-trips through VerifyCompileReceipt.
func SealCompileReceipt(record CompileReceipt, signer crypto.Signer) (CompileReceipt, error) {
	if signer == nil {
		return CompileReceipt{}, errors.New("compile receipt seal requires a signer")
	}
	payload, err := CompileReceiptSigningBytes(record)
	if err != nil {
		return CompileReceipt{}, err
	}
	sigHex, err := signer.Sign(payload)
	if err != nil {
		return CompileReceipt{}, fmt.Errorf("sign compile receipt: %w", err)
	}
	record.RecordHash = canonicalize.ComputeArtifactHash(payload)
	record.Signature = "ed25519:" + sigHex
	if err := validateCompileReceiptShape(record, true); err != nil {
		return CompileReceipt{}, err
	}
	return record, nil
}

// VerifyCompileReceipt proves content integrity and the trust-root signature
// fully offline: recompute the JCS payload, constant-time-compare the record
// hash, then verify the Ed25519 signature.
func VerifyCompileReceipt(record CompileReceipt, publicKey ed25519.PublicKey) error {
	if err := validateCompileReceiptShape(record, true); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("compile receipt public key has invalid size")
	}
	payload, err := CompileReceiptSigningBytes(record)
	if err != nil {
		return err
	}
	if !constantEqual(record.RecordHash, canonicalize.ComputeArtifactHash(payload)) {
		return errors.New("compile receipt record hash mismatch")
	}
	signature, err := parseRecordSignature(record.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("compile receipt signature verification failed")
	}
	return nil
}

func validateCompileReceiptShape(record CompileReceipt, sealed bool) error {
	if record.SchemaVersion != CompileReceiptSchemaVersion {
		return fmt.Errorf("compile receipt schema_version must be %q", CompileReceiptSchemaVersion)
	}
	if record.ReceiptID == "" || record.SignerKeyID == "" || record.KernelVersion == "" {
		return errors.New("compile receipt identity is incomplete")
	}
	if !validProfileID.MatchString(record.ProfileID) {
		return errors.New("compile receipt profile_id is invalid")
	}
	switch record.ModeTier {
	case TierObserve, TierEnforce:
	default:
		return errors.New("compile receipt mode_tier is invalid")
	}
	if !validSHA256.MatchString(record.PolicyInputHash) {
		return errors.New("compile receipt policy_input_hash is invalid")
	}
	if !validSHA256.MatchString(record.ArtifactSetHash) {
		return errors.New("compile receipt artifact_set_hash is invalid")
	}
	if len(record.Artifacts) == 0 {
		return errors.New("compile receipt must reference at least one artifact")
	}
	if !sort.SliceIsSorted(record.Artifacts, func(i, j int) bool {
		return record.Artifacts[i].Path < record.Artifacts[j].Path
	}) {
		return errors.New("compile receipt artifacts must be sorted by path")
	}
	seen := map[string]bool{}
	for _, ref := range record.Artifacts {
		if err := validateArtifactPath(ref.Path); err != nil {
			return err
		}
		if seen[ref.Path] {
			return fmt.Errorf("compile receipt artifact path %q is duplicated", ref.Path)
		}
		seen[ref.Path] = true
		if !validSHA256.MatchString(ref.SHA256) {
			return fmt.Errorf("compile receipt artifact %q hash is invalid", ref.Path)
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, record.CompiledAt); err != nil {
		return errors.New("compile receipt compiled_at must be RFC3339")
	}
	if sealed {
		if !validSHA256.MatchString(record.RecordHash) {
			return errors.New("compile receipt record hash is invalid")
		}
		if _, err := parseRecordSignature(record.Signature); err != nil {
			return err
		}
	} else if record.RecordHash != "" || record.Signature != "" {
		return errors.New("unsealed compile receipt cannot carry hash or signature")
	}
	return nil
}

func parseRecordSignature(value string) ([]byte, error) {
	const prefix = "ed25519:"
	if !strings.HasPrefix(value, prefix) {
		return nil, errors.New("record signature must use ed25519 prefix")
	}
	raw := strings.TrimPrefix(value, prefix)
	if len(raw) != ed25519.SignatureSize*2 || strings.ToLower(raw) != raw {
		return nil, errors.New("record signature must be lowercase hex")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, errors.New("record signature is invalid")
	}
	return decoded, nil
}

func constantEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
