package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

// PackExporter defines the interface for generating and signing proof packs.
type PackExporter interface {
	ExportChangePack(ctx context.Context, input *contracts.ChangePack) (*contracts.ChangePack, error)
	ExportIncidentPack(ctx context.Context, input *contracts.IncidentPack) (*contracts.IncidentPack, error)
	ExportAccessReviewPack(ctx context.Context, input *contracts.AccessReviewPack) (*contracts.AccessReviewPack, error)
	ExportVendorDueDiligencePack(ctx context.Context, input *contracts.VendorDueDiligencePack) (*contracts.VendorDueDiligencePack, error)
}

type packExporter struct {
	signerID string
	signer   crypto.Signer
}

// NewPackExporter creates a new PackExporter with a real cryptographic signer.
// The signer MUST implement crypto.Signer (e.g. Ed25519Signer).
func NewPackExporter(signerID string, signer crypto.Signer) PackExporter {
	return &packExporter{
		signerID: signerID,
		signer:   signer,
	}
}

func (e *packExporter) ExportChangePack(ctx context.Context, input *contracts.ChangePack) (*contracts.ChangePack, error) {
	if input.Attestation.GeneratedAt.IsZero() {
		input.Attestation.GeneratedAt = time.Now().UTC()
	}
	input.Attestation.SignerID = e.signerID

	hash, err := e.computePackHash(input)
	if err != nil {
		return nil, fmt.Errorf("failed to compute pack hash: %w", err)
	}
	input.Attestation.PackHash = hash

	sig, err := e.signer.Sign([]byte(hash))
	if err != nil {
		return nil, fmt.Errorf("failed to sign pack: %w", err)
	}
	input.Attestation.Signature = sig

	return input, nil
}

func (e *packExporter) ExportIncidentPack(ctx context.Context, input *contracts.IncidentPack) (*contracts.IncidentPack, error) {
	if input.Attestation.GeneratedAt.IsZero() {
		input.Attestation.GeneratedAt = time.Now().UTC()
	}

	hash, err := e.computePackHash(input)
	if err != nil {
		return nil, fmt.Errorf("failed to compute pack hash: %w", err)
	}
	input.Attestation.PackHash = hash

	sig, err := e.signer.Sign([]byte(hash))
	if err != nil {
		return nil, fmt.Errorf("failed to sign pack: %w", err)
	}
	input.Attestation.Signature = sig

	return input, nil
}

func (e *packExporter) ExportAccessReviewPack(ctx context.Context, input *contracts.AccessReviewPack) (*contracts.AccessReviewPack, error) {
	if input.Attestation.GeneratedAt.IsZero() {
		input.Attestation.GeneratedAt = time.Now().UTC()
	}

	hash, err := e.computePackHash(input)
	if err != nil {
		return nil, fmt.Errorf("failed to compute pack hash: %w", err)
	}
	input.Attestation.PackHash = hash

	sig, err := e.signer.Sign([]byte(hash))
	if err != nil {
		return nil, fmt.Errorf("failed to sign pack: %w", err)
	}
	input.Attestation.Signature = sig

	return input, nil
}

func (e *packExporter) ExportVendorDueDiligencePack(ctx context.Context, input *contracts.VendorDueDiligencePack) (*contracts.VendorDueDiligencePack, error) {
	if input.Attestation.GeneratedAt.IsZero() {
		input.Attestation.GeneratedAt = time.Now().UTC()
	}

	hash, err := e.computePackHash(input)
	if err != nil {
		return nil, fmt.Errorf("failed to compute pack hash: %w", err)
	}
	input.Attestation.PackHash = hash

	sig, err := e.signer.Sign([]byte(hash))
	if err != nil {
		return nil, fmt.Errorf("failed to sign pack: %w", err)
	}
	input.Attestation.Signature = sig

	return input, nil
}

// computePackHash computes the SHA-256 hash of the JCS (RFC 8785) canonicalized pack data.
// It strips the attestation hash/signature fields before hashing to avoid circular references.
// Note: It uses core/pkg/canonicalize to ensure strict JCS compliance and large integer safety.
func (e *packExporter) computePackHash(data interface{}) (string, error) {
	// 1. Marshal to intermediate JSON (to handle struct tags)
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	// 2. Unmarshal into generic map, using UseNumber to preserve integers > 2^53
	var flatMap map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(jsonBytes))
	decoder.UseNumber() // CRITICAL for Lamport clocks
	if err := decoder.Decode(&flatMap); err != nil {
		return "", err
	}

	// 3. Remove attestation.pack_hash and attestation.signature before hashing.
	if attestation, ok := flatMap["attestation"].(map[string]interface{}); ok {
		delete(attestation, "pack_hash")
		delete(attestation, "signature")
	}

	// 4. Use canonicalize.JCS helper, which handles the map->canonical bytes conversion
	// recursive marshalling (including json.Number support) is handled by JCS() internally
	// assuming we passed the correct types.
	// Wait, canonicalize.JCS handles structs by default.
	// But we have modified the map. So we pass the map to JCS.
	// The map contains json.Number (from UseNumber). canonicalize.JCS supports json.Number.

	canonicalBytes, err := canonicalize.JCS(flatMap)
	if err != nil {
		return "", err
	}

	// 5. Hash
	return fmt.Sprintf("sha256:%s", canonicalize.HashBytes(canonicalBytes)), nil
}
