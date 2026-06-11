// inclusionproof.go defines the redacted-verification profile for EvidencePacks
// (MIN-512): a self-contained, offline-verifiable artifact that proves a single
// manifest entry (e.g. one receipt) belongs to a pack — binding to the pack's
// manifest_hash and policy_hash — WITHOUT requiring the holder to possess the
// pack's other entries.
//
// The proof carries:
//   - The pack-level public binding (pack_id, manifest_hash, policy_hash,
//     created_at, entries_merkle_root, entry_count) — always public.
//   - The disclosed entry's manifest record (path, content_hash, size,
//     content_type).
//   - A Merkle audit path from that entry's leaf to entries_merkle_root.
//   - Optionally, an SD-JWT presentation (core/pkg/crypto/sdjwt) carrying the
//     selectively-disclosed receipt claims. Always-public receipt fields
//     (verdict, policy_hash, timestamps, signature) are present in every
//     presentation; sensitive fields are omitted unless the holder discloses
//     them. Redaction never breaks Merkle verification because the leaf binds
//     content_hash, not the cleartext receipt body.
//
// Verification is fail-closed: any mismatch (wrong entry, tampered root,
// tampered binding, tampered disclosed claim) MUST fail.
package evidencepack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// InclusionProofVersion is the redacted-verification profile version.
const InclusionProofVersion = "1.0.0"

// PublicReceiptFields are the receipt fields that MUST always be disclosed for a
// redacted single-entry proof to carry audit value. They never contain tenant
// payloads, so they are safe to expose to an auditor/insurer/counterparty.
var PublicReceiptFields = []string{"verdict", "policy_hash", "timestamp", "signature", "receipt_id", "decision_id"}

// PackBinding is the always-public pack-level summary an inclusion proof binds
// to. It is sufficient for an auditor to state "pack <pack_id> sealed under
// policy_hash X at created_at, manifest_hash Y" without any entry payloads.
type PackBinding struct {
	PackID            string `json:"pack_id"`
	ManifestHash      string `json:"manifest_hash"`
	PolicyHash        string `json:"policy_hash"`
	CreatedAt         string `json:"created_at"`
	EntriesMerkleRoot string `json:"entries_merkle_root"`
	EntryCount        int    `json:"entry_count"`
}

// SelectiveDisclosure carries an optional SD-JWT presentation for the entry's
// receipt claims. PublicClaims lists the claim names guaranteed present; the
// presentation itself is the SD-JWT string (issuerJWT~disclosure~...~).
type SelectiveDisclosure struct {
	Presentation string   `json:"presentation"`
	PublicClaims []string `json:"public_claims,omitempty"`
}

// InclusionProof is the self-contained redacted-verification artifact.
type InclusionProof struct {
	Version     string               `json:"version"`
	Binding     PackBinding          `json:"binding"`
	Entry       ManifestEntry        `json:"entry"`
	LeafHash    string               `json:"leaf_hash"`
	Path        []MerkleProofStep    `json:"merkle_path"`
	Disclosure  *SelectiveDisclosure `json:"selective_disclosure,omitempty"`
	BindingHash string               `json:"binding_hash"` // SHA-256 over Version+Binding+Entry+LeafHash
}

// BuildInclusionProof constructs a single-entry inclusion proof for entryPath
// against the given manifest. The manifest's ManifestHash MUST already be set.
// The optional disclosure is attached verbatim (the caller is responsible for
// constructing a presentation that includes the always-public receipt fields).
func BuildInclusionProof(manifest *Manifest, entryPath string, disclosure *SelectiveDisclosure) (*InclusionProof, error) {
	if manifest == nil {
		return nil, fmt.Errorf("inclusion proof: manifest is nil")
	}
	if manifest.ManifestHash == "" {
		return nil, fmt.Errorf("inclusion proof: manifest hash is unset")
	}

	root, err := ComputeEntriesMerkleRoot(manifest.Entries)
	if err != nil {
		return nil, err
	}

	var entry ManifestEntry
	found := false
	for _, e := range manifest.Entries {
		if e.Path == entryPath {
			entry = e
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("inclusion proof: entry %q not found in manifest", entryPath)
	}

	steps, derivedRoot, err := BuildInclusionPath(manifest.Entries, entryPath)
	if err != nil {
		return nil, err
	}
	if derivedRoot != root {
		// Defensive: path construction and full-tree reduction must agree.
		return nil, fmt.Errorf("inclusion proof: internal root mismatch")
	}

	leaf, err := LeafHash(entry)
	if err != nil {
		return nil, err
	}

	proof := &InclusionProof{
		Version: InclusionProofVersion,
		Binding: PackBinding{
			PackID:            manifest.PackID,
			ManifestHash:      manifest.ManifestHash,
			PolicyHash:        manifest.PolicyHash,
			CreatedAt:         manifest.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
			EntriesMerkleRoot: root,
			EntryCount:        len(manifest.Entries),
		},
		Entry:      entry,
		LeafHash:   leaf,
		Path:       steps,
		Disclosure: disclosure,
	}

	bindingHash, err := computeBindingHash(proof)
	if err != nil {
		return nil, err
	}
	proof.BindingHash = bindingHash
	return proof, nil
}

// VerifyInclusionProof checks a single-entry inclusion proof offline, fail-closed.
//
// It verifies, in order:
//  1. binding_hash integrity (no tampering with version/binding/entry/leaf).
//  2. The leaf hash matches the disclosed entry record.
//  3. The Merkle audit path reconstructs entries_merkle_root from the leaf.
//
// It does NOT require the full pack. The returned error names the first failing
// check. A nil error means the entry provably belongs to the pack identified by
// binding.manifest_hash / binding.entries_merkle_root.
func VerifyInclusionProof(proof *InclusionProof) error {
	if proof == nil {
		return fmt.Errorf("inclusion proof: nil proof")
	}
	if proof.Version != InclusionProofVersion {
		return fmt.Errorf("inclusion proof: unsupported version %q", proof.Version)
	}

	// 1. Binding integrity.
	expectedBinding, err := computeBindingHash(proof)
	if err != nil {
		return err
	}
	if proof.BindingHash != expectedBinding {
		return fmt.Errorf("inclusion proof: binding hash mismatch (tampered binding or entry)")
	}

	// 2. Leaf matches the disclosed entry.
	wantLeaf, err := LeafHash(proof.Entry)
	if err != nil {
		return err
	}
	if proof.LeafHash != wantLeaf {
		return fmt.Errorf("inclusion proof: leaf hash does not match entry record")
	}

	// 3. Merkle path reconstructs the published root.
	derivedRoot, err := VerifyInclusionPath(proof.LeafHash, proof.Path)
	if err != nil {
		return err
	}
	if derivedRoot != proof.Binding.EntriesMerkleRoot {
		return fmt.Errorf("inclusion proof: merkle path does not reach entries_merkle_root (wrong entry or tampered path)")
	}

	return nil
}

// computeBindingHash hashes the immutable core of a proof (everything except the
// optional disclosure, which is verified separately by the SD-JWT verifier and
// MUST NOT change the entry's binding to the pack).
func computeBindingHash(proof *InclusionProof) (string, error) {
	hashable := struct {
		Version  string        `json:"version"`
		Binding  PackBinding   `json:"binding"`
		Entry    ManifestEntry `json:"entry"`
		LeafHash string        `json:"leaf_hash"`
	}{
		Version:  proof.Version,
		Binding:  proof.Binding,
		Entry:    proof.Entry,
		LeafHash: proof.LeafHash,
	}
	data, err := canonicalize.JCS(hashable)
	if err != nil {
		return "", fmt.Errorf("canonicalize proof binding: %w", err)
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
