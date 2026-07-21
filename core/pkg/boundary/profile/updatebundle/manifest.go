// Package updatebundle defines the signed offline update-bundle format for
// disconnected appliance fleets: a JCS-canonical (RFC 8785) manifest over a
// tar.gz payload, hash-sealed and Ed25519-signed, verifiable fully offline.
//
// Slice A ships the FORMAT and the VERIFIER only — bundle build tooling is
// deliberately out of scope. Operators may additionally sign the manifest
// file with `cosign sign-blob` at the transport layer; nothing here imports
// cosign, and the in-repo trust anchor is the Ed25519 signature.
//
// quantum_posture: update-bundle manifests use classical Ed25519 signatures;
// this preview contract makes no hybrid or post-quantum claim.
package updatebundle

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

// UpdateBundleManifestSchemaVersion identifies the manifest record format.
const UpdateBundleManifestSchemaVersion = "update_bundle_manifest.v1"

// BundleEntry pins one payload file by relative path, content hash, and size.
type BundleEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// UpdateBundleManifest is the proof object of an offline update bundle: this
// exact payload set, for this kernel version, signed by this key.
type UpdateBundleManifest struct {
	SchemaVersion   string        `json:"schema_version"`
	BundleID        string        `json:"bundle_id"`
	KernelVersion   string        `json:"kernel_version"`
	CreatedAt       string        `json:"created_at"`
	Entries         []BundleEntry `json:"entries"`
	ArtifactSetHash string        `json:"artifact_set_hash"`
	SignerKeyID     string        `json:"signer_key_id"`
	RecordHash      string        `json:"record_hash"`
	Signature       string        `json:"signature"`
}

var (
	validSHA256   = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	validBundleID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// EntrySetHash derives the artifact set hash binding the entries: sha256 of
// the JCS-canonical entry list (path-sorted).
func EntrySetHash(entries []BundleEntry) (string, error) {
	if err := validateEntries(entries); err != nil {
		return "", err
	}
	payload, err := canonicalize.JCS(entries)
	if err != nil {
		return "", fmt.Errorf("canonicalize bundle entries: %w", err)
	}
	return canonicalize.ComputeArtifactHash(payload), nil
}

// ManifestSigningBytes is the RFC 8785 payload signed by the bundle
// publisher. RecordHash and Signature are excluded to avoid self-reference.
func ManifestSigningBytes(manifest UpdateBundleManifest) ([]byte, error) {
	manifest.RecordHash = ""
	manifest.Signature = ""
	if err := validateManifestShape(manifest, false); err != nil {
		return nil, err
	}
	return canonicalize.JCS(manifest)
}

// SealManifest computes the record hash over the signing payload and signs
// it. Update-bundle manifests are never unsigned.
func SealManifest(manifest UpdateBundleManifest, signer crypto.Signer) (UpdateBundleManifest, error) {
	if signer == nil {
		return UpdateBundleManifest{}, errors.New("update bundle manifest seal requires a signer")
	}
	payload, err := ManifestSigningBytes(manifest)
	if err != nil {
		return UpdateBundleManifest{}, err
	}
	sigHex, err := signer.Sign(payload)
	if err != nil {
		return UpdateBundleManifest{}, fmt.Errorf("sign update bundle manifest: %w", err)
	}
	manifest.RecordHash = canonicalize.ComputeArtifactHash(payload)
	manifest.Signature = "ed25519:" + sigHex
	if err := validateManifestShape(manifest, true); err != nil {
		return UpdateBundleManifest{}, err
	}
	return manifest, nil
}

// VerifyManifest proves content integrity and the publisher signature fully
// offline.
func VerifyManifest(manifest UpdateBundleManifest, publicKey ed25519.PublicKey) error {
	if err := validateManifestShape(manifest, true); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("update bundle public key has invalid size")
	}
	payload, err := ManifestSigningBytes(manifest)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(manifest.RecordHash), []byte(canonicalize.ComputeArtifactHash(payload))) != 1 {
		return errors.New("update bundle manifest record hash mismatch")
	}
	signature, err := parseSignature(manifest.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("update bundle manifest signature verification failed")
	}
	return nil
}

func validateManifestShape(manifest UpdateBundleManifest, sealed bool) error {
	if manifest.SchemaVersion != UpdateBundleManifestSchemaVersion {
		return fmt.Errorf("update bundle schema_version must be %q", UpdateBundleManifestSchemaVersion)
	}
	if !validBundleID.MatchString(manifest.BundleID) {
		return errors.New("update bundle bundle_id is invalid")
	}
	if manifest.KernelVersion == "" || manifest.SignerKeyID == "" {
		return errors.New("update bundle identity is incomplete")
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt); err != nil {
		return errors.New("update bundle created_at must be RFC3339")
	}
	if err := validateEntries(manifest.Entries); err != nil {
		return err
	}
	expectedSetHash, err := EntrySetHash(manifest.Entries)
	if err != nil {
		return err
	}
	if manifest.ArtifactSetHash != expectedSetHash {
		return errors.New("update bundle artifact_set_hash does not match entries")
	}
	if sealed {
		if !validSHA256.MatchString(manifest.RecordHash) {
			return errors.New("update bundle record hash is invalid")
		}
		if _, err := parseSignature(manifest.Signature); err != nil {
			return err
		}
	} else if manifest.RecordHash != "" || manifest.Signature != "" {
		return errors.New("unsealed update bundle manifest cannot carry hash or signature")
	}
	return nil
}

func validateEntries(entries []BundleEntry) error {
	if len(entries) == 0 {
		return errors.New("update bundle must carry at least one entry")
	}
	if !sort.SliceIsSorted(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path }) {
		return errors.New("update bundle entries must be sorted by path")
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if err := validateEntryPath(entry.Path); err != nil {
			return err
		}
		if seen[entry.Path] {
			return fmt.Errorf("update bundle entry path %q is duplicated", entry.Path)
		}
		seen[entry.Path] = true
		if !validSHA256.MatchString(entry.SHA256) {
			return fmt.Errorf("update bundle entry %q hash is invalid", entry.Path)
		}
		if entry.Size < 0 {
			return fmt.Errorf("update bundle entry %q size must not be negative", entry.Path)
		}
	}
	return nil
}

func validateEntryPath(path string) error {
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") {
		return fmt.Errorf("update bundle entry path %q must be relative with forward slashes", path)
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("update bundle entry path %q must be clean (no empty, . or .. segments)", path)
		}
	}
	return nil
}

func parseSignature(value string) ([]byte, error) {
	const prefix = "ed25519:"
	if !strings.HasPrefix(value, prefix) {
		return nil, errors.New("update bundle signature must use ed25519 prefix")
	}
	raw := strings.TrimPrefix(value, prefix)
	if len(raw) != ed25519.SignatureSize*2 || strings.ToLower(raw) != raw {
		return nil, errors.New("update bundle signature must be lowercase hex")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, errors.New("update bundle signature is invalid")
	}
	return decoded, nil
}
