package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	proofanchor "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph/anchor"
	"gopkg.in/yaml.v3"
)

// quantum_posture: EvidencePack seals use classical Ed25519 signatures for
// offline integrity checks in this release; no post-quantum assurance is claimed.
const (
	EvidencePackSealPath    = "07_ATTESTATIONS/evidence_pack.sig"
	EvidencePackSealVersion = "evidence-pack-seal/v1"

	EvidenceTrustProfileDevLocal      EvidenceTrustProfile = "dev-local"
	EvidenceTrustProfileTeam          EvidenceTrustProfile = "team"
	EvidenceTrustProfileCustomer      EvidenceTrustProfile = "customer"
	EvidenceTrustProfileHighAssurance EvidenceTrustProfile = "high-assurance"
)

// EvidenceTrustProfile selects the active trust rules for pack seal verification.
type EvidenceTrustProfile string

// EvidenceSigner signs canonical EvidencePack seal payload bytes.
type EvidenceSigner interface {
	KeyID() string
	Sign(ctx context.Context, payload []byte) ([]byte, error)
}

type evidenceSignerTypeProvider interface {
	SignerType() string
}

type evidenceSignerPublicKeyProvider interface {
	PublicKeyHex() string
}

// EvidencePackSealAnchor records where the pack root was anchored.
type EvidencePackSealAnchor struct {
	Type   string    `json:"type"`
	URI    string    `json:"uri,omitempty"`
	URL    string    `json:"url,omitempty" yaml:"url,omitempty"`
	Status string    `json:"status"`
	Time   time.Time `json:"time,omitempty"`
}

// EvidencePackSealStorage records where the sealed pack is stored.
type EvidencePackSealStorage struct {
	Type           string    `json:"type" yaml:"type"`
	URI            string    `json:"uri,omitempty" yaml:"uri,omitempty"`
	Status         string    `json:"status" yaml:"status,omitempty"`
	ObjectLock     bool      `json:"object_lock,omitempty" yaml:"object_lock,omitempty"`
	Immutable      bool      `json:"immutable,omitempty" yaml:"immutable,omitempty"`
	Receipt        string    `json:"receipt,omitempty" yaml:"receipt,omitempty"`
	Bucket         string    `json:"bucket,omitempty" yaml:"bucket,omitempty"`
	Key            string    `json:"key,omitempty" yaml:"key,omitempty"`
	Region         string    `json:"region,omitempty" yaml:"region,omitempty"`
	Endpoint       string    `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	Prefix         string    `json:"prefix,omitempty" yaml:"prefix,omitempty"`
	ObjectLockMode string    `json:"object_lock_mode,omitempty" yaml:"object_lock_mode,omitempty"`
	RetentionDays  int       `json:"retention_days,omitempty" yaml:"retention_days,omitempty"`
	RetainUntil    time.Time `json:"retain_until,omitempty" yaml:"retain_until,omitempty"`
}

type EvidencePackSealSigner struct {
	Type      string `json:"type"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key,omitempty"`
}

// EvidencePackSeal is written as 07_ATTESTATIONS/evidence_pack.sig. The
// Signature field is appended only after the canonical payload has been signed.
type EvidencePackSeal struct {
	Version        string                      `json:"version"`
	PackID         string                      `json:"pack_id"`
	IndexHash      string                      `json:"index_hash"`
	MerkleRoot     string                      `json:"merkle_root"`
	EntryCount     int                         `json:"entry_count"`
	Profile        EvidenceTrustProfile        `json:"profile"`
	Signer         EvidencePackSealSigner      `json:"signer"`
	Anchor         EvidencePackSealAnchor      `json:"anchor"`
	AnchorReceipts []proofanchor.AnchorReceipt `json:"anchor_receipts,omitempty"`
	Storage        EvidencePackSealStorage     `json:"storage"`
	SignedAt       time.Time                   `json:"signed_at"`
	Signature      string                      `json:"signature"`
}

type evidencePackSealPayload struct {
	Version        string                      `json:"version"`
	PackID         string                      `json:"pack_id"`
	IndexHash      string                      `json:"index_hash"`
	MerkleRoot     string                      `json:"merkle_root"`
	EntryCount     int                         `json:"entry_count"`
	Profile        EvidenceTrustProfile        `json:"profile"`
	Signer         EvidencePackSealSigner      `json:"signer"`
	Anchor         EvidencePackSealAnchor      `json:"anchor"`
	AnchorReceipts []proofanchor.AnchorReceipt `json:"anchor_receipts,omitempty"`
	Storage        EvidencePackSealStorage     `json:"storage"`
	SignedAt       time.Time                   `json:"signed_at"`
}

// SealEvidencePackOptions controls native EvidencePack seal creation.
type SealEvidencePackOptions struct {
	PackID             string
	Profile            EvidenceTrustProfile
	Signer             EvidenceSigner
	TrustConfig        *EvidencePackTrustConfig
	Anchor             EvidencePackSealAnchor
	AnchorReceipts     []proofanchor.AnchorReceipt
	Storage            EvidencePackSealStorage
	StorageReceiptPath string
	SignedAt           time.Time
	DataDir            string
	ConfigPath         string
}

// VerifyEvidencePackSealOptions controls native EvidencePack seal verification.
type VerifyEvidencePackSealOptions struct {
	Profile            EvidenceTrustProfile
	TrustConfig        *EvidencePackTrustConfig
	DataDir            string
	ConfigPath         string
	StorageReceiptPath string
	StorageObjectPath  string
	Now                time.Time
	// AllowVerifiedConformanceSignature permits the legacy control signature
	// file outside 00_INDEX.json only after the caller has verified it against
	// an external trusted key. Library callers should leave this false.
	AllowVerifiedConformanceSignature bool
}

// EvidencePackSealVerification is the verifier-facing seal status.
type EvidencePackSealVerification struct {
	State          string               `json:"state"`
	SignatureValid bool                 `json:"signature_valid"`
	AnchorStatus   string               `json:"anchor_status"`
	StorageStatus  string               `json:"storage_status"`
	TrustLevel     EvidenceTrustProfile `json:"trust_level"`
	PackID         string               `json:"pack_id,omitempty"`
	IndexHash      string               `json:"index_hash,omitempty"`
	MerkleRoot     string               `json:"merkle_root,omitempty"`
	EntryCount     int                  `json:"entry_count,omitempty"`
	SignerKeyID    string               `json:"signer_key_id,omitempty"`
	SignerType     string               `json:"signer_type,omitempty"`
	AnchorReceipts int                  `json:"anchor_receipts,omitempty"`
	StorageReceipt string               `json:"storage_receipt,omitempty"`
	SignedAt       time.Time            `json:"signed_at,omitempty"`
	Errors         []string             `json:"errors,omitempty"`
}

// EvidencePackTrustConfig is the local trust profile configuration used by
// seal producers and verifiers.
type EvidencePackTrustConfig struct {
	Version       string                  `json:"version" yaml:"version"`
	ActiveProfile EvidenceTrustProfile    `json:"active_profile" yaml:"active_profile"`
	Signer        EvidencePackTrustSigner `json:"signer" yaml:"signer"`
	Anchor        EvidencePackSealAnchor  `json:"anchor" yaml:"anchor"`
	Storage       EvidencePackSealStorage `json:"storage" yaml:"storage"`
	TrustedKeys   map[string]string       `json:"trusted_keys,omitempty" yaml:"trusted_keys,omitempty"`
	UpdatedAt     time.Time               `json:"updated_at" yaml:"updated_at"`
}

type EvidencePackTrustSigner struct {
	Type        string `json:"type" yaml:"type"`
	KeyID       string `json:"key_id,omitempty" yaml:"key_id,omitempty"`
	PublicKey   string `json:"public_key,omitempty" yaml:"public_key,omitempty"`
	KMSKeyID    string `json:"kms_key_id,omitempty" yaml:"kms_key_id,omitempty"`
	SignCommand string `json:"sign_command,omitempty" yaml:"sign_command,omitempty"`
}

type indexRootEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type indexRootFile struct {
	Entries []indexRootEntry `json:"entries"`
}

// SealEvidencePack writes 07_ATTESTATIONS/evidence_pack.sig after 00_INDEX.json exists.
func SealEvidencePack(ctx context.Context, packDir string, opts SealEvidencePackOptions) (*EvidencePackSeal, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	roots, err := ComputeEvidencePackIndexRoots(packDir)
	if err != nil {
		return nil, err
	}
	cfg := opts.TrustConfig
	if cfg == nil {
		var loadErr error
		cfg, loadErr = LoadEvidencePackTrustConfigWithPath(opts.ConfigPath, opts.DataDir)
		if loadErr != nil {
			return nil, loadErr
		}
	}
	profile := opts.Profile
	if profile == "" && cfg != nil && cfg.ActiveProfile != "" {
		profile = cfg.ActiveProfile
	}
	profile = NormalizeEvidenceTrustProfile(profile)
	if profile == "" {
		profile = EvidenceTrustProfileDevLocal
	}
	signer := opts.Signer
	if signer == nil {
		if profileRequiresExternalTrust(profile) {
			configuredSigner := ""
			if cfg != nil {
				configuredSigner = cfg.Signer.Type
			}
			signerType := firstNonEmpty(os.Getenv("HELM_EVIDENCE_SIGNER"), configuredSigner)
			if signerType == "" || isLocalEvidenceSignerType(signerType) {
				return nil, fmt.Errorf("%s profile requires an external signer", profile)
			}
		}
		signer, err = ResolveEvidenceSigner(cfg, opts.DataDir)
		if err != nil {
			return nil, err
		}
	}
	if signer == nil {
		return nil, errors.New("evidence pack seal signer is required")
	}

	now := opts.SignedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	anchor := opts.Anchor
	if anchor.Type == "" && cfg != nil {
		anchor = cfg.Anchor
	}
	if anchor.Type == "" {
		anchor = devLocalAnchor(now)
	}
	if anchor.Time.IsZero() {
		anchor.Time = now
	}
	if anchor.Status == "" {
		anchor.Status = statusForTrustType(anchor.Type)
	}
	storage := opts.Storage
	if storage.Type == "" && cfg != nil {
		storage = cfg.Storage
	}
	if storage.Type == "" {
		storage = devLocalStorage()
	}
	if storage.Receipt == "" {
		storage.Receipt = opts.StorageReceiptPath
	}
	if storage.Status == "" {
		storage.Status = statusForTrustType(storage.Type)
	}

	packID := strings.TrimSpace(opts.PackID)
	if packID == "" {
		packID = inferPackID(packDir, roots.IndexHash)
	}

	signerType := "external"
	if typed, ok := signer.(evidenceSignerTypeProvider); ok && typed.SignerType() != "" {
		signerType = typed.SignerType()
	} else if cfg != nil && cfg.Signer.Type != "" {
		signerType = cfg.Signer.Type
	}
	publicKey := ""
	if withPub, ok := signer.(evidenceSignerPublicKeyProvider); ok {
		publicKey = withPub.PublicKeyHex()
	}
	if publicKey == "" && cfg != nil && cfg.Signer.KeyID == signer.KeyID() {
		publicKey = cfg.Signer.PublicKey
	}

	anchorReceipts := opts.AnchorReceipts
	if len(anchorReceipts) == 0 {
		anchorReceipts, err = createEvidenceAnchorReceipts(ctx, roots.MerkleRoot, cfg, anchor)
		if err != nil {
			return nil, err
		}
	}
	if len(anchorReceipts) > 0 {
		anchor.Status = "verified-externally"
		if anchor.Type == "" {
			anchor.Type = anchorReceipts[0].Backend
		}
	}

	seal := &EvidencePackSeal{
		Version:    EvidencePackSealVersion,
		PackID:     packID,
		IndexHash:  roots.IndexHash,
		MerkleRoot: roots.MerkleRoot,
		EntryCount: roots.EntryCount,
		Profile:    profile,
		Signer: EvidencePackSealSigner{
			Type:      signerType,
			KeyID:     signer.KeyID(),
			Algorithm: "ed25519",
			PublicKey: publicKey,
		},
		Anchor:         anchor,
		AnchorReceipts: anchorReceipts,
		Storage:        storage,
		SignedAt:       now.UTC(),
	}
	if errs := validateProfileSeal(*seal, cfg, profile); len(errs) > 0 {
		return nil, fmt.Errorf("evidence pack seal trust profile %s is not satisfied: %s", profile, strings.Join(errs, "; "))
	}
	payload, err := canonicalSealPayload(*seal)
	if err != nil {
		return nil, fmt.Errorf("canonicalize evidence pack seal: %w", err)
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("sign evidence pack seal: %w", err)
	}
	if withPub, ok := signer.(evidenceSignerPublicKeyProvider); ok && seal.Signer.PublicKey == "" {
		seal.Signer.PublicKey = withPub.PublicKeyHex()
	}
	seal.Signature = hex.EncodeToString(signature)

	outDir := filepath.Join(packDir, "07_ATTESTATIONS")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(seal, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(packDir, EvidencePackSealPath), append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	return seal, nil
}

// VerifyEvidencePackSeal verifies the native EvidencePack seal against the active profile.
func VerifyEvidencePackSeal(packDir string, opts VerifyEvidencePackSealOptions) EvidencePackSealVerification {
	profile := opts.Profile
	result := EvidencePackSealVerification{
		State:      "invalid",
		TrustLevel: profile,
	}
	cfg := opts.TrustConfig
	if cfg == nil {
		var loadErr error
		cfg, loadErr = LoadEvidencePackTrustConfigWithPath(opts.ConfigPath, opts.DataDir)
		if loadErr != nil {
			result.Errors = append(result.Errors, loadErr.Error())
		}
	}
	if profile == "" && cfg != nil && cfg.ActiveProfile != "" {
		profile = cfg.ActiveProfile
	}
	profile = NormalizeEvidenceTrustProfile(profile)
	if profile == "" {
		profile = EvidenceTrustProfileDevLocal
	}
	result.TrustLevel = profile

	sealPath := filepath.Join(packDir, EvidencePackSealPath)
	data, err := os.ReadFile(sealPath)
	if err != nil {
		result.State = "missing"
		result.Errors = append(result.Errors, fmt.Sprintf("missing %s", EvidencePackSealPath))
		return result
	}
	var seal EvidencePackSeal
	if err := json.Unmarshal(data, &seal); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("parse evidence pack seal: %v", err))
		return result
	}
	result.PackID = seal.PackID
	result.IndexHash = seal.IndexHash
	result.MerkleRoot = seal.MerkleRoot
	result.EntryCount = seal.EntryCount
	result.SignerKeyID = seal.Signer.KeyID
	result.SignerType = seal.Signer.Type
	result.SignedAt = seal.SignedAt
	result.AnchorReceipts = len(seal.AnchorReceipts)
	result.AnchorStatus = seal.Anchor.Status
	if result.AnchorStatus == "" {
		result.AnchorStatus = statusForTrustType(seal.Anchor.Type)
	}
	result.StorageReceipt = firstNonEmpty(opts.StorageReceiptPath, seal.Storage.Receipt)
	result.StorageStatus = seal.Storage.Status
	if result.StorageStatus == "" {
		result.StorageStatus = statusForTrustType(seal.Storage.Type)
	}

	if seal.Version != EvidencePackSealVersion {
		result.Errors = append(result.Errors, fmt.Sprintf("unsupported seal version %q", seal.Version))
	}
	inventory, err := computeEvidencePackInventory(packDir, true, opts.AllowVerifiedConformanceSignature)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	} else {
		roots := inventory.Roots
		if seal.IndexHash != roots.IndexHash {
			result.Errors = append(result.Errors, fmt.Sprintf("index_hash mismatch: seal=%s current=%s", seal.IndexHash, roots.IndexHash))
		}
		if seal.MerkleRoot != roots.MerkleRoot {
			result.Errors = append(result.Errors, fmt.Sprintf("merkle_root mismatch: seal=%s current=%s", seal.MerkleRoot, roots.MerkleRoot))
		}
		if seal.EntryCount != roots.EntryCount {
			result.Errors = append(result.Errors, fmt.Sprintf("entry_count mismatch: seal=%d current=%d", seal.EntryCount, roots.EntryCount))
		}
	}
	publicKey, keyErr := trustedPublicKeyForSeal(seal, cfg, profile)
	if keyErr != nil {
		result.Errors = append(result.Errors, keyErr.Error())
	}
	signature, sigErr := hex.DecodeString(strings.TrimSpace(seal.Signature))
	if sigErr != nil || len(signature) != ed25519.SignatureSize {
		if sigErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("invalid seal signature encoding: %v", sigErr))
		} else {
			result.Errors = append(result.Errors, "invalid seal signature size")
		}
	} else if len(publicKey) == ed25519.PublicKeySize {
		payload, err := canonicalSealPayload(seal)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("canonicalize seal payload: %v", err))
		} else if ed25519.Verify(publicKey, payload, signature) {
			result.SignatureValid = true
		} else if legacyPayload, legacyErr := canonicalSealPayloadLegacyV1(seal); legacyErr == nil && ed25519.Verify(publicKey, legacyPayload, signature) {
			result.SignatureValid = true
		} else {
			result.Errors = append(result.Errors, "Ed25519 seal signature verification failed")
		}
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	anchorStatus, anchorErrs := verifyEvidenceAnchorReceipts(context.Background(), seal, cfg, profile)
	result.AnchorStatus = anchorStatus
	result.Errors = append(result.Errors, anchorErrs...)
	storageStatus, storageReceipt, storageErrs := VerifyStorageReceiptForSeal(seal, profile, opts.StorageReceiptPath, opts.StorageObjectPath, now)
	result.StorageStatus = storageStatus
	if storageReceipt != "" {
		result.StorageReceipt = storageReceipt
	}
	result.Errors = append(result.Errors, storageErrs...)
	result.Errors = append(result.Errors, validateProfileSeal(seal, cfg, profile)...)
	if len(result.Errors) == 0 && result.SignatureValid {
		result.State = "valid"
	}
	return result
}

type EvidencePackIndexRoots struct {
	IndexHash  string
	MerkleRoot string
	EntryCount int
}

type evidencePackInventory struct {
	Roots   EvidencePackIndexRoots
	Entries []indexRootEntry
}

// ComputeEvidencePackIndexRoots derives the seal roots from 00_INDEX.json.
func ComputeEvidencePackIndexRoots(packDir string) (EvidencePackIndexRoots, error) {
	inventory, err := computeEvidencePackInventory(packDir, false)
	return inventory.Roots, err
}

// VerifyEvidencePackIndexRoots verifies every indexed file, rejects unindexed
// files, and returns the roots of the verified inventory. Callers that use the
// result as an authorization boundary must compare it with roots obtained from
// a separately trusted seal or canonical verification result.
func VerifyEvidencePackIndexRoots(packDir string) (EvidencePackIndexRoots, error) {
	inventory, err := computeEvidencePackInventory(packDir, true)
	return inventory.Roots, err
}

func computeEvidencePackInventory(packDir string, verifyFiles bool, allowVerifiedConformanceSignature ...bool) (evidencePackInventory, error) {
	indexPath := filepath.Join(packDir, "00_INDEX.json")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return evidencePackInventory{}, fmt.Errorf("read 00_INDEX.json: %w", err)
	}
	var index indexRootFile
	if err := json.Unmarshal(indexData, &index); err != nil {
		return evidencePackInventory{}, fmt.Errorf("parse 00_INDEX.json: %w", err)
	}
	sort.Slice(index.Entries, func(i, j int) bool {
		return index.Entries[i].Path < index.Entries[j].Path
	})
	leaves := make([][]byte, 0, len(index.Entries))
	for _, entry := range index.Entries {
		clean := filepath.Clean(entry.Path)
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			return evidencePackInventory{}, fmt.Errorf("index entry escapes bundle: %s", entry.Path)
		}
		hashValue := strings.TrimPrefix(strings.TrimSpace(entry.SHA256), "sha256:")
		digest, err := hex.DecodeString(hashValue)
		if err != nil || len(digest) != sha256.Size {
			if err == nil {
				err = fmt.Errorf("expected %d bytes, got %d", sha256.Size, len(digest))
			}
			return evidencePackInventory{}, fmt.Errorf("invalid sha256 for %s: %w", entry.Path, err)
		}
		leafInput := append([]byte{0x00}, digest...)
		leaf := sha256.Sum256(leafInput)
		leaves = append(leaves, leaf[:])
	}
	if verifyFiles {
		if err := verifyEvidencePackIndexedFiles(packDir, index.Entries); err != nil {
			return evidencePackInventory{}, err
		}
		allowConformanceSignature := len(allowVerifiedConformanceSignature) > 0 && allowVerifiedConformanceSignature[0]
		if err := verifyNoUnindexedEvidencePackFiles(packDir, index.Entries, allowConformanceSignature); err != nil {
			return evidencePackInventory{}, err
		}
	}
	return evidencePackInventory{Roots: EvidencePackIndexRoots{
		IndexHash:  sha256HexEvidence(indexData),
		MerkleRoot: merkleRootHexEvidence(leaves),
		EntryCount: len(index.Entries),
	}, Entries: index.Entries}, nil
}

func verifyNoUnindexedEvidencePackFiles(packDir string, entries []indexRootEntry, allowVerifiedConformanceSignature bool) error {
	indexed := make(map[string]bool, len(entries))
	for _, entry := range entries {
		indexed[filepath.ToSlash(filepath.Clean(entry.Path))] = true
	}
	allowedUnindexed := map[string]bool{
		"00_INDEX.json":      true,
		EvidencePackSealPath: true,
	}
	if allowVerifiedConformanceSignature {
		allowedUnindexed["07_ATTESTATIONS/conformance_report.sig"] = true
	}
	return filepath.WalkDir(packDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(packDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !indexed[rel] && !allowedUnindexed[rel] {
			return fmt.Errorf("unindexed evidence pack file: %s", rel)
		}
		return nil
	})
}

func verifyEvidencePackIndexedFiles(packDir string, entries []indexRootEntry) error {
	if len(entries) == 0 {
		return nil
	}
	workers := runtime.GOMAXPROCS(0)
	if workers > 8 {
		workers = 8
	}
	if workers > len(entries) {
		workers = len(entries)
	}
	jobs := make(chan indexRootEntry)
	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range jobs {
				if err := verifyEvidencePackIndexedFile(packDir, entry); err != nil {
					select {
					case errCh <- err:
					default:
					}
				}
			}
		}()
	}
	for _, entry := range entries {
		jobs <- entry
	}
	close(jobs)
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func verifyEvidencePackIndexedFile(packDir string, entry indexRootEntry) error {
	clean := filepath.Clean(entry.Path)
	actual, err := HashFile(filepath.Join(packDir, clean))
	if err != nil {
		return fmt.Errorf("hash indexed file %s: %w", entry.Path, err)
	}
	expected := strings.TrimPrefix(strings.TrimSpace(entry.SHA256), "sha256:")
	if !strings.EqualFold(strings.TrimPrefix(actual, "sha256:"), expected) {
		return fmt.Errorf("indexed file hash mismatch for %s: index=sha256:%s current=%s", entry.Path, expected, actual)
	}
	return nil
}

// ResolveEvidenceSigner creates the configured signer. KMS is fail-closed unless
// a configured signing command and key id are provided.
func ResolveEvidenceSigner(cfg *EvidencePackTrustConfig, dataDir string) (EvidenceSigner, error) {
	signerType := strings.TrimSpace(os.Getenv("HELM_EVIDENCE_SIGNER"))
	if signerType == "" && cfg != nil {
		signerType = cfg.Signer.Type
	}
	if signerType == "" {
		signerType = "file-dev"
	}
	switch signerType {
	case "file-dev", "local-dev":
		return NewFileDevEvidenceSigner(dataDir)
	case "kms":
		signerCfg := EvidencePackTrustSigner{Type: "kms"}
		if cfg != nil {
			signerCfg = cfg.Signer
		}
		return NewKMSEvidenceSigner(signerCfg)
	default:
		return nil, fmt.Errorf("unsupported evidence pack signer %q", signerType)
	}
}

type FileDevEvidenceSigner struct {
	path       string
	keyID      string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

type fileDevKeyFile struct {
	Version    string    `json:"version"`
	Algorithm  string    `json:"algorithm"`
	KeyID      string    `json:"key_id"`
	PrivateKey string    `json:"private_key"`
	PublicKey  string    `json:"public_key"`
	CreatedAt  time.Time `json:"created_at"`
}

func NewFileDevEvidenceSigner(dataDir string) (*FileDevEvidenceSigner, error) {
	path := FileDevEvidenceKeyPath(dataDir)
	if data, err := os.ReadFile(path); err == nil {
		return parseFileDevEvidenceSigner(path, data)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	keyID := fileDevKeyID(publicKey)
	keyFile := fileDevKeyFile{
		Version:    "file-dev-ed25519/v1",
		Algorithm:  "ed25519",
		KeyID:      keyID,
		PrivateKey: hex.EncodeToString(privateKey),
		PublicKey:  hex.EncodeToString(publicKey),
		CreatedAt:  time.Now().UTC(),
	}
	data, err := json.MarshalIndent(keyFile, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	return &FileDevEvidenceSigner{path: path, keyID: keyID, privateKey: privateKey, publicKey: publicKey}, nil
}

func parseFileDevEvidenceSigner(path string, data []byte) (*FileDevEvidenceSigner, error) {
	var keyFile fileDevKeyFile
	if err := json.Unmarshal(data, &keyFile); err != nil {
		return nil, fmt.Errorf("parse file-dev evidence key: %w", err)
	}
	privateKeyBytes, err := hex.DecodeString(strings.TrimSpace(keyFile.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("decode file-dev private key: %w", err)
	}
	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("file-dev private key must be %d bytes", ed25519.PrivateKeySize)
	}
	privateKey := ed25519.PrivateKey(privateKeyBytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if keyFile.PublicKey != "" && hex.EncodeToString(publicKey) != strings.ToLower(strings.TrimSpace(keyFile.PublicKey)) {
		return nil, errors.New("file-dev public key does not match private key")
	}
	keyID := keyFile.KeyID
	if keyID == "" {
		keyID = fileDevKeyID(publicKey)
	}
	return &FileDevEvidenceSigner{path: path, keyID: keyID, privateKey: privateKey, publicKey: publicKey}, nil
}

func (s *FileDevEvidenceSigner) KeyID() string { return s.keyID }

func (s *FileDevEvidenceSigner) PublicKeyHex() string {
	return hex.EncodeToString(s.publicKey)
}

func (s *FileDevEvidenceSigner) SignerType() string { return "file-dev" }

func (s *FileDevEvidenceSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(s.privateKey, payload), nil
}

func (s *FileDevEvidenceSigner) Path() string { return s.path }

type KMSEvidenceSigner struct {
	keyID       string
	publicKey   string
	signCommand string
}

func NewKMSEvidenceSigner(cfg EvidencePackTrustSigner) (*KMSEvidenceSigner, error) {
	keyID := firstNonEmpty(cfg.KMSKeyID, cfg.KeyID, os.Getenv("HELM_EVIDENCE_KMS_KEY_ID"))
	signCommand := firstNonEmpty(cfg.SignCommand, os.Getenv("HELM_EVIDENCE_KMS_SIGN_COMMAND"))
	publicKey := firstNonEmpty(cfg.PublicKey, os.Getenv("HELM_EVIDENCE_KMS_PUBLIC_KEY_HEX"))
	if keyID == "" || signCommand == "" {
		return nil, errors.New("kms evidence signer is not configured; set HELM_EVIDENCE_KMS_KEY_ID and HELM_EVIDENCE_KMS_SIGN_COMMAND or trust config")
	}
	return &KMSEvidenceSigner{keyID: keyID, publicKey: publicKey, signCommand: signCommand}, nil
}

func (s *KMSEvidenceSigner) KeyID() string { return s.keyID }

func (s *KMSEvidenceSigner) PublicKeyHex() string { return s.publicKey }

func (s *KMSEvidenceSigner) SignerType() string { return "kms" }

func (s *KMSEvidenceSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	resp, err := (crypto.CommandSigner{
		Command:   s.signCommand,
		KeyID:     s.keyID,
		Algorithm: "ed25519",
	}).Sign(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("kms sign command failed: %w", err)
	}
	if resp.KeyID != "" && s.keyID != "" && resp.KeyID != s.keyID {
		return nil, fmt.Errorf("kms signer key_id mismatch: expected %s got %s", s.keyID, resp.KeyID)
	}
	if s.keyID == "" {
		s.keyID = resp.KeyID
	}
	if resp.PublicKey != "" {
		s.publicKey = resp.PublicKey
	}
	signature, err := crypto.DecodeSignature(resp.Signature)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func FileDevEvidenceKeyPath(dataDir string) string {
	return filepath.Join(ResolveEvidencePackDataDir(dataDir), "keys", "evidence-pack-dev.ed25519")
}

func EvidencePackTrustConfigPath(dataDir string) string {
	if override := strings.TrimSpace(os.Getenv("HELM_EVIDENCE_TRUST_CONFIG")); override != "" {
		return override
	}
	return filepath.Join(ResolveEvidencePackDataDir(dataDir), "trust", "evidence-pack.json")
}

func EvidencePackTrustConfigPathForWrite(configPath, dataDir string) string {
	if strings.TrimSpace(configPath) != "" {
		return strings.TrimSpace(configPath)
	}
	return EvidencePackTrustConfigPath(dataDir)
}

func ResolveEvidencePackDataDir(dataDir string) string {
	if strings.TrimSpace(dataDir) != "" {
		return strings.TrimSpace(dataDir)
	}
	if env := strings.TrimSpace(os.Getenv("HELM_DATA_DIR")); env != "" {
		return env
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".helm")
	}
	return ".helm"
}

func LoadEvidencePackTrustConfig(dataDir string) (*EvidencePackTrustConfig, error) {
	return LoadEvidencePackTrustConfigWithPath("", dataDir)
}

func LoadEvidencePackTrustConfigWithPath(configPath, dataDir string) (*EvidencePackTrustConfig, error) {
	for _, path := range evidencePackTrustConfigCandidates(configPath, dataDir) {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		cfg, err := parseEvidencePackTrustConfig(data)
		if err != nil {
			if shouldSkipUnrelatedEvidencePackTrustConfig(configPath, path, data) {
				continue
			}
			return nil, fmt.Errorf("parse evidence pack trust config %s: %w", path, err)
		}
		return cfg, nil
	}
	return nil, nil
}

func SaveEvidencePackTrustConfig(dataDir string, cfg EvidencePackTrustConfig) (string, error) {
	return SaveEvidencePackTrustConfigWithPath("", dataDir, cfg)
}

func SaveEvidencePackTrustConfigWithPath(configPath, dataDir string, cfg EvidencePackTrustConfig) (string, error) {
	if cfg.Version == "" {
		cfg.Version = "evidence-pack-trust/v1"
	}
	if cfg.ActiveProfile == "" {
		cfg.ActiveProfile = EvidenceTrustProfileDevLocal
	}
	if cfg.UpdatedAt.IsZero() {
		cfg.UpdatedAt = time.Now().UTC()
	}
	path := EvidencePackTrustConfigPathForWrite(configPath, dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	var data []byte
	var err error
	if strings.HasSuffix(strings.ToLower(path), ".yaml") || strings.HasSuffix(strings.ToLower(path), ".yml") {
		data, err = marshalEvidencePackTrustYAML(cfg)
	} else {
		data, err = json.MarshalIndent(cfg, "", "  ")
	}
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func NewEvidencePackTrustConfig(profile EvidenceTrustProfile, signerType, anchorType, storageType string, objectLock bool, dataDir string) (EvidencePackTrustConfig, error) {
	profile = NormalizeEvidenceTrustProfile(profile)
	if profile == "" {
		profile = EvidenceTrustProfileDevLocal
	}
	if signerType == "" {
		signerType = "file-dev"
	}
	if anchorType == "" {
		anchorType = "local-dev"
	}
	if storageType == "" {
		storageType = "local-dev"
	}
	cfg := EvidencePackTrustConfig{
		Version:       "evidence-pack-trust/v1",
		ActiveProfile: profile,
		Signer:        EvidencePackTrustSigner{Type: signerType},
		Anchor:        EvidencePackSealAnchor{Type: anchorType, Status: statusForTrustType(anchorType)},
		Storage:       EvidencePackSealStorage{Type: storageType, Status: statusForTrustType(storageType), ObjectLock: objectLock, Immutable: objectLock},
		TrustedKeys:   map[string]string{},
		UpdatedAt:     time.Now().UTC(),
	}
	switch signerType {
	case "file-dev", "local-dev":
		signer, err := NewFileDevEvidenceSigner(dataDir)
		if err != nil {
			return cfg, err
		}
		cfg.Signer.Type = "file-dev"
		cfg.Signer.KeyID = signer.KeyID()
		cfg.Signer.PublicKey = signer.PublicKeyHex()
		cfg.TrustedKeys[signer.KeyID()] = signer.PublicKeyHex()
	case "kms":
		cfg.Signer.KeyID = firstNonEmpty(os.Getenv("HELM_EVIDENCE_KMS_KEY_ID"), os.Getenv("HELM_EVIDENCE_SIGNER_KEY_ID"))
		cfg.Signer.KMSKeyID = cfg.Signer.KeyID
		cfg.Signer.PublicKey = os.Getenv("HELM_EVIDENCE_KMS_PUBLIC_KEY_HEX")
		cfg.Signer.SignCommand = os.Getenv("HELM_EVIDENCE_KMS_SIGN_COMMAND")
		if cfg.Signer.PublicKey != "" && cfg.Signer.KeyID != "" {
			cfg.TrustedKeys[cfg.Signer.KeyID] = cfg.Signer.PublicKey
		}
	default:
		return cfg, fmt.Errorf("unsupported evidence pack signer %q", signerType)
	}
	return cfg, nil
}

type evidencePackTrustYAMLFile struct {
	Version string `yaml:"version,omitempty"`
	Trust   struct {
		EvidencePack evidencePackTrustYAML `yaml:"evidence_pack"`
	} `yaml:"trust"`
}

type evidencePackTrustYAML struct {
	Version       string                  `yaml:"version,omitempty"`
	Profile       EvidenceTrustProfile    `yaml:"profile,omitempty"`
	ActiveProfile EvidenceTrustProfile    `yaml:"active_profile,omitempty"`
	Signer        EvidencePackTrustSigner `yaml:"signer,omitempty"`
	Anchor        EvidencePackSealAnchor  `yaml:"anchor,omitempty"`
	Storage       EvidencePackSealStorage `yaml:"storage,omitempty"`
	TrustedKeys   map[string]string       `yaml:"trusted_keys,omitempty"`
	UpdatedAt     time.Time               `yaml:"updated_at,omitempty"`
}

func parseEvidencePackTrustConfig(data []byte) (*EvidencePackTrustConfig, error) {
	var file evidencePackTrustYAMLFile
	if err := yaml.Unmarshal(data, &file); err == nil {
		nested := file.Trust.EvidencePack
		if hasEvidencePackTrustYAML(nested) {
			cfg := EvidencePackTrustConfig{
				Version:       nested.Version,
				ActiveProfile: firstNonEmptyProfile(nested.ActiveProfile, nested.Profile),
				Signer:        nested.Signer,
				Anchor:        nested.Anchor,
				Storage:       nested.Storage,
				TrustedKeys:   nested.TrustedKeys,
				UpdatedAt:     nested.UpdatedAt,
			}
			cfg.ActiveProfile = NormalizeEvidenceTrustProfile(cfg.ActiveProfile)
			return &cfg, nil
		}
	}
	var cfg EvidencePackTrustConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.ActiveProfile = NormalizeEvidenceTrustProfile(cfg.ActiveProfile)
	return &cfg, nil
}

func shouldSkipUnrelatedEvidencePackTrustConfig(configPath, path string, data []byte) bool {
	if strings.TrimSpace(configPath) != "" || filepath.ToSlash(path) != "helm/helm.yaml" {
		return false
	}
	var file evidencePackTrustYAMLFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return false
	}
	return !hasEvidencePackTrustYAML(file.Trust.EvidencePack)
}

func hasEvidencePackTrustYAML(cfg evidencePackTrustYAML) bool {
	return cfg.Version != "" ||
		cfg.Profile != "" ||
		cfg.ActiveProfile != "" ||
		cfg.Signer.Type != "" ||
		cfg.Signer.KeyID != "" ||
		cfg.Signer.PublicKey != "" ||
		cfg.Signer.KMSKeyID != "" ||
		cfg.Signer.SignCommand != "" ||
		cfg.Anchor.Type != "" ||
		cfg.Anchor.URI != "" ||
		cfg.Anchor.URL != "" ||
		cfg.Storage.Type != "" ||
		cfg.Storage.URI != "" ||
		cfg.Storage.Bucket != "" ||
		len(cfg.TrustedKeys) > 0 ||
		!cfg.UpdatedAt.IsZero()
}

func marshalEvidencePackTrustYAML(cfg EvidencePackTrustConfig) ([]byte, error) {
	file := evidencePackTrustYAMLFile{Version: "1.0"}
	file.Trust.EvidencePack = evidencePackTrustYAML{
		Version:     cfg.Version,
		Profile:     cfg.ActiveProfile,
		Signer:      cfg.Signer,
		Anchor:      cfg.Anchor,
		Storage:     cfg.Storage,
		TrustedKeys: cfg.TrustedKeys,
		UpdatedAt:   cfg.UpdatedAt,
	}
	return yaml.Marshal(file)
}

func evidencePackTrustConfigCandidates(configPath, dataDir string) []string {
	if strings.TrimSpace(configPath) != "" {
		return []string{strings.TrimSpace(configPath)}
	}
	var candidates []string
	if env := strings.TrimSpace(os.Getenv("HELM_EVIDENCE_TRUST_CONFIG")); env != "" {
		candidates = append(candidates, env)
	}
	candidates = append(candidates, filepath.Join("helm", "helm.yaml"))
	candidates = append(candidates, filepath.Join(ResolveEvidencePackDataDir(dataDir), "trust", "evidence-pack.json"))
	return candidates
}

func firstNonEmptyProfile(values ...EvidenceTrustProfile) EvidenceTrustProfile {
	for _, value := range values {
		if strings.TrimSpace(string(value)) != "" {
			return value
		}
	}
	return ""
}

func NormalizeEvidenceTrustProfile(profile EvidenceTrustProfile) EvidenceTrustProfile {
	switch strings.ToLower(strings.TrimSpace(string(profile))) {
	case "", "dev-local", "local-dev", "local", "dev":
		if strings.TrimSpace(string(profile)) == "" {
			return ""
		}
		return EvidenceTrustProfileDevLocal
	case "team":
		return EvidenceTrustProfileTeam
	case "customer", "prod", "production":
		return EvidenceTrustProfileCustomer
	case "high-assurance":
		return EvidenceTrustProfileHighAssurance
	default:
		return profile
	}
}

func canonicalSealPayload(seal EvidencePackSeal) ([]byte, error) {
	signer := seal.Signer
	// Public keys may be returned by external signers with the signature. Trust
	// is established from local config/env, so avoid making that response field
	// part of the signed payload.
	signer.PublicKey = ""
	payload := evidencePackSealPayload{
		Version:        seal.Version,
		PackID:         seal.PackID,
		IndexHash:      seal.IndexHash,
		MerkleRoot:     seal.MerkleRoot,
		EntryCount:     seal.EntryCount,
		Profile:        seal.Profile,
		Signer:         signer,
		Anchor:         seal.Anchor,
		AnchorReceipts: seal.AnchorReceipts,
		Storage:        seal.Storage,
		SignedAt:       seal.SignedAt.UTC(),
	}
	return canonicalize.JCS(payload)
}

func canonicalSealPayloadLegacyV1(seal EvidencePackSeal) ([]byte, error) {
	type legacyAnchor struct {
		Type   string    `json:"type"`
		URI    string    `json:"uri,omitempty"`
		Status string    `json:"status"`
		Time   time.Time `json:"time,omitempty"`
	}
	type legacyStorage struct {
		Type       string `json:"type"`
		URI        string `json:"uri,omitempty"`
		Status     string `json:"status"`
		ObjectLock bool   `json:"object_lock,omitempty"`
		Immutable  bool   `json:"immutable,omitempty"`
	}
	payload := struct {
		Version    string                 `json:"version"`
		PackID     string                 `json:"pack_id"`
		IndexHash  string                 `json:"index_hash"`
		MerkleRoot string                 `json:"merkle_root"`
		EntryCount int                    `json:"entry_count"`
		Profile    EvidenceTrustProfile   `json:"profile"`
		Signer     EvidencePackSealSigner `json:"signer"`
		Anchor     legacyAnchor           `json:"anchor"`
		Storage    legacyStorage          `json:"storage"`
		SignedAt   time.Time              `json:"signed_at"`
	}{
		Version:    seal.Version,
		PackID:     seal.PackID,
		IndexHash:  seal.IndexHash,
		MerkleRoot: seal.MerkleRoot,
		EntryCount: seal.EntryCount,
		Profile:    seal.Profile,
		Signer:     seal.Signer,
		Anchor: legacyAnchor{
			Type:   seal.Anchor.Type,
			URI:    seal.Anchor.URI,
			Status: seal.Anchor.Status,
			Time:   seal.Anchor.Time,
		},
		Storage: legacyStorage{
			Type:       seal.Storage.Type,
			URI:        seal.Storage.URI,
			Status:     seal.Storage.Status,
			ObjectLock: seal.Storage.ObjectLock,
			Immutable:  seal.Storage.Immutable,
		},
		SignedAt: seal.SignedAt.UTC(),
	}
	return canonicalize.JCS(payload)
}

func inferPackID(packDir, indexHash string) string {
	for _, rel := range []string{"00_INDEX.json", "manifest.json", "04_EXPORTS/launchpad_manifest.json"} {
		data, err := os.ReadFile(filepath.Join(packDir, rel))
		if err != nil {
			continue
		}
		var doc map[string]any
		if json.Unmarshal(data, &doc) != nil {
			continue
		}
		for _, key := range []string{"pack_id", "run_id", "launch_id", "session_id", "id"} {
			if value, ok := doc[key].(string); ok && value != "" {
				return value
			}
		}
	}
	if indexHash != "" {
		return "ep_" + indexHash[:12]
	}
	return "ep_unknown"
}

func trustedPublicKeyForSeal(seal EvidencePackSeal, cfg *EvidencePackTrustConfig, profile EvidenceTrustProfile) (ed25519.PublicKey, error) {
	trusted := ""
	if cfg != nil {
		if cfg.TrustedKeys != nil {
			trusted = cfg.TrustedKeys[seal.Signer.KeyID]
		}
		if trusted == "" && cfg.Signer.KeyID == seal.Signer.KeyID {
			trusted = cfg.Signer.PublicKey
		}
	}
	if trusted == "" {
		trusted = firstNonEmpty(os.Getenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX"), os.Getenv("HELM_EVIDENCE_SIGNER_PUBLIC_KEY_HEX"))
	}
	if trusted != "" {
		if seal.Signer.PublicKey != "" && !strings.EqualFold(strings.TrimSpace(trusted), strings.TrimSpace(seal.Signer.PublicKey)) {
			return nil, fmt.Errorf("trusted key mismatch for signer %s", seal.Signer.KeyID)
		}
		return decodeEd25519PublicKey(trusted)
	}
	if profile == EvidenceTrustProfileDevLocal && seal.Signer.Type == "file-dev" && seal.Signer.PublicKey != "" {
		return decodeEd25519PublicKey(seal.Signer.PublicKey)
	}
	return nil, fmt.Errorf("no trusted public key configured for signer %s under profile %s", seal.Signer.KeyID, profile)
}

func decodeEd25519PublicKey(value string) (ed25519.PublicKey, error) {
	data, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("invalid trusted public key hex: %w", err)
	}
	if len(data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trusted public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(data), nil
}

func validateProfileSeal(seal EvidencePackSeal, cfg *EvidencePackTrustConfig, profile EvidenceTrustProfile) []string {
	var errs []string
	switch profile {
	case EvidenceTrustProfileDevLocal:
		return errs
	case EvidenceTrustProfileTeam:
		if seal.Signer.KeyID == "" {
			errs = append(errs, "team profile requires signer key id")
		}
	case EvidenceTrustProfileCustomer, EvidenceTrustProfileHighAssurance:
		if seal.Signer.Type == "file-dev" || seal.Signer.Type == "local-dev" {
			errs = append(errs, fmt.Sprintf("%s profile requires an external signer, got %s", profile, seal.Signer.Type))
		}
		if seal.Anchor.Type == "" || seal.Anchor.Type == "local-dev" {
			errs = append(errs, fmt.Sprintf("%s profile requires an external anchor", profile))
		}
		if seal.Storage.Type == "" || seal.Storage.Type == "local-dev" {
			errs = append(errs, fmt.Sprintf("%s profile requires off-host storage metadata", profile))
		}
		if profile == EvidenceTrustProfileHighAssurance && !seal.Storage.ObjectLock && !seal.Storage.Immutable {
			errs = append(errs, "high-assurance profile requires immutable/WORM storage metadata")
		}
	default:
		errs = append(errs, fmt.Sprintf("unknown evidence trust profile %q", profile))
	}
	if cfg == nil && profile != EvidenceTrustProfileDevLocal && !trustedKeyEnvConfigured() {
		errs = append(errs, fmt.Sprintf("%s profile requires a local trust config or trusted-key env", profile))
	}
	return errs
}

func trustedKeyEnvConfigured() bool {
	return strings.TrimSpace(firstNonEmpty(os.Getenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX"), os.Getenv("HELM_EVIDENCE_SIGNER_PUBLIC_KEY_HEX"))) != ""
}

func profileRequiresExternalTrust(profile EvidenceTrustProfile) bool {
	return profile == EvidenceTrustProfileCustomer || profile == EvidenceTrustProfileHighAssurance
}

func ProfileRequiresExternalTrust(profile EvidenceTrustProfile) bool {
	return profileRequiresExternalTrust(NormalizeEvidenceTrustProfile(profile))
}

func BuildEvidencePackVerifyCommand(bundle string, profile EvidenceTrustProfile, storageReceiptPath string) string {
	cmd := "helm-ai-kernel verify --bundle " + bundle
	profile = NormalizeEvidenceTrustProfile(profile)
	if profileRequiresExternalTrust(profile) {
		cmd += " --profile " + string(profile)
		if strings.TrimSpace(storageReceiptPath) != "" {
			cmd += " --storage-receipt " + strings.TrimSpace(storageReceiptPath)
		}
	}
	return cmd
}

func isLocalEvidenceSignerType(signerType string) bool {
	switch strings.ToLower(strings.TrimSpace(signerType)) {
	case "file-dev", "local-dev":
		return true
	default:
		return false
	}
}

func devLocalAnchor(now time.Time) EvidencePackSealAnchor {
	return EvidencePackSealAnchor{
		Type:   "local-dev",
		URI:    "local-dev://evidence-pack",
		Status: "development-only",
		Time:   now.UTC(),
	}
}

func devLocalStorage() EvidencePackSealStorage {
	return EvidencePackSealStorage{
		Type:   "local-dev",
		URI:    "local-dev://evidence-pack",
		Status: "development-only",
	}
}

func statusForTrustType(value string) string {
	if value == "" || value == "local-dev" || value == "file-dev" {
		return "development-only"
	}
	return "configured"
}

func fileDevKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "file-dev:" + hex.EncodeToString(sum[:])[:16]
}

func merkleRootHexEvidence(leaves [][]byte) string {
	if len(leaves) == 0 {
		return sha256HexEvidence(nil)
	}
	for len(leaves) > 1 {
		next := make([][]byte, 0, (len(leaves)+1)/2)
		for i := 0; i < len(leaves); i += 2 {
			left := leaves[i]
			right := left
			if i+1 < len(leaves) {
				right = leaves[i+1]
			}
			input := make([]byte, 0, 1+len(left)+len(right))
			input = append(input, 0x01)
			input = append(input, left...)
			input = append(input, right...)
			parent := sha256.Sum256(input)
			next = append(next, parent[:])
		}
		leaves = next
	}
	return hex.EncodeToString(leaves[0])
}

func sha256HexEvidence(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
