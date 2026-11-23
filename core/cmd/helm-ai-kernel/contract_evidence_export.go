package main

// quantum_posture: evidence export seals packs through the configured receipt
// signer and uses SHA-256 to index the archived files.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

const (
	maxEvidenceBundleBytes    = 32 << 20
	maxEvidenceExportReceipts = 10000
	evidenceExportPageSize    = 500
	evidenceBundleIndexPath   = "00_INDEX.json"
)

var errEvidenceExportTooLarge = errors.New("evidence export receipt limit exceeded")

type evidenceManifest struct {
	Version    string            `json:"version"`
	ExportedAt string            `json:"exported_at"`
	SessionID  string            `json:"session_id,omitempty"`
	FileHashes map[string]string `json:"file_hashes"`
}

type evidenceBundle struct {
	Manifest evidenceManifest
	Files    map[string][]byte
}

type runtimeEvidenceSealSigner struct {
	keyID      string
	publicKey  string
	signerType string
	signFn     func([]byte) (string, error)
}

func (s runtimeEvidenceSealSigner) KeyID() string {
	return s.keyID
}

func (s runtimeEvidenceSealSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	signatureHex, err := s.signFn(payload)
	if err != nil {
		return nil, err
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return nil, fmt.Errorf("decode runtime evidence seal signature: %w", err)
	}
	return signature, nil
}

func (s runtimeEvidenceSealSigner) SignerType() string {
	return s.signerType
}

func (s runtimeEvidenceSealSigner) PublicKeyHex() string {
	return s.publicKey
}

func contractReceiptsForExport(ctx context.Context, svc *Services, tenantID, sessionID string) ([]*contracts.Receipt, error) {
	return contractReceiptsForExportWithPageSize(ctx, svc, tenantID, sessionID, evidenceExportPageSize)
}

func contractReceiptsForExportWithPageSize(ctx context.Context, svc *Services, tenantID, sessionID string, pageSize int) ([]*contracts.Receipt, error) {
	if svc == nil || svc.ReceiptStore == nil {
		return nil, fmt.Errorf("receipt store unavailable")
	}
	if pageSize <= 0 {
		return nil, fmt.Errorf("evidence export page size must be positive")
	}
	var receipts []*contracts.Receipt
	var cursor store.TenantReceiptCursor
	for {
		remaining := maxEvidenceExportReceipts - len(receipts)
		if remaining <= 0 {
			return nil, errEvidenceExportTooLarge
		}
		limit := pageSize
		if remaining <= limit {
			// Read one extra receipt at the cap so exactly-max exports succeed
			// while a truncated export still fails closed.
			limit = remaining + 1
		}
		var page []*contracts.Receipt
		var err error
		page, err = listReceiptsForCursor(ctx, svc, tenantID, sessionID, cursor, store.ReceiptQueryFilter{}, limit)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return receipts, nil
		}
		if len(page) > remaining {
			return nil, errEvidenceExportTooLarge
		}
		canonicalPage, err := canonicalReceiptsForTenant(ctx, svc, tenantID, page)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, canonicalPage...)
		nextCursor, err := receiptCursorForReceipt(sessionID, page[len(page)-1])
		if err != nil {
			return nil, err
		}
		cursor = nextCursor
		if len(page) < limit {
			return receipts, nil
		}
	}
}

func buildTrustedEvidenceBundleWithSurfaceArtifacts(sessionID string, receipts []*contracts.Receipt, surfaces *boundarypkg.SurfaceRegistry, svc *Services) ([]byte, error) {
	files, err := buildEvidenceBundleFilesWithSurfaceArtifacts(sessionID, receipts, surfaces)
	if err != nil {
		return nil, err
	}
	sealSigner, trustConfig, err := trustedEvidenceBundleSealSigner(svc)
	if err != nil {
		return nil, err
	}
	packDir, err := os.MkdirTemp("", "helm-evidence-export-*")
	if err != nil {
		return nil, fmt.Errorf("create evidence export workspace: %w", err)
	}
	defer os.RemoveAll(packDir)
	if err := writeEvidenceBundlePackFiles(packDir, files); err != nil {
		return nil, err
	}
	if err := writeEvidenceBundleIndex(packDir, files); err != nil {
		return nil, err
	}
	if _, err := evidencepkg.SealEvidencePack(context.Background(), packDir, evidencepkg.SealEvidencePackOptions{
		PackID:      evidenceBundlePackID(sessionID, files),
		Profile:     evidencepkg.EvidenceTrustProfileDevLocal,
		Signer:      sealSigner,
		TrustConfig: trustConfig,
		SignedAt:    evidenceBundleSignedAt(receipts),
	}); err != nil {
		return nil, fmt.Errorf("seal evidence bundle: %w", err)
	}
	for _, controlPath := range []string{evidenceBundleIndexPath, evidencepkg.EvidencePackSealPath} {
		data, err := os.ReadFile(filepath.Join(packDir, filepath.FromSlash(controlPath)))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", controlPath, err)
		}
		files[controlPath] = data
	}
	return tarEvidenceBundleFiles(files)
}

func buildEvidenceBundleFilesWithSurfaceArtifacts(sessionID string, receipts []*contracts.Receipt, surfaces *boundarypkg.SurfaceRegistry) (map[string][]byte, error) {
	files := make(map[string][]byte)
	for _, receipt := range receipts {
		data, err := json.Marshal(receipt)
		if err != nil {
			return nil, fmt.Errorf("marshal receipt %s: %w", receipt.ReceiptID, err)
		}
		files["receipts/"+receipt.ReceiptID+".json"] = data
	}
	if surfaces != nil {
		if err := addReferencedSurfaceArtifacts(files, surfaces, receipts); err != nil {
			return nil, err
		}
	}
	fileHashes := make(map[string]string, len(files))
	for name, data := range files {
		sum := sha256.Sum256(data)
		fileHashes[name] = hex.EncodeToString(sum[:])
	}
	manifest := evidenceManifest{
		Version:    "1.0",
		ExportedAt: "1970-01-01T00:00:00Z",
		SessionID:  sessionID,
		FileHashes: fileHashes,
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	files["manifest.json"] = manifestData
	return files, nil
}

func tarEvidenceBundleFiles(files map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzipWriter)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := writeTarEntry(tarWriter, name, files[name]); err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			return nil, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		return nil, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeEvidenceBundlePackFiles(packDir string, files map[string][]byte) error {
	root, err := os.OpenRoot(packDir)
	if err != nil {
		return fmt.Errorf("open evidence bundle root: %w", err)
	}
	defer func() { _ = root.Close() }()
	for name, data := range files {
		if !safeArchiveName(name) {
			return fmt.Errorf("unsafe archive path %q", name)
		}
		if dir := path.Dir(name); dir != "." {
			if err := root.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("mkdir evidence bundle path %s: %w", name, err)
			}
		}
		if err := root.WriteFile(name, data, 0o600); err != nil {
			return fmt.Errorf("write evidence bundle file %s: %w", name, err)
		}
	}
	return nil
}

func writeEvidenceBundleIndex(packDir string, files map[string][]byte) error {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]map[string]string, 0, len(names))
	for _, name := range names {
		sum := sha256.Sum256(files[name])
		entries = append(entries, map[string]string{
			"path":   name,
			"sha256": hex.EncodeToString(sum[:]),
		})
	}
	indexData, err := json.MarshalIndent(map[string]any{
		"version": "1.0.0",
		"entries": entries,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal evidence bundle index: %w", err)
	}
	if err := os.WriteFile(filepath.Join(packDir, evidenceBundleIndexPath), append(indexData, '\n'), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", evidenceBundleIndexPath, err)
	}
	return nil
}

func evidenceBundlePackID(sessionID string, files map[string][]byte) string {
	if strings.TrimSpace(sessionID) != "" {
		return "evidence-export-" + sessionID
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	sum := sha256.Sum256([]byte(strings.Join(names, "\n")))
	return "evidence-export-" + hex.EncodeToString(sum[:8])
}

func evidenceBundleSignedAt(receipts []*contracts.Receipt) time.Time {
	signedAt := time.Unix(0, 0).UTC()
	for _, receipt := range receipts {
		if receipt != nil && receipt.Timestamp.After(signedAt) {
			signedAt = receipt.Timestamp.UTC()
		}
	}
	return signedAt
}

func writeTarEntry(tw *tar.Writer, name string, data []byte) error {
	if !safeArchiveName(name) {
		return fmt.Errorf("unsafe archive path %q", name)
	}
	header := &tar.Header{Name: name, Size: int64(len(data)), Mode: 0644, ModTime: time.Unix(0, 0), Uid: 0, Gid: 0}
	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("write tar header %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("write tar data %s: %w", name, err)
	}
	return nil
}

func trustedEvidenceBundleSealSigner(svc *Services) (evidencepkg.EvidenceSigner, *evidencepkg.EvidencePackTrustConfig, error) {
	if svc == nil || svc.ReceiptSigner == nil {
		return nil, nil, errors.New("trusted evidence bundle seal signer unavailable")
	}
	switch signer := svc.ReceiptSigner.(type) {
	case *helmcrypto.Ed25519Signer:
		if signer == nil {
			return nil, nil, errors.New("trusted evidence bundle seal signer unavailable")
		}
		return runtimeEvidenceSealSigner{
			keyID:      signer.GetKeyID(),
			publicKey:  signer.PublicKey(),
			signerType: "runtime-receipt-ed25519",
			signFn:     signer.Sign,
		}, trustedEvidenceBundleSealConfig(signer.GetKeyID(), signer.PublicKey(), "runtime-receipt-ed25519"), nil
	case *helmcrypto.HybridSigner:
		if signer == nil || signer.Ed25519Signer() == nil {
			return nil, nil, errors.New("trusted evidence bundle seal signer unavailable")
		}
		edSigner := signer.Ed25519Signer()
		return runtimeEvidenceSealSigner{
			keyID:      signer.GetKeyID(),
			publicKey:  edSigner.PublicKey(),
			signerType: "runtime-receipt-hybrid-ed25519",
			signFn:     edSigner.Sign,
		}, trustedEvidenceBundleSealConfig(signer.GetKeyID(), edSigner.PublicKey(), "runtime-receipt-hybrid-ed25519"), nil
	case *helmcrypto.MLDSASigner:
		return nil, nil, errors.New("trusted evidence bundle seal signer unsupported: runtime is MLDSA-only and existing EvidencePack seals require Ed25519")
	case *helmcrypto.KeyRing:
		return nil, nil, errors.New("trusted evidence bundle seal signer unsupported: runtime signer keyring does not expose a stable Ed25519 trust root for bundle sealing")
	default:
		return nil, nil, fmt.Errorf("trusted evidence bundle seal signer unsupported: %T", svc.ReceiptSigner)
	}
}

func trustedEvidenceBundleSealTrustConfig(svc *Services) (*evidencepkg.EvidencePackTrustConfig, error) {
	_, trustConfig, err := trustedEvidenceBundleSealSigner(svc)
	return trustConfig, err
}

func trustedEvidenceBundleSealConfig(keyID, publicKey, signerType string) *evidencepkg.EvidencePackTrustConfig {
	return &evidencepkg.EvidencePackTrustConfig{
		Version:       "evidence-pack-trust/v1",
		ActiveProfile: evidencepkg.EvidenceTrustProfileDevLocal,
		Signer: evidencepkg.EvidencePackTrustSigner{
			Type:      signerType,
			KeyID:     keyID,
			PublicKey: publicKey,
		},
		TrustedKeys: map[string]string{keyID: publicKey},
		UpdatedAt:   time.Unix(0, 0).UTC(),
	}
}

func safeArchiveName(name string) bool {
	if strings.Contains(name, `\`) {
		return false
	}
	clean := path.Clean(name)
	return name != "" && clean == name && !strings.HasPrefix(clean, "../") && !strings.HasPrefix(clean, "/") && clean != ".."
}

func isEvidenceBundleControlFile(name string) bool {
	switch name {
	case evidenceBundleIndexPath, evidencepkg.EvidencePackSealPath:
		return true
	default:
		return false
	}
}
