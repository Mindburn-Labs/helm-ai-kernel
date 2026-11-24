package evidence

// quantum_posture: Local and KMS evidence signers produce classical Ed25519 signatures.

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
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

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

func isLocalEvidenceSignerType(signerType string) bool {
	switch strings.ToLower(strings.TrimSpace(signerType)) {
	case "file-dev", "local-dev":
		return true
	default:
		return false
	}
}

func fileDevKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "file-dev:" + hex.EncodeToString(sum[:])[:16]
}
