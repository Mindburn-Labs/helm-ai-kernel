package evidence

// quantum_posture: Trust settings configure the signer, anchor and storage used in classical evidence seals.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

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

// evidencePackTrustConfigCandidates lists the trust sources in precedence
// order: an explicit path, HELM_EVIDENCE_TRUST_CONFIG, then the operator's own
// data-dir config. Nothing is resolved against the working directory: a
// helm/helm.yaml shipped beside a pack would otherwise name its own trusted
// keys and profile (audit 13-01). Project-local configs must be passed with
// --config.
func evidencePackTrustConfigCandidates(configPath, dataDir string) []string {
	if strings.TrimSpace(configPath) != "" {
		return []string{strings.TrimSpace(configPath)}
	}
	var candidates []string
	if env := strings.TrimSpace(os.Getenv("HELM_EVIDENCE_TRUST_CONFIG")); env != "" {
		candidates = append(candidates, env)
	}
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
