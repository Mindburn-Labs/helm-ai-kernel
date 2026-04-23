package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// RegionalProfile represents a jurisdiction-specific configuration profile.
type RegionalProfile struct {
	Name           string             `yaml:"name" json:"name"`
	Code           string             `yaml:"code" json:"code"`
	Ceremony       CeremonyConfig     `yaml:"ceremony" json:"ceremony"`
	DataResidency  string             `yaml:"data_residency" json:"data_residency"`
	Compliance     []string           `yaml:"compliance" json:"compliance"`
	Encryption     string             `yaml:"encryption" json:"encryption"`
	PIIHandling    string             `yaml:"pii_handling,omitempty" json:"pii_handling,omitempty"`
	RightToErasure bool               `yaml:"right_to_erasure,omitempty" json:"right_to_erasure,omitempty"`
	Networking     NetworkingConfig   `yaml:"networking" json:"networking"`
	CryptoPolicy   CryptoPolicyConfig `yaml:"crypto_policy" json:"crypto_policy"`
	Retention      RetentionConfig    `yaml:"retention" json:"retention"`
}

// CeremonyConfig holds ceremony/escalation thresholds per region.
type CeremonyConfig struct {
	MinTimelockMs    int    `yaml:"min_timelock_ms" json:"min_timelock_ms"`
	MinHoldMs        int    `yaml:"min_hold_ms" json:"min_hold_ms"`
	RequireChallenge bool   `yaml:"require_challenge" json:"require_challenge"`
	DomainSeparation string `yaml:"domain_separation" json:"domain_separation"`
}

// NetworkingConfig controls outbound networking policy.
type NetworkingConfig struct {
	OutboundMode string   `yaml:"outbound_mode" json:"outbound_mode"` // "allowlist" | "denylist" | "island"
	Allowlist    []string `yaml:"allowlist,omitempty" json:"allowlist,omitempty"`
	Denylist     []string `yaml:"denylist,omitempty" json:"denylist,omitempty"`
	IslandMode   bool     `yaml:"island_mode" json:"island_mode"` // if true, block all outbound
}

// CryptoPolicyConfig defines allowed cryptographic algorithms and rotation.
type CryptoPolicyConfig struct {
	AllowedAlgorithms     []string `yaml:"allowed_algorithms" json:"allowed_algorithms"`
	KeyRotationDays       int      `yaml:"key_rotation_days" json:"key_rotation_days"`
	RequireHSM            bool     `yaml:"require_hsm,omitempty" json:"require_hsm,omitempty"`
	RequireNationalCrypto bool     `yaml:"require_national_crypto,omitempty" json:"require_national_crypto,omitempty"`
}

// RetentionConfig defines data retention policies.
type RetentionConfig struct {
	MaxDays          int  `yaml:"max_days" json:"max_days"`
	AuditLogDays     int  `yaml:"audit_log_days" json:"audit_log_days"`
	PIIRetentionDays int  `yaml:"pii_retention_days,omitempty" json:"pii_retention_days,omitempty"`
	RightToErasure   bool `yaml:"right_to_erasure,omitempty" json:"right_to_erasure,omitempty"`
}

// LoadProfile loads a regional profile YAML by jurisdiction code.
// It searches the profiles directory for profile_<code>.yaml.
func LoadProfile(profilesDir, code string) (*RegionalProfile, error) {
	code = strings.ToLower(code)
	path := filepath.Join(profilesDir, fmt.Sprintf("profile_%s.yaml", code))

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load profile %q: %w", code, err)
	}

	var profile RegionalProfile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("parse profile %q: %w", code, err)
	}

	if profile.Code == "" {
		profile.Code = code
	}

	return &profile, nil
}

// LoadAllProfiles loads all profile_*.yaml files from the profiles directory.
func LoadAllProfiles(profilesDir string) (map[string]*RegionalProfile, error) {
	matches, err := filepath.Glob(filepath.Join(profilesDir, "profile_*.yaml"))
	if err != nil {
		return nil, err
	}

	profiles := make(map[string]*RegionalProfile, len(matches))
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		var profile RegionalProfile
		if err := yaml.Unmarshal(data, &profile); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}

		if profile.Code == "" {
			// Extract code from filename: profile_us.yaml -> us
			base := filepath.Base(path)
			profile.Code = strings.TrimSuffix(strings.TrimPrefix(base, "profile_"), ".yaml")
		}

		profiles[profile.Code] = &profile
	}

	return profiles, nil
}

// IsIslandMode returns true if the profile blocks all outbound networking.
func (p *RegionalProfile) IsIslandMode() bool {
	return p.Networking.IslandMode || p.Networking.OutboundMode == "island"
}

// IsAllowed checks if a hostname is allowed by the networking policy.
func (p *RegionalProfile) IsAllowed(hostname string) bool {
	if p.IsIslandMode() {
		return false
	}

	switch p.Networking.OutboundMode {
	case "allowlist":
		for _, h := range p.Networking.Allowlist {
			if h == hostname {
				return true
			}
		}
		return false
	case "denylist":
		for _, h := range p.Networking.Denylist {
			if h == hostname {
				return false
			}
		}
		return true
	default:
		return true
	}
}
