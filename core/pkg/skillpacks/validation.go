package skillpacks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var skillIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*$`)

type TrustedPublisherKeyring map[string]string

func DefaultTrustedPublisherKeyring() TrustedPublisherKeyring {
	return TrustedPublisherKeyring{
		"Mindburn-Labs": "helm-first-party-keyring-v1",
	}
}

func ValidateManifest(manifest Manifest, skillMD []byte) error {
	if manifest.SchemaVersion != "helm.skillpack.v1" {
		return fmt.Errorf("unsupported SkillPack schema %q", manifest.SchemaVersion)
	}
	if !skillIDPattern.MatchString(manifest.ID) {
		return fmt.Errorf("invalid SkillPack id %q", manifest.ID)
	}
	if strings.TrimSpace(manifest.Name) == "" || strings.TrimSpace(manifest.Version) == "" || strings.TrimSpace(manifest.Description) == "" {
		return errors.New("SkillPack manifest requires name, version, and description")
	}
	if strings.TrimSpace(manifest.Publisher) == "" {
		return errors.New("SkillPack manifest requires publisher")
	}
	if !oneOf(manifest.Status, StatusVerified, StatusExperimental, StatusBlocked, StatusExternal) {
		return fmt.Errorf("invalid SkillPack status %q", manifest.Status)
	}
	if !oneOf(manifest.ScopeDefault, ScopeRepo, ScopeUser, ScopeGlobal) {
		return fmt.Errorf("invalid SkillPack scope_default %q", manifest.ScopeDefault)
	}
	if !oneOf(manifest.Risk, "LOW", "MEDIUM", "HIGH", "CRITICAL") {
		return fmt.Errorf("invalid SkillPack risk %q", manifest.Risk)
	}
	if !manifest.PermissionsDoNotGrantTools {
		return errors.New("SkillPack must declare permissions_do_not_grant_tools=true")
	}
	if manifest.ContentHash != "" && manifest.ContentHash != HashBytes(skillMD) {
		return errors.New("SkillPack content_hash does not match SKILL.md")
	}
	return nil
}

func VerifyPublisherSignature(pack SkillPack, keyring TrustedPublisherKeyring) error {
	if keyring == nil {
		keyring = DefaultTrustedPublisherKeyring()
	}
	if pack.Manifest.Status != StatusVerified {
		if pack.Manifest.SignatureRef == "" {
			return errors.New("SkillPack signature reference is missing")
		}
		return nil
	}
	keyRef, trusted := keyring[pack.Manifest.Publisher]
	if !trusted {
		return fmt.Errorf("verified SkillPack publisher %q is not in trusted keyring", pack.Manifest.Publisher)
	}
	if pack.Manifest.PublisherKeyRef != "" && pack.Manifest.PublisherKeyRef != keyRef {
		return fmt.Errorf("SkillPack publisher key ref %q does not match trusted keyring", pack.Manifest.PublisherKeyRef)
	}
	parts := strings.Split(pack.Manifest.ID, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid SkillPack id %q", pack.Manifest.ID)
	}
	expected := fmt.Sprintf("helm-first-party://skills/%s/%s", parts[1], pack.Manifest.Version)
	if pack.Manifest.SignatureRef != expected {
		return fmt.Errorf("verified SkillPack signature ref %q does not match %q", pack.Manifest.SignatureRef, expected)
	}
	if pack.Manifest.ContentHash == "" || pack.Manifest.ContentHash != HashBytes([]byte(pack.SkillMD)) {
		return errors.New("verified SkillPack content hash must match SKILL.md")
	}
	return nil
}

func ValidatePolicyFile(repoRoot, policyRef string) error {
	policyRef = strings.TrimSpace(policyRef)
	if policyRef == "" {
		return errors.New("SkillPack policy_ref is required")
	}
	if filepath.IsAbs(policyRef) {
		return errors.New("SkillPack policy_ref must be repository relative")
	}
	clean := filepath.Clean(policyRef)
	if strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return errors.New("SkillPack policy_ref escapes repository root")
	}
	path := filepath.Join(repoRoot, clean)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read SkillPack policy: %w", err)
	}
	text := string(data)
	required := []string{
		"[skill]",
		"permission_bypass_forbidden = true",
		"receipts_required = true",
		"global_install_default = \"deny\"",
		"mcp_auto_enable_default = \"quarantine\"",
		"[projection]",
		"[evidence]",
	}
	for _, needle := range required {
		if !strings.Contains(text, needle) {
			return fmt.Errorf("SkillPack policy missing required key %q", needle)
		}
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
