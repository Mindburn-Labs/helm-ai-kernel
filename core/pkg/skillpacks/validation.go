package skillpacks

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var skillIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*$`)

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

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
