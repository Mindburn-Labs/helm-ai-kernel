// Package promotionpermit binds an exact production promotion candidate to
// the immutable release and GitOps inputs reviewed by HELM.
package promotionpermit

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const (
	InputSchemaV1 = "helm.production-promotion-input/v1"

	ReleaseManifestStatusProductionCandidate = "production_candidate"
	ReleaseManifestStatusReleased            = "released"
)

const maxJCSSafeInteger = int64(1<<53 - 1)

var (
	sha256ReferencePattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	canonicalTokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
)

// Input is authority-free content. Its JCS digest is carried by the existing
// DEPLOY_PRODUCTION_ACTIVATE promotion_permit_hash field.
type Input struct {
	Schema                    string `json:"schema"`
	TargetEnvironment         string `json:"target_environment"`
	ReleaseManifestRef        string `json:"release_manifest_ref"`
	ReleaseManifestGeneration int64  `json:"release_manifest_generation"`
	ReleaseManifestHash       string `json:"release_manifest_hash"`
	ReleaseManifestStatus     string `json:"release_manifest_status"`
	PlatformOverlayRef        string `json:"platform_overlay_ref"`
	PlatformOverlayHash       string `json:"platform_overlay_hash"`
	AppsOverlayRef            string `json:"apps_overlay_ref"`
	AppsOverlayHash           string `json:"apps_overlay_hash"`
	ProtectedEnvironment      string `json:"protected_environment"`
	AppsEmptyIntent           bool   `json:"apps_empty_intent"`
}

func (input Input) Validate() error {
	if input.Schema != InputSchemaV1 {
		return fmt.Errorf("promotion input schema must equal %q", InputSchemaV1)
	}
	if input.TargetEnvironment != "production" {
		return errors.New("promotion input target_environment must equal production")
	}
	if input.ReleaseManifestGeneration <= 0 || input.ReleaseManifestGeneration > maxJCSSafeInteger {
		return errors.New("promotion input release_manifest_generation must be a positive JCS-safe integer")
	}
	switch input.ReleaseManifestStatus {
	case ReleaseManifestStatusProductionCandidate, ReleaseManifestStatusReleased:
	default:
		return errors.New("promotion input release_manifest_status must be production_candidate or released")
	}
	for field, value := range map[string]string{
		"release_manifest_ref": input.ReleaseManifestRef,
		"platform_overlay_ref": input.PlatformOverlayRef,
		"apps_overlay_ref":     input.AppsOverlayRef,
	} {
		if !canonicalReference(value) {
			return fmt.Errorf("promotion input %s must be a bounded non-empty reference", field)
		}
	}
	for field, value := range map[string]string{
		"release_manifest_hash": input.ReleaseManifestHash,
		"platform_overlay_hash": input.PlatformOverlayHash,
		"apps_overlay_hash":     input.AppsOverlayHash,
	} {
		if !sha256ReferencePattern.MatchString(value) {
			return fmt.Errorf("promotion input %s must be a canonical SHA-256 reference", field)
		}
	}
	if !canonicalTokenPattern.MatchString(input.ProtectedEnvironment) {
		return errors.New("promotion input protected_environment must be a canonical token")
	}
	return nil
}

func (input Input) CanonicalBytes() ([]byte, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}
	return canonicalize.JCS(input)
}

func (input Input) Hash() (string, error) {
	canonical, err := input.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return canonicalize.ComputeArtifactHash(canonical), nil
}

// VerifyArtifactBytes checks the exact bytes named by the promotion input.
// Parsing their YAML/JSON would create a second source of release truth.
func (input Input) VerifyArtifactBytes(releaseManifest, platformOverlay, appsOverlay []byte) error {
	if err := input.Validate(); err != nil {
		return err
	}
	for field, expected := range map[string]string{
		"release manifest": input.ReleaseManifestHash,
		"platform overlay": input.PlatformOverlayHash,
		"apps overlay":     input.AppsOverlayHash,
	} {
		var content []byte
		switch field {
		case "release manifest":
			content = releaseManifest
		case "platform overlay":
			content = platformOverlay
		default:
			content = appsOverlay
		}
		actual := canonicalize.ComputeArtifactHash(content)
		if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
			return fmt.Errorf("promotion input %s bytes do not match the approved hash", field)
		}
	}
	return nil
}

func canonicalReference(value string) bool {
	return value != "" && len(value) <= 1024 && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, unicode.IsSpace) == -1 && strings.IndexFunc(value, unicode.IsControl) == -1
}
