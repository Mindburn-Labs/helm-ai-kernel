package install

import (
	"fmt"
	"strings"
)

type ArtifactRequest struct {
	AppID          string
	Strategy       string
	ArtifactSource string
	Digest         string
	SignatureRef   string
	Sandboxed      bool
}

func ValidateArtifactRequest(req ArtifactRequest) error {
	if req.AppID == "" {
		return fmt.Errorf("app id is required")
	}
	if req.Digest == "" {
		return fmt.Errorf("digest is required")
	}
	if !strings.HasPrefix(req.Digest, "sha256:") {
		return fmt.Errorf("digest must use sha256:<hex> format")
	}
	if containsHostInstaller(req.ArtifactSource) {
		return fmt.Errorf("host curl-pipe-shell installers are forbidden")
	}
	switch req.Strategy {
	case "signed_oci", "signed_tarball", "signed_release_artifact":
		if req.SignatureRef == "" {
			return fmt.Errorf("%s requires signature reference", req.Strategy)
		}
	case "pinned_source":
		if req.ArtifactSource == "" {
			return fmt.Errorf("pinned_source requires source")
		}
	case "sandboxed_upstream_installer":
		if !req.Sandboxed {
			return fmt.Errorf("upstream installers are only allowed inside sandbox")
		}
	case "byo_tool":
		return fmt.Errorf("byo_tool cannot be installed by Launchpad")
	default:
		return fmt.Errorf("unknown install strategy %q", req.Strategy)
	}
	return nil
}

func containsHostInstaller(value string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(value, " ", ""))
	return strings.Contains(normalized, "curl|bash") ||
		strings.Contains(normalized, "curl|sh") ||
		strings.Contains(normalized, "curl") && (strings.Contains(normalized, "|bash") || strings.Contains(normalized, "|sh")) ||
		strings.Contains(normalized, "irm") && strings.Contains(normalized, "|iex")
}
