package manifest

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// ValidationError collects all errors found during manifest validation.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("manifest validation failed with %d errors:\n  - %s",
		len(e.Errors), strings.Join(e.Errors, "\n  - "))
}

// Validate checks an IntegrationManifest for structural correctness.
// It returns nil if the manifest is valid, or a *ValidationError listing all issues.
func Validate(m *IntegrationManifest) error {
	var errs []string
	add := func(msg string) { errs = append(errs, msg) }

	// API version.
	if m.APIVersion != APIVersion {
		add(fmt.Sprintf("api_version must be %q, got %q", APIVersion, m.APIVersion))
	}

	// Provider.
	if m.Provider.ID == "" {
		add("provider.id is required")
	}
	if m.Provider.Name == "" {
		add("provider.name is required")
	}
	if m.Provider.Category == "" {
		add("provider.category is required")
	}

	// Connector.
	if m.Connector.ID == "" {
		add("connector.id is required")
	}
	if m.Connector.Version == "" {
		add("connector.version is required")
	} else if _, err := semver.StrictNewVersion(m.Connector.Version); err != nil {
		add(fmt.Sprintf("connector.version %q is not valid semver: %v", m.Connector.Version, err))
	}
	if m.Connector.Packaging == "" {
		add("connector.packaging is required")
	}

	// Auth.
	if len(m.Auth.Methods) == 0 {
		add("auth.methods must have at least one method")
	}
	for i, method := range m.Auth.Methods {
		if err := validateAuthMethod(i, &method); err != nil {
			add(err.Error())
		}
	}

	// Capabilities.
	if len(m.Caps) == 0 {
		add("capabilities must have at least one entry")
	}
	urnSeen := make(map[string]bool)
	for i, cap := range m.Caps {
		if cap.URN == "" {
			add(fmt.Sprintf("capabilities[%d].urn is required", i))
		} else {
			if !isValidCapabilityURN(cap.URN) {
				add(fmt.Sprintf("capabilities[%d].urn %q is not a valid capability URN (expected cap://<provider>/<action>@<version>)", i, cap.URN))
			}
			if urnSeen[cap.URN] {
				add(fmt.Sprintf("capabilities[%d].urn %q is duplicate", i, cap.URN))
			}
			urnSeen[cap.URN] = true
		}
		if cap.Name == "" {
			add(fmt.Sprintf("capabilities[%d].name is required", i))
		}
		if cap.RiskClass == "" {
			add(fmt.Sprintf("capabilities[%d].risk_class is required", i))
		} else if !isValidRiskClass(cap.RiskClass) {
			add(fmt.Sprintf("capabilities[%d].risk_class %q must be one of E0-E4", i, cap.RiskClass))
		}
	}

	// Runtime.
	if !isValidRuntimeKind(m.Runtime.Kind) {
		add(fmt.Sprintf("runtime.kind %q is not a recognized runtime kind", m.Runtime.Kind))
	}

	if len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	return nil
}

// validateAuthMethod validates a single auth method entry.
func validateAuthMethod(index int, m *AuthMethod) error {
	validTypes := map[string]bool{
		"oauth2": true, "apikey": true, "basic": true,
		"none": true, "mtls": true, "webauthn": true,
	}
	if !validTypes[m.Type] {
		return fmt.Errorf("auth.methods[%d].type %q is not valid (expected oauth2|apikey|basic|none|mtls|webauthn)", index, m.Type)
	}
	if m.Type == "oauth2" && m.OAuthConfig == nil {
		return fmt.Errorf("auth.methods[%d]: oauth2 type requires oauth_config", index)
	}
	if m.Type == "apikey" && m.APIKeyConfig == nil {
		return fmt.Errorf("auth.methods[%d]: apikey type requires apikey_config", index)
	}
	return nil
}

// isValidCapabilityURN checks the cap://<provider>/<action>@<version> format.
func isValidCapabilityURN(urn string) bool {
	if !strings.HasPrefix(urn, "cap://") {
		return false
	}
	body := strings.TrimPrefix(urn, "cap://")
	// Must have provider/action@version
	atIdx := strings.LastIndex(body, "@")
	if atIdx < 0 {
		return false
	}
	path := body[:atIdx]
	version := body[atIdx+1:]
	if version == "" {
		return false
	}
	// Path must have at least provider/action (one slash).
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	return true
}

// isValidRiskClass checks if a risk class is E0-E4.
func isValidRiskClass(rc string) bool {
	switch rc {
	case "E0", "E1", "E2", "E3", "E4":
		return true
	}
	return false
}

// isValidRuntimeKind checks if a runtime kind is recognized.
func isValidRuntimeKind(k RuntimeKind) bool {
	for _, valid := range AllRuntimeKinds() {
		if k == valid {
			return true
		}
	}
	return false
}
