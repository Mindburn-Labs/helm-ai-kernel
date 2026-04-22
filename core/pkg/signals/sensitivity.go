package signals

// SensitivityTag classifies the sensitivity level of a signal's content.
// Used for routing decisions, access control, and encryption requirements.
type SensitivityTag string

const (
	SensitivityPublic       SensitivityTag = "PUBLIC"
	SensitivityInternal     SensitivityTag = "INTERNAL"
	SensitivityConfidential SensitivityTag = "CONFIDENTIAL"
	SensitivityRestricted   SensitivityTag = "RESTRICTED"
)

// IsValid returns true if the sensitivity tag is recognized.
func (s SensitivityTag) IsValid() bool {
	switch s {
	case SensitivityPublic, SensitivityInternal, SensitivityConfidential, SensitivityRestricted:
		return true
	default:
		return false
	}
}

// RequiresEncryption returns true if the sensitivity level requires encryption at rest.
func (s SensitivityTag) RequiresEncryption() bool {
	return s == SensitivityConfidential || s == SensitivityRestricted
}
