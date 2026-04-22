package signals

// SignalTypeCatalogEntry describes a registered signal type with its
// classification and default sensitivity.
type SignalTypeCatalogEntry struct {
	// Class is the signal class this entry describes.
	Class SignalClass `json:"class"`

	// Name is a human-readable name.
	Name string `json:"name"`

	// Description explains what this signal type represents.
	Description string `json:"description"`

	// DefaultSensitivity is the default sensitivity if not specified by the connector.
	DefaultSensitivity SensitivityTag `json:"default_sensitivity"`

	// SupportsThreading indicates whether signals of this class can have thread references.
	SupportsThreading bool `json:"supports_threading"`

	// SupportsArtifacts indicates whether signals of this class can have artifact attachments.
	SupportsArtifacts bool `json:"supports_artifacts"`
}

// DefaultSignalCatalog returns the canonical catalog of recognized signal types.
func DefaultSignalCatalog() []SignalTypeCatalogEntry {
	return []SignalTypeCatalogEntry{
		{
			Class:              SignalClassEmail,
			Name:               "Email",
			Description:        "Inbound or outbound email message from a connected mailbox.",
			DefaultSensitivity: SensitivityInternal,
			SupportsThreading:  true,
			SupportsArtifacts:  true,
		},
		{
			Class:              SignalClassChat,
			Name:               "Chat Message",
			Description:        "Message from a connected chat platform (Slack, Teams, etc.).",
			DefaultSensitivity: SensitivityInternal,
			SupportsThreading:  true,
			SupportsArtifacts:  true,
		},
		{
			Class:              SignalClassDoc,
			Name:               "Document Update",
			Description:        "Creation or modification of a document in a connected document store.",
			DefaultSensitivity: SensitivityInternal,
			SupportsThreading:  false,
			SupportsArtifacts:  true,
		},
		{
			Class:              SignalClassMeeting,
			Name:               "Meeting",
			Description:        "Meeting event or transcript from a connected calendar or meeting platform.",
			DefaultSensitivity: SensitivityConfidential,
			SupportsThreading:  false,
			SupportsArtifacts:  true,
		},
		{
			Class:              SignalClassTicket,
			Name:               "Ticket",
			Description:        "Issue or ticket update from a connected project management tool.",
			DefaultSensitivity: SensitivityInternal,
			SupportsThreading:  true,
			SupportsArtifacts:  true,
		},
		{
			Class:              SignalClassCRM,
			Name:               "CRM Update",
			Description:        "Customer relationship update from a connected CRM system.",
			DefaultSensitivity: SensitivityConfidential,
			SupportsThreading:  false,
			SupportsArtifacts:  false,
		},
		{
			Class:              SignalClassApproval,
			Name:               "Approval",
			Description:        "Approval request or decision from an internal governance system.",
			DefaultSensitivity: SensitivityInternal,
			SupportsThreading:  false,
			SupportsArtifacts:  false,
		},
		{
			Class:              SignalClassSystemAlert,
			Name:               "System Alert",
			Description:        "Automated alert from a monitoring or observability system.",
			DefaultSensitivity: SensitivityInternal,
			SupportsThreading:  false,
			SupportsArtifacts:  false,
		},
	}
}

// LookupSignalType returns the catalog entry for a given signal class, or nil if not found.
func LookupSignalType(class SignalClass) *SignalTypeCatalogEntry {
	catalog := DefaultSignalCatalog()
	for i := range catalog {
		if catalog[i].Class == class {
			return &catalog[i]
		}
	}
	return nil
}
