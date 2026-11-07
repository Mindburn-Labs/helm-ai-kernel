package governance

// ConnectorManifest defines which external systems are allowed for each data class.
type ConnectorManifest struct {
	// AllowedClasses maps a ConnectorID to the maximum allowed DataClass.
	ConnectorPolicies map[string]DataClass
}
