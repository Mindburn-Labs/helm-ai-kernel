package governance

import "fmt"

// ConnectorManifest defines which external systems are allowed for each data class.
type ConnectorManifest struct {
	// AllowedClasses maps a ConnectorID to the maximum allowed DataClass.
	// Actually, inverted is easier: Map DataClass to allowed Connectors?
	// Or Map Connector to AllowedClasses.
	// Let's go with: Map ConnectorID -> MaxAllowedClass (Hierarchy: Public < Internal < Confidential < Restricted)
	ConnectorPolicies map[string]DataClass
}

func NewConnectorManifest() *ConnectorManifest {
	return &ConnectorManifest{
		ConnectorPolicies: map[string]DataClass{
			"slack":   DataClassInternal,     // Can send Internal, but not Confidential
			"email":   DataClassConfidential, // encrypted email ok for confidential
			"logger":  DataClassRestricted,   // Secure logs can take anything (redaction happens elsewhere)
			"public":  DataClassPublic,       // Public web
			"console": DataClassConfidential, // Operator console
		},
	}
}

// CanEgress checks if 'data' of 'class' can be sent to 'connectorID'.
func (m *ConnectorManifest) CanEgress(connectorID string, class DataClass) (bool, error) {
	maxAllowed, ok := m.ConnectorPolicies[connectorID]
	if !ok {
		return false, fmt.Errorf("unknown connector: %s", connectorID)
	}

	// Rank classes
	rank := map[DataClass]int{
		DataClassPublic:       0,
		DataClassInternal:     1,
		DataClassConfidential: 2,
		DataClassRestricted:   3,
	}

	dataRank := rank[class]
	maxRank := rank[maxAllowed]

	if dataRank > maxRank {
		return false, fmt.Errorf("EGRESS DENIED: Data is %s, Connector %s only allows up to %s", class, connectorID, maxAllowed)
	}

	return true, nil
}
