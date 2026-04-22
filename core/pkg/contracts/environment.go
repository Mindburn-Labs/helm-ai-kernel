package contracts

import "time"

// EnvironmentProfile defines the execution context constraints.
type EnvironmentProfile struct {
	ID          string            `json:"id"`
	Fingerprint string            `json:"fingerprint"`
	Vars        map[string]string `json:"vars"`

	// Boot Compatibility
	ProfileID      string         `json:"profile_id"`
	Name           string         `json:"name"`
	JurisdictionID string         `json:"jurisdiction_id"`
	Currency       string         `json:"currency"`
	Rails          []string       `json:"rails"`
	RiskBaseline   map[string]any `json:"risk_baseline"`
}

type EnvSnap struct {
	Timestamp           time.Time         `json:"timestamp"`
	Vars                map[string]string `json:"vars"`
	JurisdictionID      string            `json:"jurisdiction_id"`
	RiskThreshold       float64           `json:"risk_threshold"`
	DataClasses         []string          `json:"data_classes"`
	ActionClasses       []string          `json:"action_classes"`
	AvailableConnectors []string          `json:"available_connectors"`
}
