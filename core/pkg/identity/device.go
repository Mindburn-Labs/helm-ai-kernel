// Package identity — Device and IoT identity schemas.
//
// Per HELM 2030 Spec §5.1:
//
//	Cross-actor identity spans humans, agents, services, devices, and robots.
//	Device identity enables governance of physical-world actors.
package identity

import (
	"time"
)

// DeviceClass classifies the category of physical device.
type DeviceClass string

const (
	DeviceClassRobot    DeviceClass = "ROBOT"
	DeviceClassSensor   DeviceClass = "SENSOR"
	DeviceClassActuator DeviceClass = "ACTUATOR"
	DeviceClassGateway  DeviceClass = "GATEWAY"
	DeviceClassTerminal DeviceClass = "TERMINAL"
	DeviceClassVehicle  DeviceClass = "VEHICLE"
	DeviceClassFacility DeviceClass = "FACILITY_CONTROLLER"
)

// DeviceTrustLevel indicates the trust tier for governance decisions.
type DeviceTrustLevel string

const (
	DeviceTrustUnverified DeviceTrustLevel = "UNVERIFIED"
	DeviceTrustBasic      DeviceTrustLevel = "BASIC"
	DeviceTrustVerified   DeviceTrustLevel = "VERIFIED"
	DeviceTrustAttested   DeviceTrustLevel = "ATTESTED"
)

// DeviceIdentity is the canonical identity for a physical device or robot.
type DeviceIdentity struct {
	ID               string            `json:"id"`
	TenantID         string            `json:"tenant_id"`
	Name             string            `json:"name"`
	Class            DeviceClass       `json:"class"`
	TrustLevel       DeviceTrustLevel  `json:"trust_level"`
	FirmwareHash     string            `json:"firmware_hash,omitempty"`
	Location         string            `json:"location,omitempty"`
	Capabilities     []string          `json:"capabilities"`
	SafetyInterlocks []SafetyInterlock `json:"safety_interlocks,omitempty"`
	OwnerID          string            `json:"owner_id"`
	RegisteredAt     time.Time         `json:"registered_at"`
	LastSeenAt       *time.Time        `json:"last_seen_at,omitempty"`
	ContentHash      string            `json:"content_hash"`
}

// SafetyInterlock defines a physical safety constraint.
type SafetyInterlock struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "ESTOP", "GEOFENCE", "SPEED_LIMIT", "FORCE_LIMIT"
	Active      bool   `json:"active"`
	Description string `json:"description"`
}
