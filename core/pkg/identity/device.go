// Package identity — Device and IoT identity schemas.
//
// Per HELM 2030 Spec §5.1:
//
//	Cross-actor identity spans humans, agents, services, devices, and robots.
//	Device identity enables governance of physical-world actors.
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// DeviceClass classifies the category of physical device.
type DeviceClass string

const (
	DeviceClassRobot     DeviceClass = "ROBOT"
	DeviceClassSensor    DeviceClass = "SENSOR"
	DeviceClassActuator  DeviceClass = "ACTUATOR"
	DeviceClassGateway   DeviceClass = "GATEWAY"
	DeviceClassTerminal  DeviceClass = "TERMINAL"
	DeviceClassVehicle   DeviceClass = "VEHICLE"
	DeviceClassFacility  DeviceClass = "FACILITY_CONTROLLER"
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
	ID             string           `json:"id"`
	TenantID       string           `json:"tenant_id"`
	Name           string           `json:"name"`
	Class          DeviceClass      `json:"class"`
	TrustLevel     DeviceTrustLevel `json:"trust_level"`
	FirmwareHash   string           `json:"firmware_hash,omitempty"`
	Location       string           `json:"location,omitempty"`
	Capabilities   []string         `json:"capabilities"`
	SafetyInterlocks []SafetyInterlock `json:"safety_interlocks,omitempty"`
	OwnerID        string           `json:"owner_id"`
	RegisteredAt   time.Time        `json:"registered_at"`
	LastSeenAt     *time.Time       `json:"last_seen_at,omitempty"`
	ContentHash    string           `json:"content_hash"`
}

// SafetyInterlock defines a physical safety constraint.
type SafetyInterlock struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "ESTOP", "GEOFENCE", "SPEED_LIMIT", "FORCE_LIMIT"
	Active      bool   `json:"active"`
	Description string `json:"description"`
}

// NewDeviceIdentity creates a device identity.
func NewDeviceIdentity(id, tenantID, name string, class DeviceClass, ownerID string, capabilities []string) *DeviceIdentity {
	d := &DeviceIdentity{
		ID:           id,
		TenantID:     tenantID,
		Name:         name,
		Class:        class,
		TrustLevel:   DeviceTrustUnverified,
		OwnerID:      ownerID,
		Capabilities: capabilities,
		RegisteredAt: time.Now().UTC(),
	}
	d.ContentHash = d.computeHash()
	return d
}

// Attest raises trust level after verification.
func (d *DeviceIdentity) Attest(firmwareHash string) {
	d.FirmwareHash = firmwareHash
	d.TrustLevel = DeviceTrustAttested
	d.ContentHash = d.computeHash()
}

// Validate ensures the device identity is well-formed.
func (d *DeviceIdentity) Validate() error {
	if d.ID == "" {
		return errors.New("device: id is required")
	}
	if d.TenantID == "" {
		return errors.New("device: tenant_id is required")
	}
	if d.Class == "" {
		return errors.New("device: class is required")
	}
	if d.OwnerID == "" {
		return errors.New("device: owner_id is required")
	}
	return nil
}

func (d *DeviceIdentity) computeHash() string {
	canon, _ := json.Marshal(struct {
		ID       string      `json:"id"`
		TenantID string      `json:"tenant_id"`
		Class    DeviceClass `json:"class"`
		Trust    DeviceTrustLevel `json:"trust"`
		FW       string      `json:"fw_hash"`
	}{d.ID, d.TenantID, d.Class, d.TrustLevel, d.FirmwareHash})
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}
