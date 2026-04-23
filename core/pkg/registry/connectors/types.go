// Package connectors provides connector release registry types, storage,
// lifecycle management, and verification for the HELM execution firewall.
//
// A ConnectorRelease describes a versioned connector binary that bridges
// skill execution to external systems (digital or analog).
package connectors

// ConnectorExecutorKind distinguishes between digital and analog connectors.
type ConnectorExecutorKind string

const (
	// ExecDigital represents a software-only connector (APIs, databases, etc.).
	ExecDigital ConnectorExecutorKind = "digital"
	// ExecAnalog represents a connector that interfaces with physical systems.
	ExecAnalog ConnectorExecutorKind = "analog"
)

// ConnectorReleaseState represents the lifecycle state of a connector release.
type ConnectorReleaseState string

const (
	// ConnectorCandidate is the initial state after registration.
	ConnectorCandidate ConnectorReleaseState = "candidate"
	// ConnectorCertified indicates the release has passed all verification.
	ConnectorCertified ConnectorReleaseState = "certified"
	// ConnectorRevoked indicates the release has been permanently disabled.
	ConnectorRevoked ConnectorReleaseState = "revoked"
)

// ConnectorRelease is the complete metadata descriptor for a connector binary.
type ConnectorRelease struct {
	ConnectorID      string                `json:"connector_id"`
	Name             string                `json:"name"`
	Version          string                `json:"version"`
	State            ConnectorReleaseState `json:"state"`
	SchemaRefs       []string              `json:"schema_refs"`
	ExecutorKind     ConnectorExecutorKind `json:"executor_kind"`
	SandboxProfile   string                `json:"sandbox_profile"`
	DriftPolicyRef   string                `json:"drift_policy_ref"`
	CertificationRef string                `json:"certification_ref,omitempty"`
	BinaryHash       string                `json:"binary_hash"`
	SignatureRef     string                `json:"signature_ref"`
}
