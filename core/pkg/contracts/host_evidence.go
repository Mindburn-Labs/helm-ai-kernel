package contracts

import "time"

const (
	ExternalHostReceiptVersion      = "external_host_receipt.v1"
	ExternalReceiptChainVersion     = "external_receipt_chain.v1"
	HostCorrelationResultVersion    = "host_correlation_result.v1"
	BoundaryDriftReceiptVersion     = "boundary_drift_receipt.v1"
	ReceiptTypeNetworkEgressAttempt = "NETWORK_EGRESS_ATTEMPT"
	ReceiptTypeNetworkEgressAllowed = "NETWORK_EGRESS_ALLOWED"
	ReceiptTypeNetworkEgressDenied  = "NETWORK_EGRESS_DENIED"
	ReceiptTypeNetworkEgressUncorr  = "NETWORK_EGRESS_UNCORRELATED"
	ReceiptTypeBoundaryDrift        = "BOUNDARY_DRIFT"

	EventKindNetworkEgress = "network_egress"
	EventKindActionEffect  = "action_effect"

	HostCorrelationCorrelated             = "CORRELATED"
	HostCorrelationPartiallyCorrelated    = "PARTIALLY_CORRELATED"
	HostCorrelationUncorrelatedHostEgress = "UNCORRELATED_HOST_EGRESS"
	HostCorrelationMissingHostReceipt     = "MISSING_HOST_RECEIPT"
	HostCorrelationMissingHELMIntent      = "MISSING_HELM_INTENT"
	HostCorrelationPolicyAllowedHostBlock = "POLICY_ALLOWED_BUT_HOST_BLOCKED"
	HostCorrelationPolicyDeniedHostEgress = "POLICY_DENIED_BUT_HOST_OBSERVED_EGRESS"
)

// ExternalReceiptChain is the vendor-neutral envelope for host/network
// evidence imported into HELM EvidencePacks.
type ExternalReceiptChain struct {
	SchemaVersion     string                `json:"schema_version,omitempty"`
	ChainID           string                `json:"chain_id,omitempty"`
	SourceVendor      string                `json:"source_vendor,omitempty"`
	SourceProfile     string                `json:"source_profile,omitempty"`
	EventSchemaHash   string                `json:"event_schema_hash,omitempty"`
	ReceiptChainHash  string                `json:"receipt_chain_hash,omitempty"`
	VerificationHint  string                `json:"verification_hint,omitempty"`
	VerificationCmd   string                `json:"verification_command,omitempty"`
	CreatedAt         time.Time             `json:"created_at,omitempty"`
	PublicKeys        []ExternalVerifierKey `json:"public_keys,omitempty"`
	Receipts          []ExternalHostReceipt `json:"receipts"`
	VerificationNotes []string              `json:"verification_notes,omitempty"`
}

// ExternalVerifierKey carries local public-key material. Verifiers never fetch
// public keys over the network while checking an EvidencePack.
type ExternalVerifierKey struct {
	KeyID        string `json:"key_id"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"public_key_hex"`
}

// ExternalHostReceipt records one host-observed event, typically a network
// egress attempt recorded below the application layer by an external recorder.
type ExternalHostReceipt struct {
	SchemaVersion      string             `json:"schema_version,omitempty"`
	ReceiptID          string             `json:"receipt_id"`
	SourceVendor       string             `json:"source_vendor,omitempty"`
	SourceProfile      string             `json:"source_profile,omitempty"`
	HostID             string             `json:"host_id"`
	ProcessIdentity    string             `json:"process_identity,omitempty"`
	ProcessAncestry    []string           `json:"process_ancestry,omitempty"`
	AgentID            string             `json:"agent_id,omitempty"`
	WorkloadID         string             `json:"workload_id,omitempty"`
	SandboxLeaseID     string             `json:"sandbox_lease_id,omitempty"`
	Event              NetworkEgressEvent `json:"event"`
	EventKind          string             `json:"event_kind,omitempty"`
	ActionEvent        *ActionEffectEvent `json:"action_event,omitempty"`
	ReceiptHash        string             `json:"receipt_hash"`
	PrevReceiptHash    string             `json:"prev_receipt_hash,omitempty"`
	SigningKeyID       string             `json:"signing_key_id,omitempty"`
	SignatureAlgorithm string             `json:"signature_algorithm,omitempty"`
	Signature          string             `json:"signature,omitempty"`
	PublicKeyRef       string             `json:"public_key_ref,omitempty"`
	HardwareRoot       *HardwareRootClaim `json:"hardware_root,omitempty"`
	VerifierProfile    string             `json:"verifier_profile,omitempty"`
	RecordedAt         time.Time          `json:"recorded_at,omitempty"`
	Metadata           map[string]string  `json:"metadata,omitempty"`
}

// NetworkEgressEvent is the canonical host-observed outbound network event.
type NetworkEgressEvent struct {
	EventID          string            `json:"event_id,omitempty"`
	AttemptID        string            `json:"attempt_id,omitempty"`
	ActionID         string            `json:"action_id,omitempty"`
	Direction        string            `json:"direction,omitempty"`
	SourceIP         string            `json:"source_ip,omitempty"`
	DestinationIP    string            `json:"destination_ip"`
	DestinationHost  string            `json:"destination_host,omitempty"`
	DestinationPort  int               `json:"destination_port"`
	Protocol         string            `json:"protocol"`
	Timestamp        time.Time         `json:"timestamp"`
	BytesSent        int64             `json:"bytes_sent,omitempty"`
	BytesReceived    int64             `json:"bytes_received,omitempty"`
	Verdict          string            `json:"verdict,omitempty"`
	ObservedBy       string            `json:"observed_by,omitempty"`
	CorrelationHints map[string]string `json:"correlation_hints,omitempty"`
}

// ActionEffectEvent is a host/mediator-observed agent tool/action effect — the
// vendor-neutral analogue of a competitor "action receipt" (Signet, AGT, Pipelock/AAR).
// Used when ExternalHostReceipt.EventKind == "action_effect".
type ActionEffectEvent struct {
	ActionID        string    `json:"action_id"`
	ToolName        string    `json:"tool_name"`
	TargetRef       string    `json:"target_ref,omitempty"`
	Transport       string    `json:"transport,omitempty"`
	ParamsHash      string    `json:"params_hash,omitempty"`
	OutputHash      string    `json:"output_hash,omitempty"`
	ResultCount     int64     `json:"result_count,omitempty"`
	SideEffectClass string    `json:"side_effect_class,omitempty"`
	Reversibility   string    `json:"reversibility,omitempty"`
	Decision        string    `json:"decision,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

// HardwareRootClaim is structural evidence only unless a local verifier checks
// quote_blob_b64 for the claimed hardware_root_type.
type HardwareRootClaim struct {
	KernelMeasurementSHA256 string    `json:"kernel_measurement_sha256,omitempty"`
	ExecutionProfile        string    `json:"execution_profile,omitempty"`
	HardwareRootType        string    `json:"hardware_root_type,omitempty"`
	QuoteFormat             string    `json:"quote_format,omitempty"`
	QuoteBlobB64            string    `json:"quote_blob_b64,omitempty"`
	QuoteVerifier           string    `json:"quote_verifier,omitempty"`
	SigningKeyNonExportable *bool     `json:"signing_key_nonexportable,omitempty"`
	MeasurementTime         time.Time `json:"measurement_time,omitempty"`
	BootSequenceRef         string    `json:"boot_sequence_ref,omitempty"`
	VerificationStatus      string    `json:"verification_status,omitempty"`
}

// HostCorrelationResult links HELM authority receipts to host-observed egress.
type HostCorrelationResult struct {
	SchemaVersion     string                `json:"schema_version,omitempty"`
	Status            string                `json:"status"`
	ReasonCode        string                `json:"reason_code,omitempty"`
	Confidence        float64               `json:"confidence,omitempty"`
	HELMReceiptID     string                `json:"helm_receipt_id,omitempty"`
	HELMDecisionID    string                `json:"helm_decision_id,omitempty"`
	HELMSandboxLease  string                `json:"helm_sandbox_lease_id,omitempty"`
	HostReceiptID     string                `json:"host_receipt_id,omitempty"`
	HostReceiptHash   string                `json:"host_receipt_hash,omitempty"`
	ObservedEvent     *NetworkEgressEvent   `json:"observed_event,omitempty"`
	BoundaryDrift     *BoundaryDriftReceipt `json:"boundary_drift,omitempty"`
	CorrelationMethod string                `json:"correlation_method,omitempty"`
	Details           string                `json:"details,omitempty"`
	CorrelatedAt      time.Time             `json:"correlated_at,omitempty"`
}

// BoundaryDriftReceipt records a mismatch between HELM authority and observed
// host behavior.
type BoundaryDriftReceipt struct {
	ReceiptVersion  string    `json:"receipt_version"`
	ReceiptID       string    `json:"receipt_id"`
	Type            string    `json:"type"`
	ReasonCode      string    `json:"reason_code"`
	Severity        string    `json:"severity,omitempty"`
	HostReceiptID   string    `json:"host_receipt_id,omitempty"`
	HostReceiptHash string    `json:"host_receipt_hash,omitempty"`
	HELMReceiptID   string    `json:"helm_receipt_id,omitempty"`
	HELMDecisionID  string    `json:"helm_decision_id,omitempty"`
	PolicyHash      string    `json:"policy_hash,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	ReceiptHash     string    `json:"receipt_hash"`
	Signature       string    `json:"signature,omitempty"`
	SignerKeyID     string    `json:"signer_key_id,omitempty"`
}
