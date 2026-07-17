package contracts

import "fmt"

const (
	ApprovalConnectorAuthoritySchemaV1   = "approval-connector-authority.v1"
	ApprovalConnectorAuthorityContractV1 = "2026-07-17"
	ApprovalConnectorAuthorityStateV1    = "certified"
)

// ApprovalConnectorAuthority is the policy-owned connector release snapshot
// approved for one exact pack lifecycle effect. It is committed before the
// approval hold starts and is carried unchanged through challenge, quorum,
// grant, consumption, and dispatch admission.
//
// This immutable snapshot prevents a dispatch workload from selecting its own
// connector. A near-effect boundary must additionally check the release
// against the current source-owned revocation registry before execution.
type ApprovalConnectorAuthority struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`
	State           string `json:"state"`

	BindingRef  string `json:"binding_ref"`
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`

	PackID           string `json:"pack_id"`
	PackVersion      string `json:"pack_version"`
	PackManifestHash string `json:"pack_manifest_hash"`
	Action           string `json:"action"`
	EffectHash       string `json:"effect_hash"`
	PolicyHash       string `json:"policy_hash"`

	ConnectorID             string `json:"connector_id"`
	ConnectorVersion        string `json:"connector_version"`
	ConnectorExecutorKind   string `json:"connector_executor_kind"`
	ConnectorBinaryHash     string `json:"connector_binary_hash"`
	ConnectorSignatureRef   string `json:"connector_signature_ref"`
	ConnectorSignerID       string `json:"connector_signer_id"`
	ConnectorSandboxProfile string `json:"connector_sandbox_profile"`
	ConnectorDriftPolicyRef string `json:"connector_drift_policy_ref"`

	CertificationRef       string `json:"certification_ref"`
	CertificationHash      string `json:"certification_hash"`
	CertificationAuthority string `json:"certification_authority"`

	AuthorityHash string `json:"authority_hash,omitempty"`
}

func (a ApprovalConnectorAuthority) Validate() error {
	if a.SchemaVersion != ApprovalConnectorAuthoritySchemaV1 {
		return approvalConnectorAuthorityInvalid("unsupported schema_version")
	}
	if a.ContractVersion != ApprovalConnectorAuthorityContractV1 {
		return approvalConnectorAuthorityInvalid("unsupported contract_version")
	}
	if a.State != ApprovalConnectorAuthorityStateV1 {
		return approvalConnectorAuthorityInvalid("state must be certified")
	}
	for field, value := range map[string]string{
		"binding_ref": a.BindingRef, "tenant_id": a.TenantID, "workspace_id": a.WorkspaceID,
		"pack_id": a.PackID, "pack_version": a.PackVersion, "connector_id": a.ConnectorID,
		"connector_version": a.ConnectorVersion, "connector_executor_kind": a.ConnectorExecutorKind,
		"connector_signature_ref": a.ConnectorSignatureRef, "connector_signer_id": a.ConnectorSignerID,
		"connector_sandbox_profile":  a.ConnectorSandboxProfile,
		"connector_drift_policy_ref": a.ConnectorDriftPolicyRef,
		"certification_ref":          a.CertificationRef, "certification_authority": a.CertificationAuthority,
	} {
		if !isApprovalGrantToken(value) || len(value) > 512 {
			return approvalConnectorAuthorityInvalid(field + " is required and must be a bounded token")
		}
	}
	for field, value := range map[string]string{
		"pack_manifest_hash": a.PackManifestHash, "effect_hash": a.EffectHash,
		"policy_hash": a.PolicyHash, "connector_binary_hash": a.ConnectorBinaryHash,
		"certification_hash": a.CertificationHash,
	} {
		if !isApprovalGrantSHA256(value) {
			return approvalConnectorAuthorityInvalid(field + " must be a lowercase sha256 reference")
		}
	}
	switch a.Action {
	case ApprovalGrantActionInstall, ApprovalGrantActionUpgrade,
		ApprovalGrantActionUninstall, ApprovalGrantActionRollback:
	default:
		return approvalConnectorAuthorityInvalid("unsupported action")
	}
	switch a.ConnectorExecutorKind {
	case "digital", "analog":
	default:
		return approvalConnectorAuthorityInvalid("connector_executor_kind must be digital or analog")
	}
	if a.AuthorityHash != "" && !isApprovalGrantSHA256(a.AuthorityHash) {
		return approvalConnectorAuthorityInvalid("authority_hash must be a lowercase sha256 reference")
	}
	return nil
}

func (a ApprovalConnectorAuthority) Seal() (ApprovalConnectorAuthority, error) {
	if err := a.Validate(); err != nil {
		return ApprovalConnectorAuthority{}, err
	}
	a.AuthorityHash = ""
	hash, err := hashJCS(a)
	if err != nil {
		return ApprovalConnectorAuthority{}, fmt.Errorf("%w: connector authority seal: %v", ErrApprovalGrantIntegrity, err)
	}
	a.AuthorityHash = hash
	return a, nil
}

func (a ApprovalConnectorAuthority) ValidateIntegrity() error {
	if err := a.Validate(); err != nil {
		return err
	}
	if a.AuthorityHash == "" {
		return approvalConnectorAuthorityInvalid("authority_hash is required")
	}
	sealed, err := a.Seal()
	if err != nil || sealed.AuthorityHash != a.AuthorityHash {
		return approvalConnectorAuthorityInvalid("authority integrity mismatch")
	}
	return nil
}

// ValidateEffectBinding proves that the connector snapshot belongs to the
// exact effect context carried by its enclosing approval artifact.
func (a ApprovalConnectorAuthority) ValidateEffectBinding(
	tenantID, workspaceID, packID, packVersion, packManifestHash, action, effectHash, policyHash string,
) error {
	if err := a.ValidateIntegrity(); err != nil {
		return err
	}
	if a.TenantID != tenantID || a.WorkspaceID != workspaceID ||
		a.PackID != packID || a.PackVersion != packVersion || a.PackManifestHash != packManifestHash ||
		a.Action != action || a.EffectHash != effectHash || a.PolicyHash != policyHash {
		return approvalConnectorAuthorityInvalid("effect binding mismatch")
	}
	return nil
}

func approvalConnectorAuthorityInvalid(message string) error {
	return fmt.Errorf("%w: connector authority: %s", ErrApprovalGrantIntegrity, message)
}
