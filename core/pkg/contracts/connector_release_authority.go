// quantum_posture: connector release authority is signed and verified with
// classical Ed25519; this contract makes no hybrid or post-quantum claim.
package contracts

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	ConnectorReleaseAuthoritySchemaV1       = "connector-release-authority.v1"
	ConnectorReleaseAuthorityContractV1     = "2026-07-17"
	ConnectorReleaseAuthorityAlgorithmV1    = "ed25519"
	ConnectorReleaseAuthorityScopeGlobal    = "global"
	ConnectorReleaseAuthorityScopeWorkspace = "tenant_workspace"
	ConnectorReleaseAuthorityStateCertified = "certified"
	ConnectorReleaseAuthorityStateRevoked   = "revoked"
	ConnectorReleaseAuthorityMaxRevision    = uint64(1<<53 - 1)
)

var (
	ErrConnectorReleaseAuthorityInvalid  = errors.New("connector release authority invalid")
	ErrConnectorReleaseAuthorityInactive = errors.New("connector release authority inactive")
)

// ConnectorReleaseAuthority is one immutable, source-owned statement about an
// exact connector release. Revisions are append-only per scoped
// connector/version identity; a later signed revision, especially a terminal
// revocation, makes an older certified statement historical rather than
// current authority.
type ConnectorReleaseAuthority struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`

	AuthorityID      string `json:"authority_id"`
	SigningKeyRef    string `json:"signing_key_ref"`
	Algorithm        string `json:"algorithm"`
	RegistryRevision uint64 `json:"registry_revision"`

	ScopeKind   string `json:"scope_kind"`
	TenantID    string `json:"tenant_id,omitempty"`
	WorkspaceID string `json:"workspace_id,omitempty"`

	ConnectorID      string `json:"connector_id"`
	ConnectorVersion string `json:"connector_version"`
	State            string `json:"state"`

	ConnectorExecutorKind   string `json:"connector_executor_kind"`
	ConnectorSandboxProfile string `json:"connector_sandbox_profile"`
	ConnectorDriftPolicyRef string `json:"connector_drift_policy_ref"`

	ConnectorBinaryHash    string `json:"connector_binary_hash"`
	ConnectorSignatureRef  string `json:"connector_signature_ref"`
	ConnectorSignatureHash string `json:"connector_signature_hash"`
	ConnectorSignerID      string `json:"connector_signer_id"`

	CertificationRef       string `json:"certification_ref"`
	CertificationHash      string `json:"certification_hash"`
	CertificationAuthority string `json:"certification_authority"`

	SignedAt   time.Time  `json:"signed_at"`
	ValidFrom  time.Time  `json:"valid_from"`
	ValidUntil *time.Time `json:"valid_until,omitempty"`

	PreviousAuthorityHash string `json:"previous_authority_hash,omitempty"`
	RevokesAuthorityHash  string `json:"revokes_authority_hash,omitempty"`
	AuthorityHash         string `json:"authority_hash,omitempty"`
}

// ConnectorReleaseAuthorityEnvelope carries the detached source-authority
// signature. The signed payload is domain separated and binds AuthorityHash,
// authority identity, key reference, revision, and algorithm.
type ConnectorReleaseAuthorityEnvelope struct {
	Authority ConnectorReleaseAuthority `json:"authority"`
	Signature string                    `json:"signature"`
}

func (a ConnectorReleaseAuthority) Validate() error {
	if a.SchemaVersion != ConnectorReleaseAuthoritySchemaV1 {
		return connectorReleaseAuthorityInvalid("unsupported schema_version")
	}
	if a.ContractVersion != ConnectorReleaseAuthorityContractV1 {
		return connectorReleaseAuthorityInvalid("unsupported contract_version")
	}
	if a.Algorithm != ConnectorReleaseAuthorityAlgorithmV1 {
		return connectorReleaseAuthorityInvalid("unsupported algorithm")
	}
	if a.RegistryRevision == 0 || a.RegistryRevision > ConnectorReleaseAuthorityMaxRevision {
		return connectorReleaseAuthorityInvalid("registry_revision must be a positive JCS-safe integer")
	}
	for field, value := range map[string]string{
		"authority_id": a.AuthorityID, "signing_key_ref": a.SigningKeyRef,
		"connector_id": a.ConnectorID, "connector_version": a.ConnectorVersion,
		"connector_sandbox_profile":  a.ConnectorSandboxProfile,
		"connector_drift_policy_ref": a.ConnectorDriftPolicyRef,
		"connector_signature_ref":    a.ConnectorSignatureRef,
		"connector_signer_id":        a.ConnectorSignerID,
		"certification_ref":          a.CertificationRef,
		"certification_authority":    a.CertificationAuthority,
	} {
		if !isApprovalGrantToken(value) || len(value) > 512 {
			return connectorReleaseAuthorityInvalid(field + " is required and must be a bounded token")
		}
	}
	switch a.ScopeKind {
	case ConnectorReleaseAuthorityScopeGlobal:
		if a.TenantID != "" || a.WorkspaceID != "" {
			return connectorReleaseAuthorityInvalid("global scope must not carry tenant or workspace")
		}
	case ConnectorReleaseAuthorityScopeWorkspace:
		if !isApprovalGrantToken(a.TenantID) || !isApprovalGrantToken(a.WorkspaceID) ||
			len(a.TenantID) > 512 || len(a.WorkspaceID) > 512 {
			return connectorReleaseAuthorityInvalid("tenant_workspace scope requires bounded tenant and workspace")
		}
	default:
		return connectorReleaseAuthorityInvalid("unsupported scope_kind")
	}
	switch a.State {
	case ConnectorReleaseAuthorityStateCertified, ConnectorReleaseAuthorityStateRevoked:
	default:
		return connectorReleaseAuthorityInvalid("unsupported state")
	}
	switch a.ConnectorExecutorKind {
	case "digital", "analog":
	default:
		return connectorReleaseAuthorityInvalid("connector_executor_kind must be digital or analog")
	}
	for field, value := range map[string]string{
		"connector_binary_hash":    a.ConnectorBinaryHash,
		"connector_signature_hash": a.ConnectorSignatureHash,
		"certification_hash":       a.CertificationHash,
	} {
		if !isApprovalGrantSHA256(value) {
			return connectorReleaseAuthorityInvalid(field + " must be a lowercase sha256 reference")
		}
	}
	if a.SignedAt.IsZero() || a.ValidFrom.IsZero() || !isApprovalGrantUTC(a.SignedAt) || !isApprovalGrantUTC(a.ValidFrom) {
		return connectorReleaseAuthorityInvalid("signed_at and valid_from must use UTC")
	}
	if !a.SignedAt.Equal(a.SignedAt.Truncate(time.Microsecond)) || !a.ValidFrom.Equal(a.ValidFrom.Truncate(time.Microsecond)) {
		return connectorReleaseAuthorityInvalid("signed_at and valid_from must use microsecond precision")
	}
	if a.SignedAt.After(a.ValidFrom) {
		return connectorReleaseAuthorityInvalid("signed_at must not be after valid_from")
	}
	if a.RegistryRevision == 1 {
		if a.PreviousAuthorityHash != "" {
			return connectorReleaseAuthorityInvalid("initial revision must not carry previous_authority_hash")
		}
	} else if !isApprovalGrantSHA256(a.PreviousAuthorityHash) {
		return connectorReleaseAuthorityInvalid("later revision requires previous_authority_hash")
	}
	if a.State == ConnectorReleaseAuthorityStateCertified {
		if a.ValidUntil == nil || !isApprovalGrantUTC(*a.ValidUntil) || !a.ValidUntil.After(a.ValidFrom) {
			return connectorReleaseAuthorityInvalid("certified authority requires a later UTC valid_until")
		}
		if !a.ValidUntil.Equal(a.ValidUntil.Truncate(time.Microsecond)) {
			return connectorReleaseAuthorityInvalid("valid_until must use microsecond precision")
		}
		if a.RevokesAuthorityHash != "" {
			return connectorReleaseAuthorityInvalid("certified authority must not revoke another authority")
		}
	} else {
		if a.RegistryRevision < 2 || !isApprovalGrantSHA256(a.RevokesAuthorityHash) ||
			a.RevokesAuthorityHash != a.PreviousAuthorityHash {
			return connectorReleaseAuthorityInvalid("revocation must target the immediate previous authority hash")
		}
		if a.ValidUntil != nil {
			return connectorReleaseAuthorityInvalid("terminal revocation must not expire")
		}
	}
	if a.AuthorityHash != "" && !isApprovalGrantSHA256(a.AuthorityHash) {
		return connectorReleaseAuthorityInvalid("authority_hash must be a lowercase sha256 reference")
	}
	return nil
}

func (a ConnectorReleaseAuthority) Seal() (ConnectorReleaseAuthority, error) {
	if err := a.Validate(); err != nil {
		return ConnectorReleaseAuthority{}, err
	}
	a.AuthorityHash = ""
	hash, err := hashJCS(a)
	if err != nil {
		return ConnectorReleaseAuthority{}, connectorReleaseAuthorityInvalid("seal: " + err.Error())
	}
	a.AuthorityHash = hash
	return a, nil
}

func (a ConnectorReleaseAuthority) ValidateIntegrity() error {
	if err := a.Validate(); err != nil {
		return err
	}
	if a.AuthorityHash == "" {
		return connectorReleaseAuthorityInvalid("authority_hash is required")
	}
	sealed, err := a.Seal()
	if err != nil || sealed.AuthorityHash != a.AuthorityHash {
		return connectorReleaseAuthorityInvalid("authority integrity mismatch")
	}
	return nil
}

// ValidateAt proves that this exact signed statement is locally live. It does
// not prove it is the latest registry revision; the durable current-state store
// must perform that anti-rollback check separately.
func (a ConnectorReleaseAuthority) ValidateAt(now time.Time) error {
	if err := a.ValidateIntegrity(); err != nil {
		return err
	}
	if a.State != ConnectorReleaseAuthorityStateCertified {
		return fmt.Errorf("%w: release is revoked", ErrConnectorReleaseAuthorityInactive)
	}
	now = now.UTC()
	if now.Before(a.ValidFrom) || a.ValidUntil == nil || !now.Before(*a.ValidUntil) {
		return fmt.Errorf("%w: release is outside its validity window", ErrConnectorReleaseAuthorityInactive)
	}
	return nil
}

func (e ConnectorReleaseAuthorityEnvelope) Validate() error {
	if err := e.Authority.ValidateIntegrity(); err != nil {
		return err
	}
	raw, err := hex.DecodeString(e.Signature)
	if err != nil || len(raw) != 64 || hex.EncodeToString(raw) != e.Signature {
		return connectorReleaseAuthorityInvalid("signature must be canonical lowercase Ed25519 hex")
	}
	return nil
}

func connectorReleaseAuthorityInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrConnectorReleaseAuthorityInvalid, message)
}
