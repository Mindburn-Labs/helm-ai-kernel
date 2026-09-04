// quantum_posture: organization-runtime decision attestations use a
// domain-separated classical Ed25519 companion signature. The enclosing
// receipt may use a stronger profile independently.
package contracts

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const (
	OrganizationRuntimeOriginatorAssertionSourceControlPlane = "helm-control-plane"

	OrganizationRuntimeDecisionAttestationDomainV1         = "HELM/OrganizationRuntimeDecisionAttestation/v1"
	OrganizationRuntimeDecisionAttestationSchemaV1         = "organization-runtime-decision-attestation.v1"
	OrganizationRuntimeDecisionAttestationContractV1       = "2026-09-04"
	OrganizationRuntimeDecisionAttestationAlgorithmEd25519 = "ed25519"
	OrganizationRuntimeActivationIdentityVerified          = "verified"
	OrganizationRuntimeActivationIdentityPresented         = "presented"
	organizationRuntimeAttestationMaxTokenBytes            = 512
	organizationRuntimeAttestationMaxReasonBytes           = 4096
)

var ErrOrganizationRuntimeDecisionAttestationInvalid = errors.New("organization runtime decision attestation invalid")

// OrganizationRuntimeOriginatorAssertion is the sole caller-supplied human
// identity assertion accepted by the OrganizationRuntime route. The dedicated
// control-plane credential authenticates its source; the Kernel still records
// the authenticated service executor separately.
type OrganizationRuntimeOriginatorAssertion struct {
	PrincipalID     string `json:"principal_id"`
	AssertionSource string `json:"assertion_source"`
}

// UnmarshalJSON keeps this authority-bearing nested object closed even though
// the wider legacy evaluate envelope remains extension-tolerant.
func (a *OrganizationRuntimeOriginatorAssertion) UnmarshalJSON(data []byte) error {
	type wire OrganizationRuntimeOriginatorAssertion
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded wire
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("originator assertion has trailing JSON")
	}
	*a = OrganizationRuntimeOriginatorAssertion(decoded)
	return nil
}

func (a OrganizationRuntimeOriginatorAssertion) Validate() error {
	if !isApprovalGrantToken(a.PrincipalID) || len(a.PrincipalID) > organizationRuntimeAttestationMaxTokenBytes {
		return organizationRuntimeAttestationInvalid("originator principal_id is required and must be a bounded token")
	}
	if a.AssertionSource != OrganizationRuntimeOriginatorAssertionSourceControlPlane {
		return organizationRuntimeAttestationInvalid("originator assertion_source is unsupported")
	}
	return nil
}

// OrganizationRuntimeDecisionAttestationV1 is an independently signed
// companion to Receipt V5. It binds OrganizationRuntime-only provenance
// without changing the stable generic receipt signing preimage.
type OrganizationRuntimeDecisionAttestationV1 struct {
	Domain          string `json:"domain"`
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`

	ReceiptID  string `json:"receipt_id"`
	DecisionID string `json:"decision_id"`
	OutputHash string `json:"output_hash"`

	ExecutorPrincipalID       string `json:"executor_principal_id"`
	OriginatorPrincipalID     string `json:"originator_principal_id"`
	OriginatorAssertionSource string `json:"originator_assertion_source"`

	TenantID      string `json:"tenant_id"`
	WorkspaceID   string `json:"workspace_id"`
	CompanyID     string `json:"company_id"`
	EnvironmentID string `json:"environment_id"`

	EffectClass   string `json:"effect_class"`
	AutonomyLevel string `json:"autonomy_level"`

	ActivationIdentityKind          string `json:"activation_identity_kind"`
	ActivationRecordRef             string `json:"activation_record_ref,omitempty"`
	ActivationRecordHash            string `json:"activation_record_hash,omitempty"`
	PresentedActivationIdentityHash string `json:"presented_activation_identity_hash"`

	Verdict    string    `json:"verdict"`
	ReasonCode string    `json:"reason_code"`
	Reason     string    `json:"reason"`
	Timestamp  time.Time `json:"timestamp"`

	SignatureAlgorithm string `json:"signature_algorithm"`
	SigningKeyID       string `json:"signing_key_id"`
	Signature          string `json:"signature"`
}

// SigningPayload returns the domain-prefixed RFC 8785 payload. Signature is
// held structurally empty in the preimage so the wire shape stays explicit
// without self-reference.
func (a OrganizationRuntimeDecisionAttestationV1) SigningPayload() ([]byte, error) {
	a.Signature = ""
	if err := a.validate(false); err != nil {
		return nil, err
	}
	canonical, err := canonicalize.InteroperableJCS(a)
	if err != nil {
		return nil, organizationRuntimeAttestationInvalid("canonicalize signing payload: " + err.Error())
	}
	prefix := []byte(OrganizationRuntimeDecisionAttestationDomainV1 + "\x00")
	return append(prefix, canonical...), nil
}

// VerifyOrganizationRuntimeReceiptAttestation rejects an OrganizationRuntime
// receipt unless its companion is present, exactly receipt-bound, and signed
// by the trusted runtime Ed25519 key.
func VerifyOrganizationRuntimeReceiptAttestation(receipt *Receipt, publicKey ed25519.PublicKey) error {
	if receipt == nil {
		return organizationRuntimeAttestationInvalid("receipt is required")
	}
	if receipt.OrganizationRuntimeDecisionAttestation == nil {
		return organizationRuntimeAttestationInvalid("companion attestation is required")
	}
	a := *receipt.OrganizationRuntimeDecisionAttestation
	if err := a.validate(true); err != nil {
		return err
	}
	if a.ReceiptID != receipt.ReceiptID || a.DecisionID != receipt.DecisionID ||
		a.OutputHash != receipt.OutputHash || a.ExecutorPrincipalID != receipt.ExecutorID ||
		a.Verdict != receipt.Verdict || a.ReasonCode != receipt.ReasonCode ||
		!a.Timestamp.Equal(receipt.Timestamp) {
		return organizationRuntimeAttestationInvalid("companion does not match receipt")
	}
	storedReason, ok := receipt.Metadata["reason"].(string)
	if !ok || a.Reason != storedReason {
		return organizationRuntimeAttestationInvalid("companion reason does not match receipt evidence")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return organizationRuntimeAttestationInvalid("trusted Ed25519 public key is invalid")
	}
	payload, err := a.SigningPayload()
	if err != nil {
		return err
	}
	signature, err := organizationRuntimeAttestationSignature(a.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return organizationRuntimeAttestationInvalid("signature verification failed")
	}
	return nil
}

func (a OrganizationRuntimeDecisionAttestationV1) validate(sealed bool) error {
	if a.Domain != OrganizationRuntimeDecisionAttestationDomainV1 ||
		a.SchemaVersion != OrganizationRuntimeDecisionAttestationSchemaV1 ||
		a.ContractVersion != OrganizationRuntimeDecisionAttestationContractV1 {
		return organizationRuntimeAttestationInvalid("unsupported domain or contract version")
	}
	for field, value := range map[string]string{
		"receipt_id": a.ReceiptID, "decision_id": a.DecisionID,
		"executor_principal_id":   a.ExecutorPrincipalID,
		"originator_principal_id": a.OriginatorPrincipalID,
		"tenant_id":               a.TenantID, "workspace_id": a.WorkspaceID,
		"company_id": a.CompanyID, "environment_id": a.EnvironmentID,
		"effect_class": a.EffectClass, "signing_key_id": a.SigningKeyID,
	} {
		if !isApprovalGrantToken(value) || len(value) > organizationRuntimeAttestationMaxTokenBytes {
			return organizationRuntimeAttestationInvalid(field + " is required and must be a bounded token")
		}
	}
	if a.OriginatorPrincipalID == a.ExecutorPrincipalID {
		return organizationRuntimeAttestationInvalid("originator must be distinct from the authenticated executor")
	}
	if a.OriginatorAssertionSource != OrganizationRuntimeOriginatorAssertionSourceControlPlane {
		return organizationRuntimeAttestationInvalid("originator assertion source is unsupported")
	}
	if !isApprovalGrantSHA256(a.OutputHash) || !isApprovalGrantSHA256(a.PresentedActivationIdentityHash) {
		return organizationRuntimeAttestationInvalid("output and presented activation identity hashes must be lowercase sha256 references")
	}
	if len(a.AutonomyLevel) > 32 || strings.ContainsAny(a.AutonomyLevel, "\r\n") || strings.TrimSpace(a.AutonomyLevel) != a.AutonomyLevel {
		return organizationRuntimeAttestationInvalid("autonomy_level is invalid")
	}
	switch a.ActivationIdentityKind {
	case OrganizationRuntimeActivationIdentityVerified:
		if !isApprovalGrantToken(a.ActivationRecordRef) || !isApprovalGrantSHA256(a.ActivationRecordHash) {
			return organizationRuntimeAttestationInvalid("verified activation identity requires record ref and hash")
		}
	case OrganizationRuntimeActivationIdentityPresented:
		if a.ActivationRecordRef != "" || a.ActivationRecordHash != "" {
			return organizationRuntimeAttestationInvalid("unverified activation identity must use only the presented identity hash")
		}
	default:
		return organizationRuntimeAttestationInvalid("activation identity kind is unsupported")
	}
	switch Verdict(a.Verdict) {
	case VerdictAllow, VerdictDeny, VerdictEscalate:
	default:
		return organizationRuntimeAttestationInvalid("verdict is invalid")
	}
	if a.ReasonCode != "" && (!isApprovalGrantToken(a.ReasonCode) || len(a.ReasonCode) > organizationRuntimeAttestationMaxTokenBytes) {
		return organizationRuntimeAttestationInvalid("reason_code is invalid")
	}
	if len(a.Reason) > organizationRuntimeAttestationMaxReasonBytes {
		return organizationRuntimeAttestationInvalid("reason is too large")
	}
	if a.Timestamp.IsZero() {
		return organizationRuntimeAttestationInvalid("timestamp is required")
	}
	_, offset := a.Timestamp.Zone()
	if offset != 0 {
		return organizationRuntimeAttestationInvalid("timestamp must use UTC")
	}
	if a.SignatureAlgorithm != OrganizationRuntimeDecisionAttestationAlgorithmEd25519 {
		return organizationRuntimeAttestationInvalid("signature_algorithm must be ed25519")
	}
	if sealed {
		if _, err := organizationRuntimeAttestationSignature(a.Signature); err != nil {
			return err
		}
	} else if a.Signature != "" {
		return organizationRuntimeAttestationInvalid("signature must be empty while building the signing payload")
	}
	return nil
}

func organizationRuntimeAttestationSignature(value string) ([]byte, error) {
	const prefix = "ed25519:"
	if !strings.HasPrefix(value, prefix) {
		return nil, organizationRuntimeAttestationInvalid("signature must use the ed25519 prefix")
	}
	raw := strings.TrimPrefix(value, prefix)
	if len(raw) != ed25519.SignatureSize*2 || strings.ToLower(raw) != raw {
		return nil, organizationRuntimeAttestationInvalid("signature must be 64 lowercase hexadecimal bytes")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, organizationRuntimeAttestationInvalid("signature must be 64 lowercase hexadecimal bytes")
	}
	return decoded, nil
}

func organizationRuntimeAttestationInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrOrganizationRuntimeDecisionAttestationInvalid, message)
}
