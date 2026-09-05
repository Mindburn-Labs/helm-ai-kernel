package main

// quantum_posture: activation trust uses pinned classical Ed25519 keys;
// no post-quantum signature verification is implemented here.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	companyActivationPublicKeyEnv                = "HELM_CONTROL_PLANE_ACTIVATION_PUBLIC_KEY"
	companyActivationDeploymentModeEnv           = "HELM_DEPLOYMENT_MODE"
	companyActivationExecutionProfileHeader      = "X-Helm-Execution-Profile"
	companyActivationOrganizationRuntimeProfile  = "organization-runtime"
	companyActivationOrganizationRuntimePath     = "/internal/v1/organization-runtime/evaluate"
	organizationRuntimeOriginatorContextKey      = "organization_runtime_originator"
	organizationRuntimePresentedActivationDomain = "HELM/OrganizationRuntimePresentedActivation/v1"
)

type organizationRuntimeActivationEvidence struct {
	IdentityKind          string
	RecordRef             string
	RecordHash            string
	PresentedIdentityHash string
	CompanyID             string
	EnvironmentID         string
	EffectClass           string
	AutonomyLevel         string
}

type organizationRuntimeReceiptProvenance struct {
	Originator  contracts.OrganizationRuntimeOriginatorAssertion
	Activation  organizationRuntimeActivationEvidence
	TenantID    string
	WorkspaceID string
	Reason      string
}

func configuredCompanyActivationPublicKey() (ed25519.PublicKey, error) {
	value := strings.TrimSpace(os.Getenv(companyActivationPublicKeyEnv))
	if value == "" {
		return nil, nil
	}
	value = strings.TrimPrefix(value, "ed25519:")
	if len(value) != ed25519.PublicKeySize*2 || strings.ToLower(value) != value {
		return nil, fmt.Errorf("%s must be a lowercase hex-encoded Ed25519 public key", companyActivationPublicKeyEnv)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s must be a lowercase hex-encoded Ed25519 public key", companyActivationPublicKeyEnv)
	}
	return ed25519.PublicKey(decoded), nil
}

func configuredCompanyActivationEnvironmentID() (string, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(companyActivationDeploymentModeEnv))) {
	case "", "managed":
		return "managed", nil
	case "local":
		return "local", nil
	case "high-assurance", "high_assurance":
		return "high-assurance", nil
	default:
		return "", fmt.Errorf("%s must be local, managed, or high-assurance", companyActivationDeploymentModeEnv)
	}
}

func validateCompanyActivationRuntimeConfiguration(publicKey ed25519.PublicKey, organizationRuntimeKey string) error {
	if len(publicKey) == 0 && organizationRuntimeKey == "" {
		return nil
	}
	if len(publicKey) != ed25519.PublicKeySize || organizationRuntimeKey == "" {
		return fmt.Errorf("%s and %s must be configured together", companyActivationPublicKeyEnv, organizationRuntimeAPIKeyEnv)
	}
	return nil
}

func organizationRuntimeActivationDenial(svc *Services, req *api.EvaluateRequest, organizationRuntime bool, tenantID, workspaceID string, now time.Time) (contracts.ReasonCode, string, *organizationRuntimeActivationEvidence) {
	if req == nil || req.Context == nil {
		return contracts.ReasonActivationRecordInvalid, "Company activation request context is unavailable", nil
	}
	if !organizationRuntime {
		for _, field := range []string{
			"organization_runtime", "execution_profile", "company_activation_record",
			"activation_record_ref", "activation_record_hash", "company_id", "environment_id", "autonomy_level",
		} {
			delete(req.Context, field)
		}
		return "", "", nil
	}
	autonomyLevel, _ := req.Context["autonomy_level"].(string)
	autonomyLevel = strings.TrimSpace(autonomyLevel)
	rawRecord, ok := req.Context["company_activation_record"]
	evidence := &organizationRuntimeActivationEvidence{
		IdentityKind:          contracts.OrganizationRuntimeActivationIdentityPresented,
		PresentedIdentityHash: presentedCompanyActivationIdentityHash(ok, rawRecord),
		CompanyID:             tenantID,
		EffectClass:           req.EffectLevel,
		AutonomyLevel:         autonomyLevel,
	}
	if svc != nil {
		evidence.EnvironmentID = svc.CompanyActivationEnvironmentID
	}
	for _, field := range []string{
		"organization_runtime", "execution_profile", "company_activation_record",
		"activation_record_ref", "activation_record_hash", "company_id", "environment_id", "effect_class", "autonomy_level",
	} {
		delete(req.Context, field)
	}
	req.Context["organization_runtime"] = true
	req.Context["execution_profile"] = companyActivationOrganizationRuntimeProfile
	if svc == nil || len(svc.CompanyActivationPublicKey) != ed25519.PublicKeySize {
		return contracts.ReasonActivationTrustUnavailable, "Company activation trust anchor is unavailable", evidence
	}
	if !ok || rawRecord == nil {
		return contracts.ReasonActivationRecordInvalid, "Company activation record is required", evidence
	}
	encoded, err := json.Marshal(rawRecord)
	if err != nil {
		return contracts.ReasonActivationRecordInvalid, "Company activation record is invalid", evidence
	}
	record, err := contracts.DecodeCompanyActivationRecord(encoded)
	if err != nil {
		return contracts.ReasonActivationRecordInvalid, "Company activation record is invalid", evidence
	}
	err = contracts.VerifyCompanyActivationRecord(record, svc.CompanyActivationPublicKey, contracts.CompanyActivationBinding{
		TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: svc.CompanyActivationEnvironmentID,
		EffectClass: req.EffectLevel, AutonomyLevel: autonomyLevel, Now: now,
	})
	if err == nil || errors.Is(err, contracts.ErrCompanyActivationCeilingExceeded) {
		evidence.IdentityKind = contracts.OrganizationRuntimeActivationIdentityVerified
		evidence.RecordRef = record.RecordRef
		evidence.RecordHash = record.RecordHash
		evidence.CompanyID = record.CompanyID
		evidence.EnvironmentID = record.EnvironmentID
	}
	if err == nil {
		err = contracts.VerifyUncertifiedCompanyActivationCheckpoint(record)
	}
	switch {
	case err == nil:
		req.Context["activation_record_ref"] = record.RecordRef
		req.Context["activation_record_hash"] = record.RecordHash
		req.Context["company_id"] = record.CompanyID
		req.Context["environment_id"] = record.EnvironmentID
		req.Context["effect_class"] = req.EffectLevel
		req.Context["autonomy_level"] = autonomyLevel
		return "", "", evidence
	case errors.Is(err, contracts.ErrCompanyActivationBindingMismatch):
		return contracts.ReasonActivationBindingMismatch, "Company activation record does not match the authenticated runtime request", evidence
	case errors.Is(err, contracts.ErrCompanyActivationCeilingExceeded):
		return contracts.ReasonActivationCeilingExceeded, "Company activation ceiling was exceeded", evidence
	default:
		return contracts.ReasonActivationRecordInvalid, "Company activation record is invalid or inactive", evidence
	}
}

func bindOrganizationRuntimeOriginator(req *api.EvaluateRequest, organizationRuntime bool, executorPrincipalID string) (*contracts.OrganizationRuntimeOriginatorAssertion, error) {
	if req == nil || req.Context == nil {
		return nil, fmt.Errorf("organization runtime request context is unavailable")
	}
	stripOrganizationRuntimeOriginatorAliases(req.Context)
	if req.Args != nil {
		policyArgs := make(map[string]any, len(req.Args))
		for key, value := range req.Args {
			policyArgs[key] = value
		}
		stripOrganizationRuntimeOriginatorAliases(policyArgs)
		req.Context["args"] = policyArgs
	}
	if !organizationRuntime {
		req.Originator = nil
		return nil, nil
	}
	if req.Originator == nil {
		return nil, fmt.Errorf("organization runtime originator assertion is required")
	}
	assertion := *req.Originator
	if err := assertion.Validate(); err != nil {
		return nil, err
	}
	if assertion.PrincipalID == executorPrincipalID {
		return nil, fmt.Errorf("organization runtime originator must be distinct from the authenticated executor")
	}
	req.Context[organizationRuntimeOriginatorContextKey] = map[string]any{
		"principal_id":     assertion.PrincipalID,
		"assertion_source": assertion.AssertionSource,
	}
	return &assertion, nil
}

func stripOrganizationRuntimeOriginatorAliases(values map[string]any) {
	for _, field := range []string{
		"requesting_principal", "requesting_principal_id",
		"originator", "originator_id", "originator_principal", "originator_principal_id",
		"originator_assertion", "originator_assertion_source", "assertion_source",
		organizationRuntimeOriginatorContextKey,
	} {
		delete(values, field)
	}
}

func presentedCompanyActivationIdentityHash(present bool, raw any) string {
	presentation := struct {
		Present bool `json:"present"`
		Record  any  `json:"record"`
	}{Present: present, Record: raw}
	encoded, err := canonicalize.JCS(presentation)
	if err != nil {
		encoded = []byte(`{"present":true,"record":"unencodable"}`)
	}
	digest := sha256.Sum256(append([]byte(organizationRuntimePresentedActivationDomain+"\x00"), encoded...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func signOrganizationRuntimeDecisionAttestation(ctx context.Context, svc *Services, receipt *contracts.Receipt, provenance organizationRuntimeReceiptProvenance) (*contracts.OrganizationRuntimeDecisionAttestationV1, error) {
	sealSigner, _, err := trustedEvidenceBundleSealSigner(svc)
	if err != nil {
		return nil, fmt.Errorf("organization runtime attestation signer: %w", err)
	}
	attestation := contracts.OrganizationRuntimeDecisionAttestationV1{
		Domain:                          contracts.OrganizationRuntimeDecisionAttestationDomainV1,
		SchemaVersion:                   contracts.OrganizationRuntimeDecisionAttestationSchemaV1,
		ContractVersion:                 contracts.OrganizationRuntimeDecisionAttestationContractV1,
		ReceiptID:                       receipt.ReceiptID,
		DecisionID:                      receipt.DecisionID,
		OutputHash:                      receipt.OutputHash,
		ExecutorPrincipalID:             receipt.ExecutorID,
		OriginatorPrincipalID:           provenance.Originator.PrincipalID,
		OriginatorAssertionSource:       provenance.Originator.AssertionSource,
		TenantID:                        provenance.TenantID,
		WorkspaceID:                     provenance.WorkspaceID,
		CompanyID:                       provenance.Activation.CompanyID,
		EnvironmentID:                   provenance.Activation.EnvironmentID,
		EffectClass:                     provenance.Activation.EffectClass,
		AutonomyLevel:                   provenance.Activation.AutonomyLevel,
		ActivationIdentityKind:          provenance.Activation.IdentityKind,
		ActivationRecordRef:             provenance.Activation.RecordRef,
		ActivationRecordHash:            provenance.Activation.RecordHash,
		PresentedActivationIdentityHash: provenance.Activation.PresentedIdentityHash,
		Verdict:                         receipt.Verdict,
		ReasonCode:                      receipt.ReasonCode,
		Reason:                          provenance.Reason,
		Timestamp:                       receipt.Timestamp,
		SignatureAlgorithm:              contracts.OrganizationRuntimeDecisionAttestationAlgorithmEd25519,
		SigningKeyID:                    sealSigner.KeyID(),
	}
	payload, err := attestation.SigningPayload()
	if err != nil {
		return nil, err
	}
	signature, err := sealSigner.Sign(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("sign organization runtime decision attestation: %w", err)
	}
	attestation.Signature = "ed25519:" + hex.EncodeToString(signature)
	return &attestation, nil
}

func signedActivationDenyDecision(svc *Services, req *api.EvaluateRequest, principalID string, reasonCode contracts.ReasonCode, reason string, now time.Time) (*contracts.DecisionRecord, error) {
	if svc == nil || svc.ReceiptSigner == nil {
		return nil, fmt.Errorf("activation denial signer unavailable")
	}
	decision := &contracts.DecisionRecord{
		ID:            "dec-" + randomHex(16),
		Timestamp:     now.UTC(),
		SubjectID:     principalID,
		Action:        req.Tool,
		Resource:      req.Resource,
		Verdict:       string(contracts.VerdictDeny),
		ReasonCode:    string(reasonCode),
		Reason:        reason,
		InputContext:  req.Context,
		PolicyVersion: contracts.CompanyActivationRecordSchemaV1,
	}
	if err := svc.ReceiptSigner.SignDecision(decision); err != nil {
		return nil, fmt.Errorf("sign activation denial decision: %w", err)
	}
	return decision, nil
}
