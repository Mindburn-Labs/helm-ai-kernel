package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	companyActivationPublicKeyEnv               = "HELM_CONTROL_PLANE_ACTIVATION_PUBLIC_KEY"
	companyActivationDeploymentModeEnv          = "HELM_DEPLOYMENT_MODE"
	companyActivationExecutionProfileHeader     = "X-Helm-Execution-Profile"
	companyActivationOrganizationRuntimeProfile = "organization-runtime"
	companyActivationOrganizationRuntimePath    = "/internal/v1/organization-runtime/evaluate"
)

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

func organizationRuntimeActivationDenial(svc *Services, req *api.EvaluateRequest, organizationRuntime bool, tenantID, workspaceID string, now time.Time) (contracts.ReasonCode, string) {
	if req == nil || req.Context == nil {
		return contracts.ReasonActivationRecordInvalid, "Company activation request context is unavailable"
	}
	if !organizationRuntime {
		for _, field := range []string{
			"organization_runtime", "execution_profile", "company_activation_record",
			"activation_record_ref", "activation_record_hash", "company_id", "environment_id", "autonomy_level",
		} {
			delete(req.Context, field)
		}
		return "", ""
	}
	autonomyLevel, _ := req.Context["autonomy_level"].(string)
	autonomyLevel = strings.TrimSpace(autonomyLevel)
	rawRecord, ok := req.Context["company_activation_record"]
	for _, field := range []string{
		"organization_runtime", "execution_profile", "company_activation_record",
		"activation_record_ref", "activation_record_hash", "company_id", "environment_id", "effect_class", "autonomy_level",
	} {
		delete(req.Context, field)
	}
	req.Context["organization_runtime"] = true
	req.Context["execution_profile"] = companyActivationOrganizationRuntimeProfile
	if svc == nil || len(svc.CompanyActivationPublicKey) != ed25519.PublicKeySize {
		return contracts.ReasonActivationTrustUnavailable, "Company activation trust anchor is unavailable"
	}
	if !ok || rawRecord == nil {
		return contracts.ReasonActivationRecordInvalid, "Company activation record is required"
	}
	encoded, err := json.Marshal(rawRecord)
	if err != nil {
		return contracts.ReasonActivationRecordInvalid, "Company activation record is invalid"
	}
	record, err := contracts.DecodeCompanyActivationRecord(encoded)
	if err != nil {
		return contracts.ReasonActivationRecordInvalid, "Company activation record is invalid"
	}
	err = contracts.VerifyCompanyActivationRecord(record, svc.CompanyActivationPublicKey, contracts.CompanyActivationBinding{
		TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: svc.CompanyActivationEnvironmentID,
		EffectClass: req.EffectLevel, AutonomyLevel: autonomyLevel, Now: now,
	})
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
		return "", ""
	case errors.Is(err, contracts.ErrCompanyActivationBindingMismatch):
		return contracts.ReasonActivationBindingMismatch, "Company activation record does not match the authenticated runtime request"
	case errors.Is(err, contracts.ErrCompanyActivationCeilingExceeded):
		return contracts.ReasonActivationCeilingExceeded, "Company activation ceiling was exceeded"
	default:
		return contracts.ReasonActivationRecordInvalid, "Company activation record is invalid or inactive"
	}
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
