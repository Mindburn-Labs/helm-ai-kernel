package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

const (
	approvalConsumptionEnabledEnv       = "HELM_APPROVAL_CONSUMPTION_ENABLED"
	approvalConsumerJWKSURLEnv          = "HELM_APPROVAL_CONSUMER_JWKS_URL"
	approvalConsumerIssuerEnv           = "HELM_APPROVAL_CONSUMER_ISSUER"
	approvalConsumerAudienceEnv         = "HELM_APPROVAL_CONSUMER_AUDIENCE"
	approvalConsumerResourceEnv         = "HELM_APPROVAL_CONSUMER_RESOURCE"
	approvalConsumerScopeEnv            = "HELM_APPROVAL_CONSUMER_SCOPE"
	approvalDispatchScopeEnv            = "HELM_APPROVAL_DISPATCH_SCOPE"
	approvalDispatchAdmissionTTLEnv     = "HELM_APPROVAL_DISPATCH_ADMISSION_TTL"
	approvalSigningKeyRefEnv            = "HELM_APPROVAL_SIGNING_KEY_REF"
	approvalKernelTrustRootIDEnv        = "HELM_APPROVAL_KERNEL_TRUST_ROOT_ID"
	approvalConsumerMaxTokenTTLEnv      = "HELM_APPROVAL_CONSUMER_MAX_TOKEN_TTL"
	defaultApprovalConsumerScope        = "helm.approval.consume"
	defaultApprovalDispatchScope        = "helm.approval.dispatch"
	defaultApprovalDispatchAdmissionTTL = 30 * time.Second
	defaultApprovalConsumerMaxTokenTTL  = 5 * time.Minute
	maximumApprovalConsumerMaxTokenTTL  = 15 * time.Minute
)

type approvalConsumptionConfig struct {
	JWKSURL              string
	Issuer               string
	Audience             string
	Resource             string
	Scope                string
	DispatchScope        string
	SigningKeyRef        string
	KernelTrustRootID    string
	MaxTokenTTL          time.Duration
	DispatchAdmissionTTL time.Duration
}

func approvalConsumptionConfigFromEnv() (approvalConsumptionConfig, bool, error) {
	if !envBool(approvalConsumptionEnabledEnv) {
		return approvalConsumptionConfig{}, false, nil
	}
	config := approvalConsumptionConfig{
		JWKSURL:              strings.TrimSpace(os.Getenv(approvalConsumerJWKSURLEnv)),
		Issuer:               strings.TrimSpace(os.Getenv(approvalConsumerIssuerEnv)),
		Audience:             strings.TrimSpace(os.Getenv(approvalConsumerAudienceEnv)),
		Resource:             strings.TrimSpace(os.Getenv(approvalConsumerResourceEnv)),
		Scope:                strings.TrimSpace(os.Getenv(approvalConsumerScopeEnv)),
		DispatchScope:        strings.TrimSpace(os.Getenv(approvalDispatchScopeEnv)),
		SigningKeyRef:        strings.TrimSpace(os.Getenv(approvalSigningKeyRefEnv)),
		KernelTrustRootID:    strings.TrimSpace(os.Getenv(approvalKernelTrustRootIDEnv)),
		MaxTokenTTL:          defaultApprovalConsumerMaxTokenTTL,
		DispatchAdmissionTTL: defaultApprovalDispatchAdmissionTTL,
	}
	if config.Scope == "" {
		config.Scope = defaultApprovalConsumerScope
	}
	if config.DispatchScope == "" {
		config.DispatchScope = defaultApprovalDispatchScope
	}
	for name, value := range map[string]string{
		approvalConsumerJWKSURLEnv:   config.JWKSURL,
		approvalConsumerIssuerEnv:    config.Issuer,
		approvalConsumerAudienceEnv:  config.Audience,
		approvalConsumerResourceEnv:  config.Resource,
		approvalSigningKeyRefEnv:     config.SigningKeyRef,
		approvalKernelTrustRootIDEnv: config.KernelTrustRootID,
	} {
		if value == "" {
			return approvalConsumptionConfig{}, true, fmt.Errorf("%s is required when %s=1", name, approvalConsumptionEnabledEnv)
		}
	}
	if rawTTL := strings.TrimSpace(os.Getenv(approvalConsumerMaxTokenTTLEnv)); rawTTL != "" {
		parsedTTL, ttlErr := time.ParseDuration(rawTTL)
		if ttlErr != nil {
			return approvalConsumptionConfig{}, true, fmt.Errorf("parse %s: %w", approvalConsumerMaxTokenTTLEnv, ttlErr)
		}
		config.MaxTokenTTL = parsedTTL
	}
	if rawTTL := strings.TrimSpace(os.Getenv(approvalDispatchAdmissionTTLEnv)); rawTTL != "" {
		parsedTTL, ttlErr := time.ParseDuration(rawTTL)
		if ttlErr != nil {
			return approvalConsumptionConfig{}, true, fmt.Errorf("parse %s: %w", approvalDispatchAdmissionTTLEnv, ttlErr)
		}
		config.DispatchAdmissionTTL = parsedTTL
	}
	if config.MaxTokenTTL <= 0 || config.MaxTokenTTL > maximumApprovalConsumerMaxTokenTTL {
		return approvalConsumptionConfig{}, true, fmt.Errorf(
			"%s must be greater than zero and no more than %s",
			approvalConsumerMaxTokenTTLEnv, maximumApprovalConsumerMaxTokenTTL,
		)
	}
	if config.DispatchAdmissionTTL <= 0 || config.DispatchAdmissionTTL > contracts.ApprovalDispatchAdmissionMaxTTL {
		return approvalConsumptionConfig{}, true, fmt.Errorf(
			"%s must be greater than zero and no more than %s",
			approvalDispatchAdmissionTTLEnv, contracts.ApprovalDispatchAdmissionMaxTTL,
		)
	}
	parsedJWKS, err := url.Parse(config.JWKSURL)
	if err != nil || parsedJWKS.Scheme != "https" || parsedJWKS.Host == "" {
		return approvalConsumptionConfig{}, true, errors.New("approval consumer JWKS URL must be an absolute HTTPS URL")
	}
	if !validWorkloadClaim(config.Issuer) || !validWorkloadClaim(config.Audience) || !validWorkloadClaim(config.Resource) ||
		!validWorkloadClaim(config.SigningKeyRef) ||
		!validWorkloadClaim(config.KernelTrustRootID) || !validWorkloadClaim(config.Scope) ||
		!validWorkloadClaim(config.DispatchScope) || config.DispatchScope == config.Scope {
		return approvalConsumptionConfig{}, true, errors.New("approval consumption issuer, audience, resource, scope, signing key, and trust root must be non-whitespace tokens")
	}
	return config, true, nil
}

func newApprovalConsumptionRuntime(ctx context.Context, db *sql.DB, databaseMode string, signer helmcrypto.Signer, stops kernel.ScopedStopReader) (*approvalConsumptionRuntime, error) {
	config, enabled, err := approvalConsumptionConfigFromEnv()
	if err != nil || !enabled {
		return nil, err
	}
	if databaseMode != "postgres" || db == nil {
		return nil, errors.New("approval grant consumption requires the durable PostgreSQL runtime")
	}
	if stops == nil {
		return nil, errors.New("approval grant consumption requires durable emergency-stop scope coordination")
	}
	approvalSigner, err := classicalApprovalSigner(signer)
	if err != nil {
		return nil, err
	}
	verifier, err := approvalceremony.NewEd25519GrantSignatureVerifier(
		approvalSigner.PublicKeyBytes(), config.SigningKeyRef, config.KernelTrustRootID,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize approval grant verifier: %w", err)
	}
	store := approvalceremony.NewPostgresStore(db, verifier)
	if err := store.Init(ctx); err != nil {
		return nil, fmt.Errorf("initialize approval ceremony store: %w", err)
	}
	consumer, err := approvalceremony.NewGrantConsumer(
		store, approvalceremony.ContextConsumerIdentityProvider{}, approvalSigner,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize approval grant consumer: %w", err)
	}
	admitter, err := approvalceremony.NewDispatchAdmitter(
		store, approvalceremony.ContextConsumerIdentityProvider{}, approvalSigner, config.DispatchAdmissionTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize approval dispatch admitter: %w", err)
	}
	validator := mcppkg.NewJWKSValidator(mcppkg.JWKSConfig{
		JWKSURL: config.JWKSURL, Issuer: config.Issuer, Audience: config.Audience,
		Resource: config.Resource, Scopes: []string{config.Scope},
	})
	dispatchValidator := mcppkg.NewJWKSValidator(mcppkg.JWKSConfig{
		JWKSURL: config.JWKSURL, Issuer: config.Issuer, Audience: config.Audience,
		Resource: config.Resource, Scopes: []string{config.DispatchScope},
	})
	return &approvalConsumptionRuntime{
		consumer: consumer, admitter: admitter, validator: validator, dispatchValidator: dispatchValidator,
		stops: stops, audience: config.Audience,
		maxTokenTTL: config.MaxTokenTTL,
	}, nil
}

func classicalApprovalSigner(signer helmcrypto.Signer) (helmcrypto.Signer, error) {
	switch typed := signer.(type) {
	case *helmcrypto.Ed25519Signer:
		return typed, nil
	case *helmcrypto.HybridSigner:
		if typed == nil || typed.Ed25519Signer() == nil {
			break
		}
		return typed.Ed25519Signer(), nil
	}
	return nil, errors.New("approval grant consumption requires an Ed25519 Kernel signing authority")
}
