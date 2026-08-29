package main

// quantum_posture: wires classical Ed25519 grant-consumption, effect-disposition
// command signature verification and RSA-JWKS (RS256) OAuth token checks; no
// post-quantum path.

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	connectorregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry/connectors"
)

const (
	approvalConsumptionEnabledEnv              = "HELM_APPROVAL_CONSUMPTION_ENABLED"
	approvalConsumerJWKSURLEnv                 = "HELM_APPROVAL_CONSUMER_JWKS_URL"
	approvalConsumerIssuerEnv                  = "HELM_APPROVAL_CONSUMER_ISSUER"
	approvalConsumerAudienceEnv                = "HELM_APPROVAL_CONSUMER_AUDIENCE"
	approvalConsumerResourceEnv                = "HELM_APPROVAL_CONSUMER_RESOURCE"
	approvalConsumerScopeEnv                   = "HELM_APPROVAL_CONSUMER_SCOPE"
	approvalDispatchScopeEnv                   = "HELM_APPROVAL_DISPATCH_SCOPE"
	approvalDispatchAdmissionTTLEnv            = "HELM_APPROVAL_DISPATCH_ADMISSION_TTL"
	approvalSigningKeyRefEnv                   = "HELM_APPROVAL_SIGNING_KEY_REF"
	approvalKernelTrustRootIDEnv               = "HELM_APPROVAL_KERNEL_TRUST_ROOT_ID"
	approvalConsumerMaxTokenTTLEnv             = "HELM_APPROVAL_CONSUMER_MAX_TOKEN_TTL"
	approvalControlEnabledEnv                  = "HELM_APPROVAL_CONTROL_ENABLED"
	approvalControlSourceURLEnv                = "HELM_APPROVAL_CONTROL_SOURCE_URL"
	approvalControlSourceTokenEnv              = "HELM_APPROVAL_CONTROL_SOURCE_TOKEN"
	approvalControlOutboundCAFileEnv           = "HELM_APPROVAL_CONTROL_OUTBOUND_CA_BUNDLE_FILE"
	approvalControlScopeEnv                    = "HELM_APPROVAL_CONTROL_SCOPE"
	approvalControlMinHoldDurationEnv          = "HELM_APPROVAL_CONTROL_MIN_HOLD_DURATION"
	approvalControlChallengeTTLEnv             = "HELM_APPROVAL_CONTROL_CHALLENGE_TTL"
	approvalControlMaxChallengeLifetimeEnv     = "HELM_APPROVAL_CONTROL_MAX_CHALLENGE_LIFETIME"
	approvalControlGrantTTLEnv                 = "HELM_APPROVAL_CONTROL_GRANT_TTL"
	approvalControlMaxAssertionsEnv            = "HELM_APPROVAL_CONTROL_MAX_ASSERTIONS"
	approvalControlServerIdentityEnv           = "HELM_APPROVAL_CONTROL_SERVER_IDENTITY"
	effectDispositionEnabledEnv                = "HELM_EFFECT_DISPOSITION_ENABLED"
	effectDispositionScopeEnv                  = "HELM_EFFECT_DISPOSITION_SCOPE"
	effectReconciliationCandidatesEnabledEnv   = "HELM_EFFECT_RECONCILIATION_CANDIDATES_ENABLED"
	effectReconciliationCandidatesResourceEnv  = "HELM_EFFECT_RECONCILIATION_CANDIDATES_RESOURCE"
	effectReconciliationCandidatesScopeEnv     = "HELM_EFFECT_RECONCILIATION_CANDIDATES_SCOPE"
	effectDispositionCommandKeyringEnv         = "HELM_EFFECT_DISPOSITION_COMMAND_KEYRING"
	connectorReleaseAuthorityKeyringEnv        = "HELM_CONNECTOR_RELEASE_AUTHORITY_KEYRING"
	defaultApprovalConsumerScope               = "helm.approval.consume"
	defaultApprovalDispatchScope               = "helm.approval.dispatch"
	defaultApprovalControlScope                = "helm.approval.control"
	defaultEffectDispositionScope              = "helm.effect.disposition"
	defaultEffectReconciliationCandidatesScope = "helm.effect.reconciliation.read"
	effectDispositionCommandKeyringV1          = "effect-disposition-command-keyring.v1"
	connectorReleaseAuthorityKeyringV1         = "connector-release-authority-keyring.v1"
	defaultApprovalDispatchAdmissionTTL        = 30 * time.Second
	defaultApprovalConsumerMaxTokenTTL         = 5 * time.Minute
	maximumApprovalConsumerMaxTokenTTL         = 15 * time.Minute
	defaultApprovalControlMinHoldDuration      = 5 * time.Second
	defaultApprovalControlChallengeTTL         = 10 * time.Minute
	defaultApprovalControlMaxChallengeLifetime = 30 * time.Minute
	defaultApprovalControlGrantTTL             = 2 * time.Minute
	defaultApprovalControlMaxAssertions        = 8
	approvalCeremonyBindingSourcePath          = "/internal/v1/approval-ceremony/source/binding"
	approvalCeremonyAuthoritySourcePath        = "/internal/v1/approval-ceremony/source/authority"
)

type approvalConsumptionConfig struct {
	JWKSURL                          string
	Issuer                           string
	Audience                         string
	Resource                         string
	Scope                            string
	DispatchScope                    string
	SigningKeyRef                    string
	KernelTrustRootID                string
	MaxTokenTTL                      time.Duration
	DispatchAdmissionTTL             time.Duration
	ControlEnabled                   bool
	ControlSourceURL                 string
	ControlSourceToken               string
	ControlOutboundCAFile            string
	ControlScope                     string
	ControlMinHoldDuration           time.Duration
	ControlChallengeTTL              time.Duration
	ControlMaxChallengeLifetime      time.Duration
	ControlGrantTTL                  time.Duration
	ControlMaxAssertions             int
	ControlServerIdentity            string
	DispositionEnabled               bool
	DispositionScope                 string
	ReconciliationCandidatesEnabled  bool
	ReconciliationCandidatesResource string
	ReconciliationCandidatesScope    string
	DispositionKeys                  []approvalceremony.TrustedEffectDispositionCommandKey
	ReleaseAuthorityID               string
	ReleaseAuthorityKeys             []connectorregistry.TrustedReleaseAuthorityKey
}

type runtimeAuthorityKeyring struct {
	KeyringVersion string                       `json:"keyring_version"`
	Keys           []runtimeAuthorityKeyringKey `json:"keys"`
}

type runtimeAuthorityKeyringKey struct {
	AuthorityID   string    `json:"authority_id"`
	SigningKeyRef string    `json:"signing_key_ref"`
	Audience      string    `json:"audience,omitempty"`
	PublicKey     string    `json:"public_key"`
	Enabled       bool      `json:"enabled"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
}

func approvalConsumptionConfigFromEnv() (approvalConsumptionConfig, bool, error) {
	if !envBool(approvalConsumptionEnabledEnv) {
		if envBool(approvalControlEnabledEnv) || envBool(effectDispositionEnabledEnv) || envBool(effectReconciliationCandidatesEnabledEnv) {
			return approvalConsumptionConfig{}, true, errors.New("approval control, effect disposition, and reconciliation transports require approval consumption runtime")
		}
		return approvalConsumptionConfig{}, false, nil
	}
	config := approvalConsumptionConfig{
		JWKSURL:                          strings.TrimSpace(os.Getenv(approvalConsumerJWKSURLEnv)),
		Issuer:                           strings.TrimSpace(os.Getenv(approvalConsumerIssuerEnv)),
		Audience:                         strings.TrimSpace(os.Getenv(approvalConsumerAudienceEnv)),
		Resource:                         strings.TrimSpace(os.Getenv(approvalConsumerResourceEnv)),
		Scope:                            strings.TrimSpace(os.Getenv(approvalConsumerScopeEnv)),
		DispatchScope:                    strings.TrimSpace(os.Getenv(approvalDispatchScopeEnv)),
		SigningKeyRef:                    strings.TrimSpace(os.Getenv(approvalSigningKeyRefEnv)),
		KernelTrustRootID:                strings.TrimSpace(os.Getenv(approvalKernelTrustRootIDEnv)),
		MaxTokenTTL:                      defaultApprovalConsumerMaxTokenTTL,
		DispatchAdmissionTTL:             defaultApprovalDispatchAdmissionTTL,
		ControlEnabled:                   envBool(approvalControlEnabledEnv),
		ControlSourceURL:                 strings.TrimSpace(os.Getenv(approvalControlSourceURLEnv)),
		ControlSourceToken:               strings.TrimSpace(os.Getenv(approvalControlSourceTokenEnv)),
		ControlOutboundCAFile:            strings.TrimSpace(os.Getenv(approvalControlOutboundCAFileEnv)),
		ControlScope:                     strings.TrimSpace(os.Getenv(approvalControlScopeEnv)),
		ControlMinHoldDuration:           defaultApprovalControlMinHoldDuration,
		ControlChallengeTTL:              defaultApprovalControlChallengeTTL,
		ControlMaxChallengeLifetime:      defaultApprovalControlMaxChallengeLifetime,
		ControlGrantTTL:                  defaultApprovalControlGrantTTL,
		ControlMaxAssertions:             defaultApprovalControlMaxAssertions,
		ControlServerIdentity:            strings.TrimSpace(os.Getenv(approvalControlServerIdentityEnv)),
		DispositionEnabled:               envBool(effectDispositionEnabledEnv),
		DispositionScope:                 strings.TrimSpace(os.Getenv(effectDispositionScopeEnv)),
		ReconciliationCandidatesEnabled:  envBool(effectReconciliationCandidatesEnabledEnv),
		ReconciliationCandidatesResource: strings.TrimSpace(os.Getenv(effectReconciliationCandidatesResourceEnv)),
		ReconciliationCandidatesScope:    strings.TrimSpace(os.Getenv(effectReconciliationCandidatesScopeEnv)),
	}
	if config.Scope == "" {
		config.Scope = defaultApprovalConsumerScope
	}
	if config.DispatchScope == "" {
		config.DispatchScope = defaultApprovalDispatchScope
	}
	if config.ControlScope == "" {
		config.ControlScope = defaultApprovalControlScope
	}
	if config.DispositionScope == "" {
		config.DispositionScope = defaultEffectDispositionScope
	}
	if config.ReconciliationCandidatesScope == "" {
		config.ReconciliationCandidatesScope = defaultEffectReconciliationCandidatesScope
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
	if config.ControlEnabled {
		for name, target := range map[string]*time.Duration{
			approvalControlMinHoldDurationEnv:      &config.ControlMinHoldDuration,
			approvalControlChallengeTTLEnv:         &config.ControlChallengeTTL,
			approvalControlMaxChallengeLifetimeEnv: &config.ControlMaxChallengeLifetime,
			approvalControlGrantTTLEnv:             &config.ControlGrantTTL,
		} {
			if raw := strings.TrimSpace(os.Getenv(name)); raw != "" {
				parsed, parseErr := time.ParseDuration(raw)
				if parseErr != nil {
					return approvalConsumptionConfig{}, true, fmt.Errorf("parse %s: %w", name, parseErr)
				}
				*target = parsed
			}
		}
		if raw := strings.TrimSpace(os.Getenv(approvalControlMaxAssertionsEnv)); raw != "" {
			config.ControlMaxAssertions = envInt(approvalControlMaxAssertionsEnv, -1)
		}
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
	if config.ControlEnabled {
		if !validApprovalControlSourceURL(config.ControlSourceURL) || !validWorkloadClaim(config.ControlSourceToken) ||
			!validWorkloadClaim(config.ControlScope) || !validWorkloadClaim(config.ControlServerIdentity) ||
			config.ControlScope == config.Scope || config.ControlScope == config.DispatchScope ||
			config.ControlMinHoldDuration <= 0 || config.ControlChallengeTTL <= 0 ||
			config.ControlMaxChallengeLifetime <= config.ControlMinHoldDuration ||
			config.ControlChallengeTTL > config.ControlMaxChallengeLifetime-config.ControlMinHoldDuration ||
			config.ControlGrantTTL <= 0 || config.ControlMaxAssertions <= 0 || config.ControlMaxAssertions > 64 {
			return approvalConsumptionConfig{}, true, errors.New("approval control source, scope, identity, or lifecycle limits are invalid")
		}
	}
	if config.DispositionEnabled {
		if !validWorkloadClaim(config.DispositionScope) || config.DispositionScope == config.Scope || config.DispositionScope == config.DispatchScope ||
			(config.ControlEnabled && config.DispositionScope == config.ControlScope) {
			return approvalConsumptionConfig{}, true, errors.New("effect disposition scope must be a distinct non-whitespace token")
		}
	}
	if config.ReconciliationCandidatesEnabled {
		if !validEffectReconciliationCandidatesResource(config.ReconciliationCandidatesResource) || !validWorkloadClaim(config.ReconciliationCandidatesScope) ||
			config.ReconciliationCandidatesScope != defaultEffectReconciliationCandidatesScope ||
			config.ReconciliationCandidatesScope == config.Scope || config.ReconciliationCandidatesScope == config.DispatchScope ||
			config.ReconciliationCandidatesScope == config.DispositionScope ||
			(config.ControlEnabled && config.ReconciliationCandidatesScope == config.ControlScope) ||
			config.ReconciliationCandidatesResource == config.Resource {
			return approvalConsumptionConfig{}, true, errors.New("effect reconciliation candidates require the exact route resource and read scope")
		}
	}
	if config.DispositionEnabled || config.ReconciliationCandidatesEnabled {
		config.DispositionKeys, config.ReleaseAuthorityID, config.ReleaseAuthorityKeys, err = configuredEffectDispositionAuthorities(config.Audience)
		if err != nil {
			return approvalConsumptionConfig{}, true, err
		}
	}
	return config, true, nil
}

func validApprovalControlSourceURL(value string) bool {
	if !validWorkloadClaim(value) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && strings.EqualFold(parsed.Scheme, "https") && parsed.Host != "" &&
		parsed.User == nil && parsed.Opaque == "" && parsed.RawPath == "" &&
		parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == ""
}

func validEffectReconciliationCandidatesResource(value string) bool {
	if !validWorkloadClaim(value) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && strings.EqualFold(parsed.Scheme, "https") && parsed.Host != "" &&
		parsed.User == nil && parsed.Opaque == "" && parsed.RawPath == "" &&
		parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" &&
		parsed.Path == effectReconciliationCandidatesPath
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
	// The one-shot helm-ai-kernel migrate command owns approval schema DDL;
	// startup reaches this path only after read-only runtime schema validation.
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
	var controller approvalCeremonyController
	var controlValidator approvalConsumerTokenValidator
	if config.ControlEnabled {
		outboundClient, clientErr := newGeneratedSpecApprovalOutboundClient(config.ControlOutboundCAFile)
		if clientErr != nil {
			return nil, fmt.Errorf("initialize approval control outbound client: %w", clientErr)
		}
		source, sourceErr := newApprovalCeremonySourceClient(
			config.ControlSourceURL, config.ControlSourceToken, outboundClient, config.Audience, false,
		)
		if sourceErr != nil {
			return nil, sourceErr
		}
		controller, err = approvalceremony.NewService(
			store, source, source, approvalControlIdentityProvider{},
			approvalceremony.ContextConsumerIdentityProvider{}, approvalSigner,
			approvalceremony.ServiceConfig{
				MinHoldDuration: config.ControlMinHoldDuration, ChallengeTTL: config.ControlChallengeTTL,
				MaxChallengeLifetime: config.ControlMaxChallengeLifetime, GrantTTL: config.ControlGrantTTL,
				MaxAssertions: config.ControlMaxAssertions, ServerIdentity: config.ControlServerIdentity,
				KernelTrustRootID: config.KernelTrustRootID, SigningKeyRef: config.SigningKeyRef,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("initialize approval ceremony controller: %w", err)
		}
		controlValidator = mcppkg.NewJWKSValidator(mcppkg.JWKSConfig{
			JWKSURL: config.JWKSURL, Issuer: config.Issuer, Audience: config.Audience,
			Resource: config.Resource, Scopes: []string{config.ControlScope}, HTTPClient: outboundClient,
		})
	}
	var disposition effectDispositionRecorder
	var reconciliationCandidates effectReconciliationCandidateProvider
	var dispositionValidator approvalConsumerTokenValidator
	var reconciliationValidator approvalConsumerTokenValidator
	if config.DispositionEnabled || config.ReconciliationCandidatesEnabled {
		commandVerifier, err := approvalceremony.NewEd25519EffectDispositionCommandVerifier(config.DispositionKeys)
		if err != nil {
			return nil, fmt.Errorf("initialize effect disposition command verifier: %w", err)
		}
		releaseVerifier, err := connectorregistry.NewEd25519ReleaseAuthorityVerifier(config.ReleaseAuthorityID, config.ReleaseAuthorityKeys)
		if err != nil {
			return nil, fmt.Errorf("initialize connector release authority verifier: %w", err)
		}
		releaseStore, err := connectorregistry.NewPostgresReleaseAuthorityStore(db, releaseVerifier)
		if err != nil {
			return nil, fmt.Errorf("initialize connector release authority store: %w", err)
		}
		service, err := approvalceremony.NewEffectDispositionService(
			store, approvalceremony.ContextConsumerIdentityProvider{}, releaseStore, commandVerifier, approvalSigner,
		)
		if err != nil {
			return nil, fmt.Errorf("initialize effect disposition service: %w", err)
		}
		if config.DispositionEnabled {
			disposition = service
			dispositionValidator = mcppkg.NewJWKSValidator(mcppkg.JWKSConfig{
				JWKSURL: config.JWKSURL, Issuer: config.Issuer, Audience: config.Audience,
				Resource: config.Resource, Scopes: []string{config.DispositionScope},
			})
		}
		if config.ReconciliationCandidatesEnabled {
			reconciliationCandidates = service
			reconciliationValidator = mcppkg.NewJWKSValidator(mcppkg.JWKSConfig{
				JWKSURL: config.JWKSURL, Issuer: config.Issuer, Audience: config.Audience,
				Resource: config.ReconciliationCandidatesResource, Scopes: []string{config.ReconciliationCandidatesScope},
			})
		}
	}
	return &approvalConsumptionRuntime{
		consumer: consumer, admitter: admitter, validator: validator, dispatchValidator: dispatchValidator,
		controller: controller, controlValidator: controlValidator,
		disposition: disposition, dispositionValidator: dispositionValidator,
		reconciliationCandidates: reconciliationCandidates, reconciliationValidator: reconciliationValidator,
		stops: stops, audience: config.Audience,
		maxTokenTTL: config.MaxTokenTTL,
	}, nil
}

type approvalCeremonySourceClient struct {
	transport *generatedSpecApprovalSourceClient
	audience  string
}

type approvalCeremonyBindingSourceRequest struct {
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	BindingRef  string `json:"binding_ref"`
}

type approvalCeremonyAuthoritySourceRequest struct {
	TenantID              string `json:"tenant_id"`
	WorkspaceID           string `json:"workspace_id"`
	AuthoritySource       string `json:"authority_source"`
	AuthorityVersion      string `json:"authority_version"`
	AuthoritySnapshotHash string `json:"authority_snapshot_hash"`
}

func newApprovalCeremonySourceClient(rawURL, token string, client *http.Client, audience string, allowInsecure bool) (*approvalCeremonySourceClient, error) {
	if !validWorkloadClaim(audience) {
		return nil, errors.New("approval ceremony source audience is invalid")
	}
	transport, err := newGeneratedSpecApprovalSourceClient(rawURL, token, client, allowInsecure)
	if err != nil {
		return nil, fmt.Errorf("initialize approval ceremony source: %w", err)
	}
	return &approvalCeremonySourceClient{transport: transport, audience: audience}, nil
}

func (client *approvalCeremonySourceClient) LoadApprovalBinding(ctx context.Context, tenantID, workspaceID, bindingRef string) (approvalceremony.ChallengeSpec, error) {
	var binding approvalceremony.ChallengeSpec
	if client == nil || client.transport == nil {
		return approvalceremony.ChallengeSpec{}, approvalceremony.ErrBindingUnavailable
	}
	err := client.transport.post(ctx, approvalCeremonyBindingSourcePath, approvalCeremonyBindingSourceRequest{
		TenantID: tenantID, WorkspaceID: workspaceID, BindingRef: bindingRef,
	}, &binding)
	if err != nil {
		return approvalceremony.ChallengeSpec{}, fmt.Errorf("%w: %v", approvalceremony.ErrBindingUnavailable, err)
	}
	if binding.TenantID != tenantID || binding.WorkspaceID != workspaceID || binding.BindingRef != bindingRef ||
		binding.Audience != client.audience || binding.Validate() != nil {
		return approvalceremony.ChallengeSpec{}, fmt.Errorf("%w: source binding mismatch", approvalceremony.ErrBindingUnavailable)
	}
	return binding, nil
}

func (client *approvalCeremonySourceClient) LoadApprovalAuthority(ctx context.Context, tenantID, workspaceID, source, version, snapshotHash string) (approvalverify.TrustStore, error) {
	var snapshot approvalceremony.AuthoritySnapshot
	if client == nil || client.transport == nil {
		return approvalverify.TrustStore{}, approvalceremony.ErrAuthorityUnavailable
	}
	err := client.transport.post(ctx, approvalCeremonyAuthoritySourcePath, approvalCeremonyAuthoritySourceRequest{
		TenantID: tenantID, WorkspaceID: workspaceID, AuthoritySource: source,
		AuthorityVersion: version, AuthoritySnapshotHash: snapshotHash,
	}, &snapshot)
	if err != nil {
		return approvalverify.TrustStore{}, fmt.Errorf("%w: %v", approvalceremony.ErrAuthorityUnavailable, err)
	}
	store, err := snapshot.TrustStore()
	if err != nil || store.AuthoritySource != source || store.AuthorityVersion != version ||
		store.AuthoritySnapshotHash != snapshotHash {
		return approvalverify.TrustStore{}, fmt.Errorf("%w: source authority mismatch", approvalceremony.ErrAuthorityUnavailable)
	}
	return store, nil
}

var _ approvalceremony.BindingProvider = (*approvalCeremonySourceClient)(nil)
var _ approvalceremony.AuthorityProvider = (*approvalCeremonySourceClient)(nil)

func configuredEffectDispositionAuthorities(audience string) (
	[]approvalceremony.TrustedEffectDispositionCommandKey,
	string,
	[]connectorregistry.TrustedReleaseAuthorityKey,
	error,
) {
	commandKeyring, err := decodeRuntimeAuthorityKeyring(
		os.Getenv(effectDispositionCommandKeyringEnv), effectDispositionCommandKeyringV1,
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("decode effect disposition command keyring: %w", err)
	}
	releaseKeyring, err := decodeRuntimeAuthorityKeyring(
		os.Getenv(connectorReleaseAuthorityKeyringEnv), connectorReleaseAuthorityKeyringV1,
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("decode connector release authority keyring: %w", err)
	}
	commandKeys := make([]approvalceremony.TrustedEffectDispositionCommandKey, 0, len(commandKeyring.Keys))
	for _, key := range commandKeyring.Keys {
		if key.Audience != audience {
			return nil, "", nil, errors.New("effect disposition command key audience must match the workload audience")
		}
		commandKeys = append(commandKeys, approvalceremony.TrustedEffectDispositionCommandKey{
			AuthorityID: key.AuthorityID, SigningKeyRef: key.SigningKeyRef, Audience: key.Audience,
			PublicKey: ed25519.PublicKey(decodeRuntimePublicKey(key.PublicKey)), Enabled: key.Enabled,
			NotBefore: key.NotBefore, NotAfter: key.NotAfter,
		})
	}
	releaseAuthorityID := releaseKeyring.Keys[0].AuthorityID
	releaseKeys := make([]connectorregistry.TrustedReleaseAuthorityKey, 0, len(releaseKeyring.Keys))
	for _, key := range releaseKeyring.Keys {
		if key.Audience != "" || key.AuthorityID != releaseAuthorityID {
			return nil, "", nil, errors.New("connector release authority keyring must contain one authority and no audiences")
		}
		releaseKeys = append(releaseKeys, connectorregistry.TrustedReleaseAuthorityKey{
			AuthorityID: key.AuthorityID, SigningKeyRef: key.SigningKeyRef,
			PublicKey: ed25519.PublicKey(decodeRuntimePublicKey(key.PublicKey)), Enabled: key.Enabled,
			NotBefore: key.NotBefore, NotAfter: key.NotAfter,
		})
	}
	return commandKeys, releaseAuthorityID, releaseKeys, nil
}

func decodeRuntimeAuthorityKeyring(raw, version string) (runtimeAuthorityKeyring, error) {
	var keyring runtimeAuthorityKeyring
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&keyring); err != nil {
		return runtimeAuthorityKeyring{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return runtimeAuthorityKeyring{}, errors.New("keyring must contain exactly one JSON object")
	}
	if keyring.KeyringVersion != version || len(keyring.Keys) == 0 || len(keyring.Keys) > 64 {
		return runtimeAuthorityKeyring{}, errors.New("keyring version or size is invalid")
	}
	enabled := false
	for _, key := range keyring.Keys {
		if !validWorkloadClaim(key.AuthorityID) || !validWorkloadClaim(key.SigningKeyRef) ||
			(key.Audience != "" && !validWorkloadClaim(key.Audience)) ||
			len(decodeRuntimePublicKey(key.PublicKey)) != ed25519.PublicKeySize ||
			key.NotBefore.IsZero() || key.NotAfter.IsZero() || key.NotBefore.Location() != time.UTC ||
			key.NotAfter.Location() != time.UTC || !key.NotAfter.After(key.NotBefore) {
			return runtimeAuthorityKeyring{}, errors.New("keyring entry is invalid")
		}
		enabled = enabled || key.Enabled
	}
	if !enabled {
		return runtimeAuthorityKeyring{}, errors.New("keyring must contain an enabled key")
	}
	return keyring, nil
}

func decodeRuntimePublicKey(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return nil
	}
	return decoded
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
