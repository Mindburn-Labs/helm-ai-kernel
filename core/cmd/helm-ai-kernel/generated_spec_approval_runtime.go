package main

// quantum_posture: this runtime wires classical Ed25519 approval envelopes,
// SHA-256 source commitments, TLS, and RS256 workload JWTs. It makes no
// post-quantum claim.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapproval"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapprovalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

const (
	generatedSpecApprovalEnabledEnv               = "HELM_GENERATED_SPEC_APPROVAL_ENABLED"
	generatedSpecApprovalSourceURLEnv             = "HELM_GENERATED_SPEC_APPROVAL_SOURCE_URL"
	generatedSpecApprovalSourceTokenEnv           = "HELM_GENERATED_SPEC_APPROVAL_SOURCE_TOKEN"
	generatedSpecApprovalJWKSURLEnv               = "HELM_GENERATED_SPEC_APPROVAL_JWKS_URL"
	generatedSpecApprovalOutboundCAFileEnv        = "HELM_GENERATED_SPEC_APPROVAL_OUTBOUND_CA_BUNDLE_FILE"
	generatedSpecApprovalIssuerEnv                = "HELM_GENERATED_SPEC_APPROVAL_ISSUER"
	generatedSpecApprovalAudienceEnv              = "HELM_GENERATED_SPEC_APPROVAL_AUDIENCE"
	generatedSpecApprovalResourceEnv              = "HELM_GENERATED_SPEC_APPROVAL_RESOURCE"
	generatedSpecApprovalControlScopeEnv          = "HELM_GENERATED_SPEC_APPROVAL_CONTROL_SCOPE"
	generatedSpecApprovalConsumerScopeEnv         = "HELM_GENERATED_SPEC_APPROVAL_CONSUMER_SCOPE"
	generatedSpecApprovalMaxTokenTTLEnv           = "HELM_GENERATED_SPEC_APPROVAL_MAX_TOKEN_TTL"
	generatedSpecApprovalMinHoldDurationEnv       = "HELM_GENERATED_SPEC_APPROVAL_MIN_HOLD_DURATION"
	generatedSpecApprovalChallengeTTLEnv          = "HELM_GENERATED_SPEC_APPROVAL_CHALLENGE_TTL"
	generatedSpecApprovalMaxChallengeLifetimeEnv  = "HELM_GENERATED_SPEC_APPROVAL_MAX_CHALLENGE_LIFETIME"
	generatedSpecApprovalGrantTTLEnv              = "HELM_GENERATED_SPEC_APPROVAL_GRANT_TTL"
	generatedSpecApprovalMaxAssertionsEnv         = "HELM_GENERATED_SPEC_APPROVAL_MAX_ASSERTIONS"
	generatedSpecApprovalServerIdentityEnv        = "HELM_GENERATED_SPEC_APPROVAL_SERVER_IDENTITY"
	generatedSpecApprovalSigningKeyRefEnv         = "HELM_GENERATED_SPEC_APPROVAL_SIGNING_KEY_REF"
	generatedSpecApprovalKernelTrustRootIDEnv     = "HELM_GENERATED_SPEC_APPROVAL_KERNEL_TRUST_ROOT_ID"
	generatedSpecApprovalBindingSourcePath        = "/internal/v1/generated-spec-approval/source/binding"
	generatedSpecApprovalAuthoritySourcePath      = "/internal/v1/generated-spec-approval/source/authority"
	defaultGeneratedSpecApprovalControlScope      = "helm.generated-spec.approval.control"
	defaultGeneratedSpecApprovalConsumerScope     = "helm.generated-spec.approval.consume"
	defaultGeneratedSpecApprovalMaxTokenTTL       = 5 * time.Minute
	maximumGeneratedSpecApprovalMaxTokenTTL       = 15 * time.Minute
	defaultGeneratedSpecApprovalMinHoldDuration   = 5 * time.Second
	defaultGeneratedSpecApprovalChallengeTTL      = 10 * time.Minute
	defaultGeneratedSpecApprovalChallengeLifetime = 30 * time.Minute
	defaultGeneratedSpecApprovalGrantTTL          = 2 * time.Minute
	defaultGeneratedSpecApprovalMaxAssertions     = 8
	generatedSpecApprovalMaximumSourceResponse    = 512 << 10
	generatedSpecApprovalSourceTimeout            = 10 * time.Second
)

type generatedSpecApprovalRuntimeConfig struct {
	SourceURL            string
	SourceToken          string
	JWKSURL              string
	OutboundCAFile       string
	Issuer               string
	Audience             string
	Resource             string
	ControlScope         string
	ConsumerScope        string
	MaxTokenTTL          time.Duration
	MinHoldDuration      time.Duration
	ChallengeTTL         time.Duration
	MaxChallengeLifetime time.Duration
	GrantTTL             time.Duration
	MaxAssertions        int
	ServerIdentity       string
	SigningKeyRef        string
	KernelTrustRootID    string
}

type generatedSpecApprovalRuntime struct {
	service           *generatedspecapprovalceremony.Service
	controlValidator  approvalConsumerTokenValidator
	consumerValidator approvalConsumerTokenValidator
	audience          string
	maxTokenTTL       time.Duration
}

func generatedSpecApprovalRuntimeConfigFromEnv() (generatedSpecApprovalRuntimeConfig, bool, error) {
	if !envBool(generatedSpecApprovalEnabledEnv) {
		return generatedSpecApprovalRuntimeConfig{}, false, nil
	}
	cfg := generatedSpecApprovalRuntimeConfig{
		SourceURL: strings.TrimSpace(os.Getenv(generatedSpecApprovalSourceURLEnv)), SourceToken: strings.TrimSpace(os.Getenv(generatedSpecApprovalSourceTokenEnv)),
		JWKSURL: strings.TrimSpace(os.Getenv(generatedSpecApprovalJWKSURLEnv)), OutboundCAFile: strings.TrimSpace(os.Getenv(generatedSpecApprovalOutboundCAFileEnv)),
		Issuer:   strings.TrimSpace(os.Getenv(generatedSpecApprovalIssuerEnv)),
		Audience: strings.TrimSpace(os.Getenv(generatedSpecApprovalAudienceEnv)), Resource: strings.TrimSpace(os.Getenv(generatedSpecApprovalResourceEnv)),
		ControlScope: strings.TrimSpace(os.Getenv(generatedSpecApprovalControlScopeEnv)), ConsumerScope: strings.TrimSpace(os.Getenv(generatedSpecApprovalConsumerScopeEnv)),
		MaxTokenTTL: defaultGeneratedSpecApprovalMaxTokenTTL, MinHoldDuration: defaultGeneratedSpecApprovalMinHoldDuration,
		ChallengeTTL: defaultGeneratedSpecApprovalChallengeTTL, MaxChallengeLifetime: defaultGeneratedSpecApprovalChallengeLifetime,
		GrantTTL: defaultGeneratedSpecApprovalGrantTTL, MaxAssertions: defaultGeneratedSpecApprovalMaxAssertions,
		ServerIdentity:    strings.TrimSpace(os.Getenv(generatedSpecApprovalServerIdentityEnv)),
		SigningKeyRef:     strings.TrimSpace(os.Getenv(generatedSpecApprovalSigningKeyRefEnv)),
		KernelTrustRootID: strings.TrimSpace(os.Getenv(generatedSpecApprovalKernelTrustRootIDEnv)),
	}
	if cfg.ControlScope == "" {
		cfg.ControlScope = defaultGeneratedSpecApprovalControlScope
	}
	if cfg.ConsumerScope == "" {
		cfg.ConsumerScope = defaultGeneratedSpecApprovalConsumerScope
	}
	var err error
	for name, target := range map[string]*time.Duration{
		generatedSpecApprovalMaxTokenTTLEnv: &cfg.MaxTokenTTL, generatedSpecApprovalMinHoldDurationEnv: &cfg.MinHoldDuration,
		generatedSpecApprovalChallengeTTLEnv: &cfg.ChallengeTTL, generatedSpecApprovalMaxChallengeLifetimeEnv: &cfg.MaxChallengeLifetime,
		generatedSpecApprovalGrantTTLEnv: &cfg.GrantTTL,
	} {
		if raw := strings.TrimSpace(os.Getenv(name)); raw != "" {
			*target, err = time.ParseDuration(raw)
			if err != nil {
				return generatedSpecApprovalRuntimeConfig{}, true, fmt.Errorf("parse %s: %w", name, err)
			}
		}
	}
	if raw := strings.TrimSpace(os.Getenv(generatedSpecApprovalMaxAssertionsEnv)); raw != "" {
		cfg.MaxAssertions = envInt(generatedSpecApprovalMaxAssertionsEnv, -1)
	}
	if err := validateGeneratedSpecApprovalRuntimeConfig(cfg, false); err != nil {
		return generatedSpecApprovalRuntimeConfig{}, true, err
	}
	return cfg, true, nil
}

func validateGeneratedSpecApprovalRuntimeConfig(cfg generatedSpecApprovalRuntimeConfig, allowInsecureSource bool) error {
	for name, value := range map[string]string{
		generatedSpecApprovalSourceTokenEnv: cfg.SourceToken, generatedSpecApprovalIssuerEnv: cfg.Issuer,
		generatedSpecApprovalAudienceEnv: cfg.Audience, generatedSpecApprovalResourceEnv: cfg.Resource,
		generatedSpecApprovalControlScopeEnv: cfg.ControlScope, generatedSpecApprovalConsumerScopeEnv: cfg.ConsumerScope,
		generatedSpecApprovalServerIdentityEnv: cfg.ServerIdentity, generatedSpecApprovalSigningKeyRefEnv: cfg.SigningKeyRef,
		generatedSpecApprovalKernelTrustRootIDEnv: cfg.KernelTrustRootID,
	} {
		if !validWorkloadClaim(value) {
			return fmt.Errorf("%s is required and must be a non-whitespace token", name)
		}
	}
	if cfg.Audience != contracts.GeneratedSpecApprovalAudienceV1 || cfg.ControlScope == cfg.ConsumerScope {
		return errors.New("generated spec approval audience or workload scopes are invalid")
	}
	for name, raw := range map[string]string{generatedSpecApprovalSourceURLEnv: cfg.SourceURL, generatedSpecApprovalJWKSURLEnv: cfg.JWKSURL, generatedSpecApprovalResourceEnv: cfg.Resource} {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
			(parsed.Scheme != "https" && !(allowInsecureSource && name == generatedSpecApprovalSourceURLEnv && parsed.Scheme == "http")) {
			return fmt.Errorf("%s must be an absolute HTTPS URL", name)
		}
	}
	if cfg.MaxTokenTTL <= 0 || cfg.MaxTokenTTL > maximumGeneratedSpecApprovalMaxTokenTTL || cfg.MinHoldDuration <= 0 ||
		cfg.ChallengeTTL <= 0 || cfg.MaxChallengeLifetime <= cfg.MinHoldDuration ||
		cfg.ChallengeTTL > cfg.MaxChallengeLifetime-cfg.MinHoldDuration || cfg.GrantTTL <= 0 || cfg.MaxAssertions <= 0 || cfg.MaxAssertions > 64 {
		return errors.New("generated spec approval runtime limits are invalid")
	}
	return nil
}

func newGeneratedSpecApprovalRuntime(ctx context.Context, db *sql.DB, databaseMode string, signer helmcrypto.Signer, stops *kernel.ScopedStopStore) (*generatedSpecApprovalRuntime, error) {
	cfg, enabled, err := generatedSpecApprovalRuntimeConfigFromEnv()
	if err != nil || !enabled {
		return nil, err
	}
	if databaseMode != "postgres" || db == nil || stops == nil {
		return nil, errors.New("generated spec approval requires durable PostgreSQL and emergency-stop scope coordination")
	}
	approvalSigner, err := classicalApprovalSigner(signer)
	if err != nil {
		return nil, err
	}
	verifier, err := generatedspecapproval.NewEd25519Verifier(approvalSigner.PublicKeyBytes(), cfg.SigningKeyRef, cfg.KernelTrustRootID)
	if err != nil {
		return nil, fmt.Errorf("initialize generated spec approval verifier: %w", err)
	}
	store := generatedspecapprovalceremony.NewPostgresStore(db, verifier)
	if err := store.Init(ctx); err != nil {
		return nil, fmt.Errorf("initialize generated spec approval ceremony store: %w", err)
	}
	outboundClient, err := newGeneratedSpecApprovalOutboundClient(cfg.OutboundCAFile)
	if err != nil {
		return nil, err
	}
	source, err := newGeneratedSpecApprovalSourceClient(cfg.SourceURL, cfg.SourceToken, outboundClient, false)
	if err != nil {
		return nil, err
	}
	identity := generatedSpecApprovalContextIdentityProvider{}
	service, err := generatedspecapprovalceremony.NewService(
		store, source, source, identity, identity, approvalSigner, verifier,
		generatedspecapprovalceremony.ServiceConfig{
			MinHoldDuration: cfg.MinHoldDuration, ChallengeTTL: cfg.ChallengeTTL,
			MaxChallengeLifetime: cfg.MaxChallengeLifetime, GrantTTL: cfg.GrantTTL,
			MaxAssertions: cfg.MaxAssertions, ServerIdentity: cfg.ServerIdentity,
			KernelTrustRootID: cfg.KernelTrustRootID, SigningKeyRef: cfg.SigningKeyRef,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("initialize generated spec approval service: %w", err)
	}
	validatorConfig := mcppkg.JWKSConfig{JWKSURL: cfg.JWKSURL, Issuer: cfg.Issuer, Audience: cfg.Audience, Resource: cfg.Resource, HTTPClient: outboundClient}
	validatorConfig.Scopes = []string{cfg.ControlScope}
	controlValidator := mcppkg.NewJWKSValidator(validatorConfig)
	validatorConfig.Scopes = []string{cfg.ConsumerScope}
	consumerValidator := mcppkg.NewJWKSValidator(validatorConfig)
	return &generatedSpecApprovalRuntime{
		service: service, controlValidator: controlValidator, consumerValidator: consumerValidator,
		audience: cfg.Audience, maxTokenTTL: cfg.MaxTokenTTL,
	}, nil
}

func newGeneratedSpecApprovalOutboundClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return nil, nil
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read generated spec approval outbound CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("generated spec approval outbound CA is invalid")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &http.Client{Transport: transport, Timeout: generatedSpecApprovalSourceTimeout}, nil
}

type generatedSpecApprovalSourceClient struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
}

type generatedSpecApprovalBindingSourceRequest struct {
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	BindingRef  string `json:"binding_ref"`
}

type generatedSpecApprovalAuthoritySourceRequest struct {
	TenantID              string `json:"tenant_id"`
	WorkspaceID           string `json:"workspace_id"`
	AuthoritySource       string `json:"authority_source"`
	AuthorityVersion      string `json:"authority_version"`
	AuthoritySnapshotHash string `json:"authority_snapshot_hash"`
}

func newGeneratedSpecApprovalSourceClient(rawURL, token string, client *http.Client, allowInsecure bool) (*generatedSpecApprovalSourceClient, error) {
	baseURL, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || baseURL.Host == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" ||
		(baseURL.Scheme != "https" && !(allowInsecure && baseURL.Scheme == "http")) {
		return nil, errors.New("generated spec approval source URL must be absolute HTTPS")
	}
	if !validWorkloadClaim(token) {
		return nil, errors.New("generated spec approval source token is invalid")
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/")
	if client == nil {
		client = &http.Client{Timeout: generatedSpecApprovalSourceTimeout}
	}
	copy := *client
	if copy.Timeout <= 0 {
		copy.Timeout = generatedSpecApprovalSourceTimeout
	}
	if copy.Timeout > 30*time.Second {
		return nil, errors.New("generated spec approval source timeout must not exceed 30 seconds")
	}
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &generatedSpecApprovalSourceClient{baseURL: baseURL, token: token, httpClient: &copy}, nil
}

func (client *generatedSpecApprovalSourceClient) LoadGeneratedSpecApprovalBinding(ctx context.Context, tenantID, workspaceID, bindingRef string) (generatedspecapprovalceremony.Binding, error) {
	var binding generatedspecapprovalceremony.Binding
	err := client.post(ctx, generatedSpecApprovalBindingSourcePath, generatedSpecApprovalBindingSourceRequest{
		TenantID: tenantID, WorkspaceID: workspaceID, BindingRef: bindingRef,
	}, &binding)
	if err != nil {
		return generatedspecapprovalceremony.Binding{}, fmt.Errorf("%w: %v", generatedspecapprovalceremony.ErrBindingUnavailable, err)
	}
	if binding.TenantID != tenantID || binding.WorkspaceID != workspaceID || binding.BindingRef != bindingRef || binding.Validate() != nil {
		return generatedspecapprovalceremony.Binding{}, fmt.Errorf("%w: source binding mismatch", generatedspecapprovalceremony.ErrBindingUnavailable)
	}
	return binding, nil
}

func (client *generatedSpecApprovalSourceClient) LoadGeneratedSpecApprovalAuthority(ctx context.Context, tenantID, workspaceID, source, version, snapshotHash string) (approvalverify.TrustStore, error) {
	var snapshot generatedspecapprovalceremony.AuthoritySnapshot
	err := client.post(ctx, generatedSpecApprovalAuthoritySourcePath, generatedSpecApprovalAuthoritySourceRequest{
		TenantID: tenantID, WorkspaceID: workspaceID, AuthoritySource: source,
		AuthorityVersion: version, AuthoritySnapshotHash: snapshotHash,
	}, &snapshot)
	if err != nil {
		return approvalverify.TrustStore{}, fmt.Errorf("%w: %v", generatedspecapprovalceremony.ErrAuthorityUnavailable, err)
	}
	store, err := snapshot.TrustStore()
	if err != nil || store.AuthoritySource != source || store.AuthorityVersion != version || store.AuthoritySnapshotHash != snapshotHash {
		return approvalverify.TrustStore{}, fmt.Errorf("%w: source authority mismatch", generatedspecapprovalceremony.ErrAuthorityUnavailable)
	}
	return store, nil
}

func (client *generatedSpecApprovalSourceClient) post(ctx context.Context, path string, request, response any) error {
	if client == nil || client.baseURL == nil || client.httpClient == nil {
		return errors.New("source client is unavailable")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	endpoint := *client.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+client.token)
	httpResponse, err := client.httpClient.Do(httpRequest)
	if err != nil {
		return err
	}
	defer func() { _ = httpResponse.Body.Close() }()
	if httpResponse.StatusCode < http.StatusOK || httpResponse.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(httpResponse.Body, 4096))
		return fmt.Errorf("source returned HTTP %d", httpResponse.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(httpResponse.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("source response content type is invalid")
	}
	limited := io.LimitReader(httpResponse.Body, generatedSpecApprovalMaximumSourceResponse+1)
	raw, err := io.ReadAll(limited)
	if err != nil || len(raw) > generatedSpecApprovalMaximumSourceResponse {
		return errors.New("source response is unavailable or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(response); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("source response must contain one JSON object")
	}
	return nil
}

var _ generatedspecapprovalceremony.BindingProvider = (*generatedSpecApprovalSourceClient)(nil)
var _ generatedspecapprovalceremony.AuthorityProvider = (*generatedSpecApprovalSourceClient)(nil)
