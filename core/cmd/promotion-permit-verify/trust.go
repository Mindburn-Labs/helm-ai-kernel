package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	connectorregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry/connectors"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

const trustedInputsSchemaV1 = "helm.production-promotion-trusted-inputs/v1"

var trustedSHA256Pattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type trustedInputs struct {
	Schema                  string                                      `json:"schema"`
	ObservedAt              time.Time                                   `json:"observed_at"`
	MaximumPermitTTL        string                                      `json:"maximum_permit_ttl"`
	ExpectedPolicyEpoch     string                                      `json:"expected_policy_epoch"`
	EmergencyFence          emergencyFence                              `json:"emergency_fence"`
	VerdictTrust            trustKey                                    `json:"verdict_trust"`
	ApprovalTrust           trustKey                                    `json:"approval_trust"`
	ApprovalConsumptionRef  string                                      `json:"approval_consumption_ref"`
	ApprovalAuthority       contracts.LaunchEffectApprovalAuthority     `json:"approval_authority"`
	ConnectorReleaseTrust   connectorReleaseTrust                       `json:"connector_release_trust"`
	CurrentConnectorRelease contracts.ConnectorReleaseAuthorityEnvelope `json:"current_connector_release"`
	Permit                  permitBinding                               `json:"permit"`
	Dependency              artifactBinding                             `json:"dependency"`
	RouteBinding            contracts.LaunchRouteBinding                `json:"route_binding"`
	RouteArtifacts          routeArtifacts                              `json:"route_artifacts"`
}

type trustKey struct {
	KernelTrustRootID string `json:"kernel_trust_root_id"`
	SigningKeyRef     string `json:"signing_key_ref"`
	PublicKey         string `json:"public_key"`
}

type connectorReleaseTrust struct {
	AuthorityID   string    `json:"authority_id"`
	SigningKeyRef string    `json:"signing_key_ref"`
	PublicKey     string    `json:"public_key"`
	Enabled       bool      `json:"enabled"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
}

type emergencyFence struct {
	TenantID       string `json:"tenant_id"`
	WorkspaceID    string `json:"workspace_id"`
	EffectiveEpoch int64  `json:"effective_epoch"`
	Active         bool   `json:"active"`
}

type artifactBinding struct {
	Ref  string `json:"ref"`
	Hash string `json:"hash"`
}

type permitBinding struct {
	EffectPermitRef         string    `json:"effect_permit_ref"`
	EffectPermitHash        string    `json:"effect_permit_hash"`
	PermitNonce             string    `json:"permit_nonce"`
	ProofSessionRef         string    `json:"proof_session_ref"`
	EvidenceReservationRef  string    `json:"evidence_reservation_ref"`
	PermitIssuedAt          time.Time `json:"permit_issued_at"`
	PermitExpiry            time.Time `json:"permit_expiry"`
	KernelVerdictRef        string    `json:"kernel_verdict_ref"`
	KernelVerdictHash       string    `json:"kernel_verdict_hash"`
	KernelVerdictIssuedAt   time.Time `json:"kernel_verdict_issued_at"`
	KernelVerdictExpiry     time.Time `json:"kernel_verdict_expiry"`
	EffectID                string    `json:"effect_id"`
	TenantID                string    `json:"tenant_id"`
	WorkspaceID             string    `json:"workspace_id"`
	MissionID               string    `json:"mission_id"`
	Principal               string    `json:"principal"`
	Audience                string    `json:"audience"`
	KernelTrustRootID       string    `json:"kernel_trust_root_id"`
	EffectOrdinal           int       `json:"effect_ordinal"`
	InputSchemaHash         string    `json:"input_schema_hash"`
	InputHash               string    `json:"input_hash"`
	IdempotencyKey          string    `json:"idempotency_key"`
	PlanHash                string    `json:"plan_hash"`
	ApprovalArtifactRef     string    `json:"approval_artifact_ref"`
	ApprovalArtifactHash    string    `json:"approval_artifact_hash"`
	ApprovalConsumptionRef  string    `json:"approval_consumption_ref"`
	ApprovalConsumptionHash string    `json:"approval_consumption_hash"`
	DispatchAdmissionRef    string    `json:"dispatch_admission_ref"`
	DispatchAdmissionHash   string    `json:"dispatch_admission_hash"`
	DependencySetRef        string    `json:"dependency_set_ref"`
	DependencySetHash       string    `json:"dependency_set_hash"`
	ConnectorID             string    `json:"connector_id"`
	ConnectorContractHash   string    `json:"connector_contract_hash"`
	ConnectorAuthorityRef   string    `json:"connector_authority_ref"`
	ConnectorAuthorityHash  string    `json:"connector_authority_hash"`
	ActionURN               string    `json:"action_urn"`
	RequestBodyHash         string    `json:"request_body_hash"`
	ArgsC14NHash            string    `json:"args_c14n_hash"`
	PolicyEpoch             string    `json:"policy_epoch"`
	EmergencyFenceEpoch     int64     `json:"emergency_fence_epoch"`
	DispatchDeadline        time.Time `json:"dispatch_deadline"`
	SingleUse               bool      `json:"single_use"`
}

type routeArtifacts struct {
	RepositoryAnalyses     map[string]contracts.LaunchRepositoryAnalysis          `json:"repository_analyses"`
	WorkloadGraphs         map[string]contracts.LaunchWorkloadGraph               `json:"workload_graphs"`
	ProviderProfiles       map[string]contracts.LaunchProviderCapabilityProfile   `json:"provider_profiles"`
	ProviderCertifications map[string]contracts.LaunchProviderCertificationRecord `json:"provider_certifications"`
	ConstraintSets         map[string]contracts.LaunchConstraintSet               `json:"constraint_sets"`
	RouteQuotes            map[string]contracts.LaunchRouteQuote                  `json:"route_quotes"`
	CommercialEvidence     map[string]contracts.LaunchCommercialEvidence          `json:"commercial_evidence"`
	FXSnapshots            map[string]contracts.LaunchFXSnapshot                  `json:"fx_snapshots"`
	TaxSnapshots           map[string]contracts.LaunchTaxSnapshot                 `json:"tax_snapshots"`
	OfferSnapshots         map[string]contracts.LaunchOfferSnapshot               `json:"offer_snapshots"`
	ResourceGraphs         map[string]contracts.LaunchResourceGraph               `json:"resource_graphs"`
	ProviderPayloadSets    map[string]contracts.LaunchProviderPayloadSet          `json:"provider_payload_sets"`
	GeneratedSpecHashes    map[string]string                                      `json:"generated_spec_hashes"`
	CertificationKeys      map[string]string                                      `json:"certification_keys"`
	CurrentCertifications  map[string]string                                      `json:"current_certifications"`
}

type staticRouteResolver struct {
	artifacts         routeArtifacts
	certificationKeys map[string]ed25519.PublicKey
}

func (inputs trustedInputs) launchContext(envelope contracts.LaunchEffectAuthorizationEnvelope, schemaBytes []byte) (contracts.LaunchEffectEnvelopeVerificationContext, error) {
	if inputs.Schema != trustedInputsSchemaV1 {
		return contracts.LaunchEffectEnvelopeVerificationContext{}, fmt.Errorf("trusted inputs schema must equal %q", trustedInputsSchemaV1)
	}
	if inputs.ObservedAt.IsZero() || inputs.ObservedAt.Location() != time.UTC {
		return contracts.LaunchEffectEnvelopeVerificationContext{}, errors.New("trusted inputs observed_at must be UTC")
	}
	maximumTTL, err := time.ParseDuration(inputs.MaximumPermitTTL)
	if err != nil || maximumTTL <= 0 {
		return contracts.LaunchEffectEnvelopeVerificationContext{}, errors.New("trusted inputs maximum_permit_ttl must be positive")
	}
	if !boundedToken(inputs.ExpectedPolicyEpoch) || !boundedToken(inputs.ApprovalConsumptionRef) {
		return contracts.LaunchEffectEnvelopeVerificationContext{}, errors.New("trusted inputs policy epoch or approval consumption ref is invalid")
	}
	verdictKey, err := parsePublicKey(inputs.VerdictTrust.PublicKey)
	if err != nil {
		return contracts.LaunchEffectEnvelopeVerificationContext{}, fmt.Errorf("trusted verdict key: %w", err)
	}
	approvalKey, err := parsePublicKey(inputs.ApprovalTrust.PublicKey)
	if err != nil {
		return contracts.LaunchEffectEnvelopeVerificationContext{}, fmt.Errorf("trusted approval key: %w", err)
	}
	approvalVerifier, err := approvalceremony.NewEd25519GrantSignatureVerifier(approvalKey, inputs.ApprovalTrust.SigningKeyRef, inputs.ApprovalTrust.KernelTrustRootID)
	if err != nil {
		return contracts.LaunchEffectEnvelopeVerificationContext{}, err
	}
	releaseKey, err := inputs.ConnectorReleaseTrust.key()
	if err != nil {
		return contracts.LaunchEffectEnvelopeVerificationContext{}, err
	}
	releaseVerifier, err := connectorregistry.NewEd25519ReleaseAuthorityVerifier(inputs.ConnectorReleaseTrust.AuthorityID, []connectorregistry.TrustedReleaseAuthorityKey{releaseKey})
	if err != nil {
		return contracts.LaunchEffectEnvelopeVerificationContext{}, err
	}
	routeResolver, err := newStaticRouteResolver(inputs.RouteArtifacts)
	if err != nil {
		return contracts.LaunchEffectEnvelopeVerificationContext{}, err
	}
	if err := inputs.Permit.validate(); err != nil {
		return contracts.LaunchEffectEnvelopeVerificationContext{}, err
	}
	if !boundedToken(inputs.Dependency.Ref) || !trustedSHA256Pattern.MatchString(inputs.Dependency.Hash) {
		return contracts.LaunchEffectEnvelopeVerificationContext{}, errors.New("trusted dependency binding is invalid")
	}

	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	const schemaURL = "https://helm.schemas.local/production-promotion/input.schema.json"
	if err := compiler.AddResource(schemaURL, bytes.NewReader(schemaBytes)); err != nil {
		return contracts.LaunchEffectEnvelopeVerificationContext{}, fmt.Errorf("load launch input schema: %w", err)
	}
	compiledSchema, err := compiler.Compile(schemaURL)
	if err != nil {
		return contracts.LaunchEffectEnvelopeVerificationContext{}, fmt.Errorf("compile launch input schema: %w", err)
	}

	approval := inputs.ApprovalAuthority
	currentRelease := inputs.CurrentConnectorRelease
	permit := inputs.Permit.contract()
	route := inputs.RouteBinding
	fence := inputs.EmergencyFence
	return contracts.LaunchEffectEnvelopeVerificationContext{
		Now: inputs.ObservedAt,
		ResolveInputSchema: func(ref string) ([]byte, error) {
			if ref != envelope.InputSchemaRef {
				return nil, errors.New("input schema ref is not trusted")
			}
			return append([]byte(nil), schemaBytes...), nil
		},
		ValidateInput: func(ref, hash string, candidate map[string]any) error {
			if ref != envelope.InputSchemaRef || hash != envelope.InputSchemaHash {
				return errors.New("input schema identity is not trusted")
			}
			return compiledSchema.Validate(candidate)
		},
		ResolveRouteBinding: func(ref string) (contracts.LaunchRouteBinding, error) {
			if ref != route.RouteID {
				return contracts.LaunchRouteBinding{}, errors.New("route binding is not trusted")
			}
			return route, nil
		},
		RouteArtifacts: routeResolver,
		ResolveApprovalAuthority: func(grantRef, grantHash, consumptionRef, consumptionHash string) (contracts.LaunchEffectApprovalAuthority, error) {
			if grantRef != approval.Grant.GrantID || grantHash != approval.Grant.GrantHash ||
				consumptionRef != inputs.ApprovalConsumptionRef || consumptionHash != approval.Consumption.ConsumptionHash {
				return contracts.LaunchEffectApprovalAuthority{}, errors.New("approval authority is not trusted")
			}
			return approval, nil
		},
		VerifyApprovalAuthority: func(candidate contracts.LaunchEffectApprovalAuthority) error {
			if err := approvalVerifier.VerifyGrantSignature(candidate.Grant, candidate.GrantSignatureAlgorithm, candidate.GrantSignature); err != nil {
				return err
			}
			if err := approvalVerifier.VerifyGrantConsumptionSignature(candidate.Consumption, candidate.ConsumptionSignatureAlgorithm, candidate.ConsumptionSignature); err != nil {
				return err
			}
			return approvalVerifier.VerifyDispatchAdmissionSignature(candidate.DispatchAdmission, candidate.DispatchSignatureAlgorithm, candidate.DispatchSignature)
		},
		VerifyDependencyState: func(ref, hash string) error {
			if ref != inputs.Dependency.Ref || subtle.ConstantTimeCompare([]byte(hash), []byte(inputs.Dependency.Hash)) != 1 {
				return errors.New("dependency state is not trusted")
			}
			return nil
		},
		ExpectedRequestBodyHash: inputs.Permit.RequestBodyHash,
		ExpectedArgsC14NHash:    inputs.Permit.ArgsC14NHash,
		ExpectedPolicyEpoch:     inputs.ExpectedPolicyEpoch,
		MaximumPermitTTL:        maximumTTL,
		ResolveVerdictKeyForTrustRoot: func(rootID, keyRef string) (ed25519.PublicKey, error) {
			if rootID != inputs.VerdictTrust.KernelTrustRootID || keyRef != inputs.VerdictTrust.SigningKeyRef {
				return nil, errors.New("verdict signer is not trusted")
			}
			return append(ed25519.PublicKey(nil), verdictKey...), nil
		},
		ResolveEmergencyFence: func(tenantID, workspaceID string) (contracts.LaunchEmergencyFenceSnapshot, error) {
			if tenantID != fence.TenantID || workspaceID != fence.WorkspaceID {
				return contracts.LaunchEmergencyFenceSnapshot{}, errors.New("emergency fence scope is not trusted")
			}
			return contracts.LaunchEmergencyFenceSnapshot{TenantID: fence.TenantID, WorkspaceID: fence.WorkspaceID, EffectiveEpoch: fence.EffectiveEpoch, Active: fence.Active}, nil
		},
		ResolveCurrentConnectorRelease: func(candidate contracts.ApprovalConnectorAuthority) (contracts.ConnectorReleaseAuthorityEnvelope, error) {
			if candidate.AuthorityHash != approval.Grant.ConnectorAuthority.AuthorityHash {
				return contracts.ConnectorReleaseAuthorityEnvelope{}, errors.New("connector release lookup is not trusted")
			}
			return currentRelease, nil
		},
		VerifyCurrentConnectorRelease: releaseVerifier.VerifyCurrentCertifiedAt,
		Permit:                        permit,
	}, nil
}

func (trust connectorReleaseTrust) key() (connectorregistry.TrustedReleaseAuthorityKey, error) {
	publicKey, err := parsePublicKey(trust.PublicKey)
	if err != nil {
		return connectorregistry.TrustedReleaseAuthorityKey{}, fmt.Errorf("trusted connector release key: %w", err)
	}
	if !boundedToken(trust.AuthorityID) || !boundedToken(trust.SigningKeyRef) || !trust.Enabled ||
		trust.NotBefore.IsZero() || trust.NotAfter.IsZero() || trust.NotBefore.Location() != time.UTC || trust.NotAfter.Location() != time.UTC || !trust.NotAfter.After(trust.NotBefore) {
		return connectorregistry.TrustedReleaseAuthorityKey{}, errors.New("trusted connector release key metadata is invalid")
	}
	return connectorregistry.TrustedReleaseAuthorityKey{
		AuthorityID: trust.AuthorityID, SigningKeyRef: trust.SigningKeyRef, PublicKey: publicKey,
		Enabled: true, NotBefore: trust.NotBefore, NotAfter: trust.NotAfter,
	}, nil
}

func (binding permitBinding) validate() error {
	if !binding.SingleUse || binding.EffectID != contracts.EffectTypeDeployProductionActivate || binding.EffectOrdinal < 0 || binding.EmergencyFenceEpoch < 0 {
		return errors.New("trusted permit must be single-use DEPLOY_PRODUCTION_ACTIVATE")
	}
	for _, observed := range []time.Time{binding.PermitIssuedAt, binding.PermitExpiry, binding.KernelVerdictIssuedAt, binding.KernelVerdictExpiry, binding.DispatchDeadline} {
		if observed.IsZero() || observed.Location() != time.UTC {
			return errors.New("trusted permit times must be UTC")
		}
	}
	return nil
}

func (binding permitBinding) contract() contracts.LaunchEffectPermitBinding {
	return contracts.LaunchEffectPermitBinding{
		EffectPermitRef: binding.EffectPermitRef, EffectPermitHash: binding.EffectPermitHash, PermitNonce: binding.PermitNonce,
		ProofSessionRef: binding.ProofSessionRef, EvidenceReservationRef: binding.EvidenceReservationRef,
		PermitIssuedAt: binding.PermitIssuedAt, PermitExpiry: binding.PermitExpiry,
		KernelVerdictRef: binding.KernelVerdictRef, KernelVerdictHash: binding.KernelVerdictHash,
		KernelVerdictIssuedAt: binding.KernelVerdictIssuedAt, KernelVerdictExpiry: binding.KernelVerdictExpiry,
		EffectID: binding.EffectID, TenantID: binding.TenantID, WorkspaceID: binding.WorkspaceID, MissionID: binding.MissionID,
		Principal: binding.Principal, Audience: binding.Audience, KernelTrustRootID: binding.KernelTrustRootID, EffectOrdinal: binding.EffectOrdinal,
		InputSchemaHash: binding.InputSchemaHash, InputHash: binding.InputHash, IdempotencyKey: binding.IdempotencyKey, PlanHash: binding.PlanHash,
		ApprovalArtifactRef: binding.ApprovalArtifactRef, ApprovalArtifactHash: binding.ApprovalArtifactHash,
		ApprovalConsumptionRef: binding.ApprovalConsumptionRef, ApprovalConsumptionHash: binding.ApprovalConsumptionHash,
		DispatchAdmissionRef: binding.DispatchAdmissionRef, DispatchAdmissionHash: binding.DispatchAdmissionHash,
		DependencySetRef: binding.DependencySetRef, DependencySetHash: binding.DependencySetHash,
		ConnectorID: binding.ConnectorID, ConnectorContractHash: binding.ConnectorContractHash,
		ConnectorAuthorityRef: binding.ConnectorAuthorityRef, ConnectorAuthorityHash: binding.ConnectorAuthorityHash,
		ActionURN: binding.ActionURN, RequestBodyHash: binding.RequestBodyHash, ArgsC14NHash: binding.ArgsC14NHash,
		PolicyEpoch: binding.PolicyEpoch, EmergencyFenceEpoch: binding.EmergencyFenceEpoch,
		DispatchDeadline: binding.DispatchDeadline, SingleUse: binding.SingleUse,
	}
}

func newStaticRouteResolver(artifacts routeArtifacts) (*staticRouteResolver, error) {
	if artifacts.RepositoryAnalyses == nil || artifacts.WorkloadGraphs == nil || artifacts.ProviderProfiles == nil ||
		artifacts.ProviderCertifications == nil || artifacts.ConstraintSets == nil || artifacts.RouteQuotes == nil ||
		artifacts.CommercialEvidence == nil || artifacts.FXSnapshots == nil || artifacts.TaxSnapshots == nil ||
		artifacts.OfferSnapshots == nil || artifacts.ResourceGraphs == nil || artifacts.ProviderPayloadSets == nil ||
		artifacts.GeneratedSpecHashes == nil || artifacts.CertificationKeys == nil || artifacts.CurrentCertifications == nil {
		return nil, errors.New("trusted route artifact maps must be explicit")
	}
	keys := make(map[string]ed25519.PublicKey, len(artifacts.CertificationKeys))
	for keyID, encoded := range artifacts.CertificationKeys {
		if !boundedToken(keyID) {
			return nil, errors.New("trusted route certification key ID is invalid")
		}
		key, err := parsePublicKey(encoded)
		if err != nil {
			return nil, fmt.Errorf("trusted route certification key %q: %w", keyID, err)
		}
		keys[keyID] = key
	}
	return &staticRouteResolver{artifacts: artifacts, certificationKeys: keys}, nil
}

func (resolver *staticRouteResolver) ResolveLaunchRepositoryAnalysis(ref string) (contracts.LaunchRepositoryAnalysis, error) {
	value, ok := resolver.artifacts.RepositoryAnalyses[ref]
	if !ok {
		return contracts.LaunchRepositoryAnalysis{}, missingRouteArtifact("repository analysis", ref)
	}
	return value, nil
}
func (resolver *staticRouteResolver) ResolveLaunchWorkloadGraph(ref string) (contracts.LaunchWorkloadGraph, error) {
	value, ok := resolver.artifacts.WorkloadGraphs[ref]
	if !ok {
		return contracts.LaunchWorkloadGraph{}, missingRouteArtifact("workload graph", ref)
	}
	return value, nil
}
func (resolver *staticRouteResolver) ResolveLaunchProviderProfile(ref string) (contracts.LaunchProviderCapabilityProfile, error) {
	value, ok := resolver.artifacts.ProviderProfiles[ref]
	if !ok {
		return contracts.LaunchProviderCapabilityProfile{}, missingRouteArtifact("provider profile", ref)
	}
	return value, nil
}
func (resolver *staticRouteResolver) ResolveLaunchProviderCertification(ref string) (contracts.LaunchProviderCertificationRecord, error) {
	value, ok := resolver.artifacts.ProviderCertifications[ref]
	if !ok {
		return contracts.LaunchProviderCertificationRecord{}, missingRouteArtifact("provider certification", ref)
	}
	return value, nil
}
func (resolver *staticRouteResolver) ResolveLaunchConstraintSet(ref string) (contracts.LaunchConstraintSet, error) {
	value, ok := resolver.artifacts.ConstraintSets[ref]
	if !ok {
		return contracts.LaunchConstraintSet{}, missingRouteArtifact("constraint set", ref)
	}
	return value, nil
}
func (resolver *staticRouteResolver) ResolveLaunchRouteQuote(ref string) (contracts.LaunchRouteQuote, error) {
	value, ok := resolver.artifacts.RouteQuotes[ref]
	if !ok {
		return contracts.LaunchRouteQuote{}, missingRouteArtifact("route quote", ref)
	}
	return value, nil
}
func (resolver *staticRouteResolver) ResolveLaunchCommercialEvidence(ref string) (contracts.LaunchCommercialEvidence, error) {
	value, ok := resolver.artifacts.CommercialEvidence[ref]
	if !ok {
		return contracts.LaunchCommercialEvidence{}, missingRouteArtifact("commercial evidence", ref)
	}
	return value, nil
}
func (resolver *staticRouteResolver) ResolveLaunchFXSnapshot(ref string) (contracts.LaunchFXSnapshot, error) {
	value, ok := resolver.artifacts.FXSnapshots[ref]
	if !ok {
		return contracts.LaunchFXSnapshot{}, missingRouteArtifact("FX snapshot", ref)
	}
	return value, nil
}
func (resolver *staticRouteResolver) ResolveLaunchTaxSnapshot(ref string) (contracts.LaunchTaxSnapshot, error) {
	value, ok := resolver.artifacts.TaxSnapshots[ref]
	if !ok {
		return contracts.LaunchTaxSnapshot{}, missingRouteArtifact("tax snapshot", ref)
	}
	return value, nil
}
func (resolver *staticRouteResolver) ResolveLaunchOfferSnapshot(ref string) (contracts.LaunchOfferSnapshot, error) {
	value, ok := resolver.artifacts.OfferSnapshots[ref]
	if !ok {
		return contracts.LaunchOfferSnapshot{}, missingRouteArtifact("offer snapshot", ref)
	}
	return value, nil
}
func (resolver *staticRouteResolver) ResolveLaunchResourceGraph(ref string) (contracts.LaunchResourceGraph, error) {
	value, ok := resolver.artifacts.ResourceGraphs[ref]
	if !ok {
		return contracts.LaunchResourceGraph{}, missingRouteArtifact("resource graph", ref)
	}
	return value, nil
}
func (resolver *staticRouteResolver) ResolveLaunchProviderPayloadSet(ref string) (contracts.LaunchProviderPayloadSet, error) {
	value, ok := resolver.artifacts.ProviderPayloadSets[ref]
	if !ok {
		return contracts.LaunchProviderPayloadSet{}, missingRouteArtifact("provider payload set", ref)
	}
	return value, nil
}
func (resolver *staticRouteResolver) ResolveLaunchGeneratedSpecHash(ref string) (string, error) {
	value, ok := resolver.artifacts.GeneratedSpecHashes[ref]
	if !ok || !trustedSHA256Pattern.MatchString(value) {
		return "", missingRouteArtifact("generated spec hash", ref)
	}
	return value, nil
}
func (resolver *staticRouteResolver) ResolveLaunchCertificationKey(keyID string) (ed25519.PublicKey, error) {
	value, ok := resolver.certificationKeys[keyID]
	if !ok {
		return nil, missingRouteArtifact("certification key", keyID)
	}
	return append(ed25519.PublicKey(nil), value...), nil
}
func (resolver *staticRouteResolver) AssertLaunchCertificationCurrent(certificationID, recordHash string) error {
	expected, ok := resolver.artifacts.CurrentCertifications[certificationID]
	if !ok || subtle.ConstantTimeCompare([]byte(recordHash), []byte(expected)) != 1 {
		return missingRouteArtifact("current certification", certificationID)
	}
	return nil
}

func parsePublicKey(value string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(value, "ed25519:") {
		return nil, errors.New("public key must use ed25519 lowercase hex encoding")
	}
	encoded := strings.TrimPrefix(value, "ed25519:")
	if len(encoded) != ed25519.PublicKeySize*2 || encoded != strings.ToLower(encoded) {
		return nil, errors.New("public key encoding is invalid")
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("public key encoding is invalid")
	}
	return ed25519.PublicKey(decoded), nil
}

func boundedToken(value string) bool {
	return value != "" && len(value) <= 1024 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\t")
}

func missingRouteArtifact(kind, ref string) error {
	return fmt.Errorf("trusted %s %q not found", kind, ref)
}
