package contracts

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	LaunchRepositoryAnalysisSchemaVersion = "launch_repository_analysis.v1"
	LaunchWorkloadGraphSchemaVersion      = "launch_workload_graph.v1"
	LaunchProviderProfileSchemaVersion    = "launch_provider_capability_profile.v1"
	LaunchRouteBindingSchemaVersion       = "launch_route_binding.v1"

	LaunchAnalysisSupported   = "SUPPORTED"
	LaunchAnalysisNeedsInput  = "NEEDS_INPUT"
	LaunchAnalysisUnsupported = "UNSUPPORTED"
	LaunchAnalysisUnknown     = "UNKNOWN"

	LaunchProviderProfileCandidate = "CANDIDATE"
	LaunchProviderProfilePublished = "PUBLISHED"
	LaunchProviderProfileRetired   = "RETIRED"

	LaunchLifecycleEphemeral        = "EPHEMERAL"
	LaunchLifecycleStatefulData     = "STATEFUL_DATA"
	LaunchLifecycleStatefulResource = "STATEFUL_RESOURCE"
	LaunchLifecycleComposite        = "COMPOSITE"

	LaunchTransitionReleaseCutover = "RELEASE_CUTOVER"
	LaunchTransitionResourceState  = "RESOURCE_STATE_TRANSITION"
	LaunchTransitionDataRestore    = "DATA_RESTORE"
	LaunchTransitionInfraReconcile = "INFRA_RECONCILE"
	LaunchTransitionComposite      = "COMPOSITE"

	LaunchCompensationReleaseRollback = "RELEASE_ROLLBACK"
	LaunchCompensationResourceRestore = "RESOURCE_STATE_RESTORE"
	LaunchCompensationDataRestore     = "DATA_RESTORE"
	LaunchCompensationInfraReconcile  = "INFRA_RECONCILE"
	LaunchCompensationComposite       = "COMPOSITE"
)

var (
	launchCommitPattern    = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
	launchSourceRefPattern = regexp.MustCompile(`^source:[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)
)

// LaunchRepositoryAnalysis records what was actually inspected. SourceConnectionRef
// is an opaque server-side reference, never a credential-bearing repository URL.
type LaunchRepositoryAnalysis struct {
	SchemaVersion        string `json:"schema_version"`
	AnalysisID           string `json:"analysis_id"`
	TenantID             string `json:"tenant_id"`
	WorkspaceID          string `json:"workspace_id"`
	SourceConnectionRef  string `json:"source_connection_ref"`
	SourceCommitSHA      string `json:"source_commit_sha"`
	SourceTreeHash       string `json:"source_tree_hash"`
	AnalyzerContractHash string `json:"analyzer_contract_hash"`
	Status               string `json:"status"`
	WorkloadGraphRef     string `json:"workload_graph_ref,omitempty"`
	WorkloadGraphHash    string `json:"workload_graph_hash,omitempty"`
	FindingSetHash       string `json:"finding_set_hash"`
	AnalyzedAt           string `json:"analyzed_at"`
}

// LaunchWorkloadGraph is provider-neutral. It represents arbitrary repository
// shapes without silently collapsing workers, stateful data, GPUs, clusters,
// functions, or infrastructure into a website deployment.
type LaunchWorkloadGraph struct {
	SchemaVersion   string               `json:"schema_version"`
	GraphID         string               `json:"graph_id"`
	TenantID        string               `json:"tenant_id"`
	WorkspaceID     string               `json:"workspace_id"`
	SourceCommitSHA string               `json:"source_commit_sha"`
	SourceTreeHash  string               `json:"source_tree_hash"`
	Nodes           []LaunchWorkloadNode `json:"nodes"`
	Edges           []LaunchWorkloadEdge `json:"edges"`
	UnknownSetHash  string               `json:"unknown_set_hash"`
}

type LaunchWorkloadNode struct {
	NodeID               string   `json:"node_id"`
	Kind                 string   `json:"kind"`
	LifecycleClass       string   `json:"lifecycle_class"`
	DefinitionHash       string   `json:"definition_hash"`
	RequirementsHash     string   `json:"requirements_hash"`
	RequiredCapabilities []string `json:"required_capabilities"`
	Deployability        string   `json:"deployability"`
}

type LaunchWorkloadEdge struct {
	FromNodeID   string `json:"from_node_id"`
	ToNodeID     string `json:"to_node_id"`
	Relationship string `json:"relationship"`
}

// LaunchProviderCapabilityProfile is provider-owned routing evidence. ProfileStatus
// is informational lifecycle metadata only. It grants no dispatch authority;
// production admission requires an independently resolved signed certification.
type LaunchProviderCapabilityProfile struct {
	SchemaVersion         string                 `json:"schema_version"`
	ProfileID             string                 `json:"profile_id"`
	ProviderID            string                 `json:"provider_id"`
	ConnectorID           string                 `json:"connector_id"`
	ConnectorContractHash string                 `json:"connector_contract_hash"`
	ProfileVersion        string                 `json:"profile_version"`
	ProfileStatus         string                 `json:"profile_status"`
	Regions               []LaunchProviderRegion `json:"regions"`
	Actions               []LaunchProviderAction `json:"actions"`
	PricingEvidenceRef    string                 `json:"pricing_evidence_ref"`
	PricingEvidenceHash   string                 `json:"pricing_evidence_hash"`
	TermsEvidenceRef      string                 `json:"terms_evidence_ref"`
	TermsEvidenceHash     string                 `json:"terms_evidence_hash"`
	RetrievedAt           string                 `json:"retrieved_at"`
	ExpiresAt             string                 `json:"expires_at"`
}

type LaunchProviderRegion struct {
	RegionID      string                   `json:"region_id"`
	Jurisdiction  string                   `json:"jurisdiction"`
	ResidencyTags []string                 `json:"residency_tags"`
	Offerings     []LaunchProviderOffering `json:"offerings"`
}

type LaunchProviderOffering struct {
	OfferingID            string   `json:"offering_id"`
	SupportedWorkloads    []string `json:"supported_workload_kinds"`
	SupportedCapabilities []string `json:"supported_capabilities"`
	SupportedLifecycles   []string `json:"supported_lifecycle_classes"`
}

type LaunchProviderAction struct {
	EffectID                     string   `json:"effect_id"`
	ActionURN                    string   `json:"action_urn"`
	ReconciliationMode           string   `json:"reconciliation_mode"`
	IdempotencyMode              string   `json:"idempotency_mode"`
	SupportedTransitionClasses   []string `json:"supported_transition_classes"`
	SupportedCompensationClasses []string `json:"supported_compensation_classes"`
}

// LaunchRouteBinding is a multi-provider route plan. Each placement binds one
// subgraph to an exact account, region, offering, connector, action set, and
// optional certification record. Cross-placement dependencies are explicit.
type LaunchRouteBinding struct {
	SchemaVersion          string                  `json:"schema_version"`
	RouteID                string                  `json:"route_id"`
	TenantID               string                  `json:"tenant_id"`
	WorkspaceID            string                  `json:"workspace_id"`
	MissionID              string                  `json:"mission_id"`
	RepositoryAnalysisRef  string                  `json:"repository_analysis_ref"`
	RepositoryAnalysisHash string                  `json:"repository_analysis_hash"`
	WorkloadGraphRef       string                  `json:"workload_graph_ref"`
	WorkloadGraphHash      string                  `json:"workload_graph_hash"`
	ConstraintSetRef       string                  `json:"constraint_set_ref"`
	ConstraintSetHash      string                  `json:"constraint_set_hash"`
	RouteQuoteRef          string                  `json:"route_quote_ref"`
	RouteQuoteHash         string                  `json:"route_quote_hash"`
	ResourceGraphRef       string                  `json:"resource_graph_ref"`
	ResourceGraphHash      string                  `json:"resource_graph_hash"`
	ProviderPayloadSetRef  string                  `json:"provider_payload_set_ref"`
	ProviderPayloadSetHash string                  `json:"provider_payload_set_hash"`
	GeneratedSpecRef       string                  `json:"generated_spec_ref"`
	GeneratedSpecHash      string                  `json:"generated_spec_hash"`
	Placements             []LaunchRoutePlacement  `json:"placements"`
	PlacementDependencies  []LaunchRouteDependency `json:"placement_dependencies"`
	ExpiresAt              string                  `json:"expires_at"`
}

type LaunchRoutePlacement struct {
	PlacementID                   string                     `json:"placement_id"`
	WorkloadNodeIDs               []string                   `json:"workload_node_ids"`
	ProviderProfileRef            string                     `json:"provider_profile_ref"`
	ProviderProfileHash           string                     `json:"provider_profile_hash"`
	ProviderCertificationRef      string                     `json:"provider_certification_ref,omitempty"`
	ProviderCertificationHash     string                     `json:"provider_certification_hash,omitempty"`
	ProviderID                    string                     `json:"provider_id"`
	ProviderAccountRef            string                     `json:"provider_account_ref"`
	ProviderAccountHash           string                     `json:"provider_account_hash"`
	RegionID                      string                     `json:"region_id"`
	Jurisdiction                  string                     `json:"jurisdiction"`
	OfferingID                    string                     `json:"offering_id"`
	ProviderConnectorID           string                     `json:"provider_connector_id"`
	ProviderConnectorContractHash string                     `json:"provider_connector_contract_hash"`
	ActionBindings                []LaunchRouteActionBinding `json:"action_bindings"`
	ResourceSubsetHash            string                     `json:"resource_subset_hash"`
	ProviderPayloadSubsetHash     string                     `json:"provider_payload_subset_hash"`
}

type LaunchRouteActionBinding struct {
	EffectID            string `json:"effect_id"`
	ProviderActionURN   string `json:"provider_action_urn"`
	ProviderPayloadHash string `json:"provider_payload_hash"`
}

type LaunchRouteDependency struct {
	FromPlacementID  string `json:"from_placement_id"`
	ToPlacementID    string `json:"to_placement_id"`
	Relationship     string `json:"relationship"`
	WorkloadEdgeHash string `json:"workload_edge_hash"`
}

// LaunchRouteArtifactResolver is intentionally source-owned. Route validation
// receives only opaque refs and resolves each approval-bound artifact through
// this interface; values copied from an effect input do not satisfy it.
type LaunchRouteArtifactResolver interface {
	ResolveLaunchRepositoryAnalysis(ref string) (LaunchRepositoryAnalysis, error)
	ResolveLaunchWorkloadGraph(ref string) (LaunchWorkloadGraph, error)
	ResolveLaunchProviderProfile(ref string) (LaunchProviderCapabilityProfile, error)
	ResolveLaunchProviderCertification(ref string) (LaunchProviderCertificationRecord, error)
	ResolveLaunchConstraintSet(ref string) (LaunchConstraintSet, error)
	ResolveLaunchRouteQuote(ref string) (LaunchRouteQuote, error)
	ResolveLaunchOfferSnapshot(ref string) (LaunchOfferSnapshot, error)
	ResolveLaunchResourceGraph(ref string) (LaunchResourceGraph, error)
	ResolveLaunchProviderPayloadSet(ref string) (LaunchProviderPayloadSet, error)
	ResolveLaunchGeneratedSpecHash(ref string) (string, error)
	ResolveLaunchCertificationKey(signerKeyID string) (ed25519.PublicKey, error)
	AssertLaunchCertificationCurrent(certificationID, recordHash string) error
}

// Workload kinds and graph relationships are namespaced, extensible tokens.
// A provider profile may support vendor- or domain-specific kinds without a
// Kernel release; exact profile certification and route approval still govern
// whether that kind is executable. The reserved "unknown" kind can represent
// analyzer uncertainty but can never be claimed as provider support.
var launchWorkloadKindPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
var launchRelationshipPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

var launchLifecycleClasses = map[string]struct{}{
	LaunchLifecycleEphemeral: {}, LaunchLifecycleStatefulData: {},
	LaunchLifecycleStatefulResource: {}, LaunchLifecycleComposite: {},
}

var launchTransitionClasses = map[string]struct{}{
	LaunchTransitionReleaseCutover: {}, LaunchTransitionResourceState: {},
	LaunchTransitionDataRestore: {}, LaunchTransitionInfraReconcile: {},
	LaunchTransitionComposite: {},
}

var launchCompensationClasses = map[string]struct{}{
	LaunchCompensationReleaseRollback: {}, LaunchCompensationResourceRestore: {},
	LaunchCompensationDataRestore: {}, LaunchCompensationInfraReconcile: {},
	LaunchCompensationComposite: {},
}

func ValidateLaunchRepositoryAnalysis(analysis LaunchRepositoryAnalysis) error {
	if analysis.SchemaVersion != LaunchRepositoryAnalysisSchemaVersion || analysis.AnalysisID == "" || analysis.TenantID == "" || analysis.WorkspaceID == "" || !launchSourceRefPattern.MatchString(analysis.SourceConnectionRef) {
		return errors.New("launch repository analysis identity or opaque source reference is invalid")
	}
	if !launchCommitPattern.MatchString(analysis.SourceCommitSHA) || !validLaunchSHA256(analysis.SourceTreeHash) || !validLaunchSHA256(analysis.AnalyzerContractHash) || !validLaunchSHA256(analysis.FindingSetHash) {
		return errors.New("launch repository analysis source or evidence hash is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, analysis.AnalyzedAt); err != nil {
		return errors.New("launch repository analysis timestamp is invalid")
	}
	switch analysis.Status {
	case LaunchAnalysisSupported, LaunchAnalysisNeedsInput, LaunchAnalysisUnsupported:
		if analysis.WorkloadGraphRef == "" || !validLaunchSHA256(analysis.WorkloadGraphHash) {
			return errors.New("known launch repository analysis must bind a workload graph")
		}
	case LaunchAnalysisUnknown:
		if analysis.WorkloadGraphRef != "" || analysis.WorkloadGraphHash != "" {
			return errors.New("UNKNOWN launch repository analysis cannot claim a workload graph")
		}
	default:
		return errors.New("launch repository analysis status is invalid")
	}
	return nil
}

func DeriveLaunchRepositoryAnalysisHash(value LaunchRepositoryAnalysis) (string, error) {
	return deriveLaunchCanonicalHash(value, "repository analysis")
}

func DeriveLaunchWorkloadGraphHash(value LaunchWorkloadGraph) (string, error) {
	return deriveLaunchCanonicalHash(value, "workload graph")
}

func DeriveLaunchProviderCapabilityProfileHash(value LaunchProviderCapabilityProfile) (string, error) {
	return deriveLaunchCanonicalHash(value, "provider capability profile")
}

func DeriveLaunchRouteBindingHash(value LaunchRouteBinding) (string, error) {
	return deriveLaunchCanonicalHash(value, "route binding")
}

func DeriveLaunchWorkloadEdgeHash(value LaunchWorkloadEdge) (string, error) {
	return deriveLaunchCanonicalHash(value, "workload edge")
}

func AggregateLaunchWorkloadGraphStatus(graph LaunchWorkloadGraph) string {
	status := LaunchAnalysisSupported
	for _, node := range graph.Nodes {
		switch node.Deployability {
		case LaunchAnalysisUnknown:
			return LaunchAnalysisUnknown
		case LaunchAnalysisUnsupported:
			status = LaunchAnalysisUnsupported
		case LaunchAnalysisNeedsInput:
			if status == LaunchAnalysisSupported {
				status = LaunchAnalysisNeedsInput
			}
		}
	}
	return status
}

func ValidateLaunchRepositoryAnalysisGraph(analysis LaunchRepositoryAnalysis, graph LaunchWorkloadGraph) error {
	if err := ValidateLaunchRepositoryAnalysis(analysis); err != nil {
		return err
	}
	if err := ValidateLaunchWorkloadGraph(graph); err != nil {
		return err
	}
	if analysis.Status == LaunchAnalysisUnknown {
		return errors.New("UNKNOWN launch repository analysis cannot be routed")
	}
	hash, err := DeriveLaunchWorkloadGraphHash(graph)
	if err != nil {
		return err
	}
	if analysis.TenantID != graph.TenantID || analysis.WorkspaceID != graph.WorkspaceID || analysis.WorkloadGraphRef != graph.GraphID || analysis.SourceCommitSHA != graph.SourceCommitSHA || !launchConstantEqual(analysis.SourceTreeHash, graph.SourceTreeHash) || !launchConstantEqual(analysis.WorkloadGraphHash, hash) {
		return errors.New("launch repository analysis does not bind the supplied workload graph")
	}
	if aggregate := AggregateLaunchWorkloadGraphStatus(graph); analysis.Status != aggregate {
		return fmt.Errorf("launch repository analysis status %s does not equal graph aggregate %s", analysis.Status, aggregate)
	}
	return nil
}

func ValidateLaunchWorkloadGraph(graph LaunchWorkloadGraph) error {
	if graph.SchemaVersion != LaunchWorkloadGraphSchemaVersion || graph.GraphID == "" || graph.TenantID == "" || graph.WorkspaceID == "" {
		return errors.New("launch workload graph identity is incomplete")
	}
	if !launchCommitPattern.MatchString(graph.SourceCommitSHA) || !validLaunchSHA256(graph.SourceTreeHash) || !validLaunchSHA256(graph.UnknownSetHash) || len(graph.Nodes) == 0 {
		return errors.New("launch workload graph source, unknown set, or nodes are invalid")
	}
	nodes := make(map[string]struct{}, len(graph.Nodes))
	previous := ""
	for _, node := range graph.Nodes {
		if node.NodeID == "" || node.NodeID <= previous {
			return errors.New("launch workload graph nodes must be unique and sorted by node_id")
		}
		previous = node.NodeID
		if !launchWorkloadKindPattern.MatchString(node.Kind) {
			return fmt.Errorf("launch workload graph node %s has invalid kind %q", node.NodeID, node.Kind)
		}
		if !launchLifecycleClassKnown(node.LifecycleClass) || !validLaunchSHA256(node.DefinitionHash) || !validLaunchSHA256(node.RequirementsHash) {
			return fmt.Errorf("launch workload graph node %s has invalid lifecycle, definition, or requirements", node.NodeID)
		}
		if err := validateSortedUniqueNonEmpty(node.RequiredCapabilities, "required capabilities"); err != nil {
			return fmt.Errorf("launch workload graph node %s: %w", node.NodeID, err)
		}
		switch node.Deployability {
		case LaunchAnalysisSupported, LaunchAnalysisNeedsInput, LaunchAnalysisUnsupported, LaunchAnalysisUnknown:
		default:
			return fmt.Errorf("launch workload graph node %s has invalid deployability", node.NodeID)
		}
		nodes[node.NodeID] = struct{}{}
	}
	previous = ""
	for _, edge := range graph.Edges {
		key := edge.FromNodeID + "\x00" + edge.ToNodeID + "\x00" + edge.Relationship
		if key <= previous {
			return errors.New("launch workload graph edges must be unique and canonically sorted")
		}
		previous = key
		if _, ok := nodes[edge.FromNodeID]; !ok {
			return fmt.Errorf("launch workload graph edge references unknown source node %q", edge.FromNodeID)
		}
		if _, ok := nodes[edge.ToNodeID]; !ok {
			return fmt.Errorf("launch workload graph edge references unknown target node %q", edge.ToNodeID)
		}
		if !launchRelationshipPattern.MatchString(edge.Relationship) {
			return fmt.Errorf("launch workload graph edge has invalid relationship %q", edge.Relationship)
		}
	}
	return nil
}

func ValidateLaunchProviderCapabilityProfile(profile LaunchProviderCapabilityProfile) error {
	if profile.SchemaVersion != LaunchProviderProfileSchemaVersion || profile.ProfileID == "" || profile.ProviderID == "" || profile.ConnectorID == "" || profile.ProfileVersion == "" {
		return errors.New("launch provider capability profile identity is incomplete")
	}
	if !validLaunchSHA256(profile.ConnectorContractHash) || !validLaunchSHA256(profile.PricingEvidenceHash) || !validLaunchSHA256(profile.TermsEvidenceHash) || profile.PricingEvidenceRef == "" || profile.TermsEvidenceRef == "" {
		return errors.New("launch provider capability profile contract or commercial evidence is invalid")
	}
	switch profile.ProfileStatus {
	case LaunchProviderProfileCandidate, LaunchProviderProfilePublished, LaunchProviderProfileRetired:
	default:
		return errors.New("launch provider profile status is invalid")
	}
	if len(profile.Regions) == 0 || len(profile.Actions) == 0 {
		return errors.New("launch provider capability profile must declare regions and actions")
	}
	previous := ""
	for _, region := range profile.Regions {
		if region.RegionID == "" || region.RegionID <= previous || region.Jurisdiction == "" || len(region.Offerings) == 0 {
			return errors.New("launch provider profile regions must be complete, unique, sorted, and have offerings")
		}
		previous = region.RegionID
		if err := validateSortedUniqueNonEmpty(region.ResidencyTags, "residency tags"); err != nil {
			return fmt.Errorf("launch provider region %s: %w", region.RegionID, err)
		}
		previousOffering := ""
		for _, offering := range region.Offerings {
			if offering.OfferingID == "" || offering.OfferingID <= previousOffering {
				return fmt.Errorf("launch provider region %s offerings must be unique and sorted", region.RegionID)
			}
			previousOffering = offering.OfferingID
			if err := validateSortedUniqueKnownWorkloads(offering.SupportedWorkloads); err != nil {
				return fmt.Errorf("launch provider offering %s: %w", offering.OfferingID, err)
			}
			if err := validateSortedUniqueNonEmpty(offering.SupportedCapabilities, "supported capabilities"); err != nil {
				return fmt.Errorf("launch provider offering %s: %w", offering.OfferingID, err)
			}
			if err := validateSortedUniqueKnownValues(offering.SupportedLifecycles, "supported lifecycle classes", launchLifecycleClasses); err != nil {
				return fmt.Errorf("launch provider offering %s: %w", offering.OfferingID, err)
			}
		}
	}
	previous = ""
	for _, action := range profile.Actions {
		if action.EffectID == "" || action.EffectID <= previous || !launchEffectIsProviderMutation(action.EffectID) || action.ActionURN == "" {
			return errors.New("launch provider actions must be registered, unique, and sorted by effect_id")
		}
		previous = action.EffectID
		switch action.ReconciliationMode {
		case "READ_AFTER_WRITE", "OPERATION_POLL", "EVENT_AND_READ":
		default:
			return fmt.Errorf("launch provider action %s has invalid reconciliation mode", action.EffectID)
		}
		switch action.IdempotencyMode {
		case "NATIVE_KEY", "RECONCILE_BEFORE_RETRY", "COMPARE_AND_SET":
		default:
			return fmt.Errorf("launch provider action %s has invalid idempotency mode", action.EffectID)
		}
		if err := validateSortedUniqueKnownValues(action.SupportedTransitionClasses, "supported transition classes", launchTransitionClasses); err != nil {
			return fmt.Errorf("launch provider action %s: %w", action.EffectID, err)
		}
		if err := validateSortedUniqueKnownValues(action.SupportedCompensationClasses, "supported compensation classes", launchCompensationClasses); err != nil {
			return fmt.Errorf("launch provider action %s: %w", action.EffectID, err)
		}
		if action.EffectID == EffectTypeDeployProductionActivate && len(action.SupportedTransitionClasses) == 0 {
			return errors.New("launch provider activation action must declare supported transition classes")
		}
		if action.EffectID == EffectTypeProviderRollback && len(action.SupportedCompensationClasses) == 0 {
			return errors.New("launch provider rollback action must declare supported compensation classes")
		}
	}
	retrievedAt, err := time.Parse(time.RFC3339Nano, profile.RetrievedAt)
	if err != nil {
		return errors.New("launch provider profile retrieval time is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, profile.ExpiresAt)
	if err != nil || !retrievedAt.Before(expiresAt) {
		return errors.New("launch provider profile expiry is invalid")
	}
	return nil
}

// ValidateLaunchRouteBinding resolves and verifies every approval-bound
// artifact. requireDispatchAuthority additionally requires a signed, current,
// non-revoked connector certification for every placement.
func ValidateLaunchRouteBinding(route LaunchRouteBinding, resolver LaunchRouteArtifactResolver, now time.Time, requireDispatchAuthority bool) error {
	if resolver == nil {
		return errors.New("launch route validation requires a source-owned artifact resolver")
	}
	if route.SchemaVersion != LaunchRouteBindingSchemaVersion || route.RouteID == "" || route.TenantID == "" || route.WorkspaceID == "" || route.MissionID == "" || route.RepositoryAnalysisRef == "" || route.WorkloadGraphRef == "" || route.ConstraintSetRef == "" || route.RouteQuoteRef == "" || route.ResourceGraphRef == "" || route.ProviderPayloadSetRef == "" || route.GeneratedSpecRef == "" || len(route.Placements) == 0 {
		return errors.New("launch route binding identity or placements are incomplete")
	}
	for name, value := range map[string]string{
		"repository_analysis_hash":  route.RepositoryAnalysisHash,
		"workload_graph_hash":       route.WorkloadGraphHash,
		"constraint_set_hash":       route.ConstraintSetHash,
		"route_quote_hash":          route.RouteQuoteHash,
		"resource_graph_hash":       route.ResourceGraphHash,
		"provider_payload_set_hash": route.ProviderPayloadSetHash,
		"generated_spec_hash":       route.GeneratedSpecHash,
	} {
		if !validLaunchSHA256(value) {
			return fmt.Errorf("launch route binding %s is invalid", name)
		}
	}
	if now.IsZero() {
		return errors.New("launch route verification time is required")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, route.ExpiresAt)
	if err != nil || !now.Before(expiresAt) {
		return errors.New("launch route binding is expired")
	}

	analysis, err := resolver.ResolveLaunchRepositoryAnalysis(route.RepositoryAnalysisRef)
	if err != nil {
		return fmt.Errorf("resolve launch repository analysis: %w", err)
	}
	graph, err := resolver.ResolveLaunchWorkloadGraph(route.WorkloadGraphRef)
	if err != nil {
		return fmt.Errorf("resolve launch workload graph: %w", err)
	}
	constraints, err := resolver.ResolveLaunchConstraintSet(route.ConstraintSetRef)
	if err != nil {
		return fmt.Errorf("resolve launch constraint set: %w", err)
	}
	quote, err := resolver.ResolveLaunchRouteQuote(route.RouteQuoteRef)
	if err != nil {
		return fmt.Errorf("resolve launch route quote: %w", err)
	}
	resources, err := resolver.ResolveLaunchResourceGraph(route.ResourceGraphRef)
	if err != nil {
		return fmt.Errorf("resolve launch resource graph: %w", err)
	}
	payloads, err := resolver.ResolveLaunchProviderPayloadSet(route.ProviderPayloadSetRef)
	if err != nil {
		return fmt.Errorf("resolve launch provider payload set: %w", err)
	}
	generatedSpecHash, err := resolver.ResolveLaunchGeneratedSpecHash(route.GeneratedSpecRef)
	if err != nil {
		return fmt.Errorf("resolve launch GeneratedSpec: %w", err)
	}
	if err := ValidateLaunchRepositoryAnalysisGraph(analysis, graph); err != nil {
		return err
	}
	if analysis.Status != LaunchAnalysisSupported {
		return fmt.Errorf("launch route requires SUPPORTED repository analysis, got %s", analysis.Status)
	}
	if err := ValidateLaunchConstraintSet(constraints); err != nil {
		return err
	}
	if err := ValidateLaunchRouteQuote(quote); err != nil {
		return err
	}
	if err := ValidateLaunchResourceGraph(resources); err != nil {
		return err
	}
	if err := ValidateLaunchProviderPayloadSet(payloads); err != nil {
		return err
	}

	analysisHash, _ := DeriveLaunchRepositoryAnalysisHash(analysis)
	graphHash, _ := DeriveLaunchWorkloadGraphHash(graph)
	constraintHash, _ := DeriveLaunchConstraintSetHash(constraints)
	quoteHash, _ := DeriveLaunchRouteQuoteHash(quote)
	resourceHash, _ := DeriveLaunchResourceGraphHash(resources)
	payloadHash, _ := DeriveLaunchProviderPayloadSetHash(payloads)
	for name, pair := range map[string][2]string{
		"repository analysis":  {route.RepositoryAnalysisHash, analysisHash},
		"workload graph":       {route.WorkloadGraphHash, graphHash},
		"constraint set":       {route.ConstraintSetHash, constraintHash},
		"route quote":          {route.RouteQuoteHash, quoteHash},
		"resource graph":       {route.ResourceGraphHash, resourceHash},
		"provider payload set": {route.ProviderPayloadSetHash, payloadHash},
		"GeneratedSpec":        {route.GeneratedSpecHash, generatedSpecHash},
	} {
		if !launchConstantEqual(pair[0], pair[1]) {
			return fmt.Errorf("launch route %s hash does not match source-owned content", name)
		}
	}
	if route.TenantID != analysis.TenantID || route.WorkspaceID != analysis.WorkspaceID || route.TenantID != graph.TenantID || route.WorkspaceID != graph.WorkspaceID ||
		route.TenantID != constraints.TenantID || route.WorkspaceID != constraints.WorkspaceID || route.MissionID != constraints.MissionID ||
		route.TenantID != quote.TenantID || route.WorkspaceID != quote.WorkspaceID || route.MissionID != quote.MissionID ||
		route.TenantID != resources.TenantID || route.WorkspaceID != resources.WorkspaceID || route.MissionID != resources.MissionID ||
		route.TenantID != payloads.TenantID || route.WorkspaceID != payloads.WorkspaceID || route.MissionID != payloads.MissionID {
		return errors.New("launch route artifacts cross tenant, workspace, or mission identity")
	}
	if quote.WorkloadGraphHash != graphHash || quote.ConstraintSetHash != constraintHash || quote.Currency != constraints.MaximumGrossCurrency || quote.GrossExposureMinor > constraints.MaximumGrossMinor {
		return errors.New("launch route quote violates the exact workload, constraints, currency, or gross cap")
	}
	quoteExpiry, _ := time.Parse(time.RFC3339Nano, quote.ExpiresAt)
	if expiresAt.After(quoteExpiry) {
		return errors.New("launch route outlives its commercial quote")
	}

	placements := make(map[string]LaunchRoutePlacement, len(route.Placements))
	profilesByPlacement := make(map[string]LaunchProviderCapabilityProfile, len(route.Placements))
	nodePlacement := make(map[string]string, len(graph.Nodes))
	profileExpiry := expiresAt
	previousPlacement := ""
	for _, placement := range route.Placements {
		if placement.PlacementID == "" || placement.PlacementID <= previousPlacement || placement.ProviderProfileRef == "" || placement.ProviderID == "" || placement.ProviderAccountRef == "" || placement.RegionID == "" || placement.Jurisdiction == "" || placement.OfferingID == "" || placement.ProviderConnectorID == "" || len(placement.ActionBindings) == 0 {
			return errors.New("launch route placements must be complete, unique, and sorted")
		}
		previousPlacement = placement.PlacementID
		for field, value := range map[string]string{
			"provider_profile_hash":            placement.ProviderProfileHash,
			"provider_account_hash":            placement.ProviderAccountHash,
			"provider_connector_contract_hash": placement.ProviderConnectorContractHash,
			"resource_subset_hash":             placement.ResourceSubsetHash,
			"provider_payload_subset_hash":     placement.ProviderPayloadSubsetHash,
		} {
			if !validLaunchSHA256(value) {
				return fmt.Errorf("launch route placement %s %s is invalid", placement.PlacementID, field)
			}
		}
		if err := validateSortedUniqueNonEmpty(placement.WorkloadNodeIDs, "placement workload node IDs"); err != nil {
			return fmt.Errorf("launch route placement %s: %w", placement.PlacementID, err)
		}
		profile, err := resolver.ResolveLaunchProviderProfile(placement.ProviderProfileRef)
		if err != nil {
			return fmt.Errorf("resolve launch provider profile %s: %w", placement.ProviderProfileRef, err)
		}
		if err := ValidateLaunchProviderCapabilityProfile(profile); err != nil {
			return err
		}
		profileHash, _ := DeriveLaunchProviderCapabilityProfileHash(profile)
		if placement.ProviderProfileRef != profile.ProfileID || !launchConstantEqual(placement.ProviderProfileHash, profileHash) || placement.ProviderID != profile.ProviderID || placement.ProviderConnectorID != profile.ConnectorID || !launchConstantEqual(placement.ProviderConnectorContractHash, profile.ConnectorContractHash) {
			return fmt.Errorf("launch route placement %s does not match provider profile", placement.PlacementID)
		}
		if profile.ProfileStatus == LaunchProviderProfileRetired {
			return fmt.Errorf("launch route placement %s uses a retired profile", placement.PlacementID)
		}
		parsedProfileExpiry, _ := time.Parse(time.RFC3339Nano, profile.ExpiresAt)
		if parsedProfileExpiry.Before(profileExpiry) {
			profileExpiry = parsedProfileExpiry
		}
		region, offering, ok := findLaunchProviderOffering(profile, placement.RegionID, placement.OfferingID)
		if !ok || region.Jurisdiction != placement.Jurisdiction {
			return fmt.Errorf("launch route placement %s region or offering is absent from provider profile", placement.PlacementID)
		}
		if len(constraints.AllowedProviders) > 0 && !containsLaunchSorted(constraints.AllowedProviders, placement.ProviderID) {
			return fmt.Errorf("launch route provider %s is denied by constraints", placement.ProviderID)
		}
		if len(constraints.AllowedJurisdictions) > 0 && !containsLaunchSorted(constraints.AllowedJurisdictions, placement.Jurisdiction) {
			return fmt.Errorf("launch route jurisdiction %s is denied by constraints", placement.Jurisdiction)
		}
		for _, tag := range constraints.RequiredResidencyTags {
			if !containsLaunchSorted(region.ResidencyTags, tag) {
				return fmt.Errorf("launch route placement %s lacks residency tag %s", placement.PlacementID, tag)
			}
		}
		for _, nodeID := range placement.WorkloadNodeIDs {
			if _, exists := nodePlacement[nodeID]; exists {
				return fmt.Errorf("launch workload node %s is assigned to multiple placements", nodeID)
			}
			node, ok := findLaunchWorkloadNode(graph, nodeID)
			if !ok {
				return fmt.Errorf("launch placement references unknown workload node %s", nodeID)
			}
			if node.Deployability != LaunchAnalysisSupported || !containsLaunchSorted(offering.SupportedWorkloads, node.Kind) || !containsLaunchSorted(offering.SupportedLifecycles, node.LifecycleClass) {
				return fmt.Errorf("launch provider offering does not support workload node %s kind or lifecycle", nodeID)
			}
			for _, capability := range node.RequiredCapabilities {
				if !containsLaunchSorted(offering.SupportedCapabilities, capability) {
					return fmt.Errorf("launch provider offering %s lacks required capability %s for node %s", offering.OfferingID, capability, nodeID)
				}
			}
			nodePlacement[nodeID] = placement.PlacementID
		}
		if err := validateLaunchPlacementActions(placement, profile, payloads); err != nil {
			return err
		}
		resourceSubsetHash, err := DeriveLaunchResourceSubsetHash(resources, placement.PlacementID)
		if err != nil || !launchConstantEqual(placement.ResourceSubsetHash, resourceSubsetHash) {
			return fmt.Errorf("launch route placement %s resource subset hash mismatch", placement.PlacementID)
		}
		payloadSubsetHash, err := DeriveLaunchProviderPayloadSubsetHash(payloads, placement.PlacementID)
		if err != nil || !launchConstantEqual(placement.ProviderPayloadSubsetHash, payloadSubsetHash) {
			return fmt.Errorf("launch route placement %s payload subset hash mismatch", placement.PlacementID)
		}
		if err := validateLaunchPlacementCertification(placement, profile, resolver, now, requireDispatchAuthority); err != nil {
			return err
		}
		placements[placement.PlacementID] = placement
		profilesByPlacement[placement.PlacementID] = profile
	}
	if expiresAt.After(profileExpiry) {
		return errors.New("launch route outlives a provider profile")
	}
	for _, node := range graph.Nodes {
		if _, ok := nodePlacement[node.NodeID]; !ok {
			return fmt.Errorf("launch workload node %s is not assigned to a placement", node.NodeID)
		}
	}
	for _, capability := range constraints.RequiredRouteCapabilities {
		found := false
		for _, placement := range route.Placements {
			profile := profilesByPlacement[placement.PlacementID]
			_, offering, _ := findLaunchProviderOffering(profile, placement.RegionID, placement.OfferingID)
			if containsLaunchSorted(offering.SupportedCapabilities, capability) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("launch route lacks required route capability %s", capability)
		}
	}
	if err := validateLaunchRouteDependencies(route.PlacementDependencies, graph, nodePlacement); err != nil {
		return err
	}
	if err := validateLaunchResourceAssignments(resources, graph, placements, nodePlacement); err != nil {
		return err
	}
	if err := validateLaunchQuotePlacements(quote, route.Placements, profilesByPlacement, constraints, resolver, route.TenantID, route.WorkspaceID); err != nil {
		return err
	}
	return nil
}

func validateLaunchPlacementCertification(placement LaunchRoutePlacement, profile LaunchProviderCapabilityProfile, resolver LaunchRouteArtifactResolver, now time.Time, required bool) error {
	if !required && placement.ProviderCertificationRef == "" && placement.ProviderCertificationHash == "" {
		return nil
	}
	if placement.ProviderCertificationRef == "" || !validLaunchSHA256(placement.ProviderCertificationHash) {
		return fmt.Errorf("launch route placement %s certification binding is incomplete", placement.PlacementID)
	}
	record, err := resolver.ResolveLaunchProviderCertification(placement.ProviderCertificationRef)
	if err != nil {
		return fmt.Errorf("resolve launch provider certification: %w", err)
	}
	if record.CertificationID != placement.ProviderCertificationRef || !launchConstantEqual(record.RecordHash, placement.ProviderCertificationHash) || record.ProfileRef != profile.ProfileID || !launchConstantEqual(record.ProfileHash, placement.ProviderProfileHash) || record.ProviderID != profile.ProviderID || record.ConnectorID != profile.ConnectorID || !launchConstantEqual(record.ConnectorContractHash, profile.ConnectorContractHash) {
		return fmt.Errorf("launch route placement %s certification does not bind the exact profile and connector", placement.PlacementID)
	}
	key, err := resolver.ResolveLaunchCertificationKey(record.SignerKeyID)
	if err != nil {
		return fmt.Errorf("resolve launch provider certification key: %w", err)
	}
	if err := VerifyLaunchProviderCertificationRecord(record, key, now); err != nil {
		return err
	}
	if err := resolver.AssertLaunchCertificationCurrent(record.CertificationID, record.RecordHash); err != nil {
		return fmt.Errorf("launch provider certification is not current: %w", err)
	}
	return nil
}

func validateLaunchPlacementActions(placement LaunchRoutePlacement, profile LaunchProviderCapabilityProfile, payloads LaunchProviderPayloadSet) error {
	profileActions := make(map[string]LaunchProviderAction, len(profile.Actions))
	for _, action := range profile.Actions {
		profileActions[action.EffectID] = action
	}
	payloadEntries := make(map[string]LaunchProviderPayloadEntry)
	for _, entry := range payloads.Entries {
		if entry.PlacementID == placement.PlacementID {
			payloadEntries[entry.EffectID+"\x00"+entry.ProviderActionURN] = entry
		}
	}
	previous := ""
	for _, binding := range placement.ActionBindings {
		if binding.EffectID == "" || binding.EffectID <= previous || binding.ProviderActionURN == "" || !validLaunchSHA256(binding.ProviderPayloadHash) {
			return fmt.Errorf("launch route placement %s actions must be complete, unique, and sorted", placement.PlacementID)
		}
		previous = binding.EffectID
		action, ok := profileActions[binding.EffectID]
		if !ok || action.ActionURN != binding.ProviderActionURN {
			return fmt.Errorf("launch route action %s is absent from provider profile", binding.EffectID)
		}
		entry, ok := payloadEntries[binding.EffectID+"\x00"+binding.ProviderActionURN]
		if !ok || !launchConstantEqual(entry.PayloadHash, binding.ProviderPayloadHash) {
			return fmt.Errorf("launch route action %s does not bind the provider payload set", binding.EffectID)
		}
	}
	if len(payloadEntries) != len(placement.ActionBindings) {
		return fmt.Errorf("launch route placement %s has unbound provider payloads", placement.PlacementID)
	}
	return nil
}

func validateLaunchRouteDependencies(actual []LaunchRouteDependency, graph LaunchWorkloadGraph, nodePlacement map[string]string) error {
	expected := make([]LaunchRouteDependency, 0)
	for _, edge := range graph.Edges {
		from := nodePlacement[edge.FromNodeID]
		to := nodePlacement[edge.ToNodeID]
		if from == to {
			continue
		}
		hash, err := DeriveLaunchWorkloadEdgeHash(edge)
		if err != nil {
			return err
		}
		expected = append(expected, LaunchRouteDependency{FromPlacementID: from, ToPlacementID: to, Relationship: edge.Relationship, WorkloadEdgeHash: hash})
	}
	sort.Slice(expected, func(i, j int) bool {
		return launchRouteDependencyKey(expected[i]) < launchRouteDependencyKey(expected[j])
	})
	if len(actual) != len(expected) {
		return errors.New("launch route cross-placement dependency set is incomplete")
	}
	previous := ""
	for index, dependency := range actual {
		key := launchRouteDependencyKey(dependency)
		if key <= previous || dependency != expected[index] {
			return errors.New("launch route cross-placement dependencies do not exactly match workload edges")
		}
		previous = key
	}
	return nil
}

func validateLaunchResourceAssignments(resources LaunchResourceGraph, graph LaunchWorkloadGraph, placements map[string]LaunchRoutePlacement, nodePlacement map[string]string) error {
	covered := make(map[string]bool, len(graph.Nodes))
	for _, resource := range resources.Nodes {
		if _, ok := placements[resource.PlacementID]; !ok || nodePlacement[resource.WorkloadNodeID] != resource.PlacementID {
			return fmt.Errorf("launch resource %s crosses its approved workload placement", resource.ResourceID)
		}
		node, ok := findLaunchWorkloadNode(graph, resource.WorkloadNodeID)
		if !ok || node.LifecycleClass != resource.LifecycleClass {
			return fmt.Errorf("launch resource %s lifecycle does not match workload", resource.ResourceID)
		}
		covered[resource.WorkloadNodeID] = true
	}
	for _, node := range graph.Nodes {
		if !covered[node.NodeID] {
			return fmt.Errorf("launch workload node %s has no resource plan", node.NodeID)
		}
	}
	return nil
}

func validateLaunchQuotePlacements(quote LaunchRouteQuote, placements []LaunchRoutePlacement, profilesByPlacement map[string]LaunchProviderCapabilityProfile, constraints LaunchConstraintSet, resolver LaunchRouteArtifactResolver, tenantID, workspaceID string) error {
	if len(quote.PlacementCosts) != len(placements) {
		return errors.New("launch route quote placement count does not match route")
	}
	for index, line := range quote.PlacementCosts {
		placement := placements[index]
		profile, ok := profilesByPlacement[placement.PlacementID]
		if !ok {
			return fmt.Errorf("launch route quote placement %s has no verified provider profile", line.PlacementID)
		}
		if line.PlacementID != placement.PlacementID || line.ProviderID != placement.ProviderID || !launchConstantEqual(line.ProviderAccountHash, placement.ProviderAccountHash) || line.RegionID != placement.RegionID || line.OfferingID != placement.OfferingID {
			return fmt.Errorf("launch route quote placement %s does not match route", line.PlacementID)
		}
		if !launchConstantEqual(line.PriceEvidenceHash, profile.PricingEvidenceHash) || !launchConstantEqual(line.TermsEvidenceHash, profile.TermsEvidenceHash) {
			return fmt.Errorf("launch route quote placement %s does not match its certified provider price and terms evidence", line.PlacementID)
		}
		if len(constraints.AllowedCommitmentTerms) > 0 && !containsLaunchSorted(constraints.AllowedCommitmentTerms, line.CommitmentTerm) {
			return fmt.Errorf("launch route commitment term %s is denied by constraints", line.CommitmentTerm)
		}
		snapshot, err := resolver.ResolveLaunchOfferSnapshot(line.OfferSnapshotRef)
		if err != nil {
			return fmt.Errorf("resolve launch offer snapshot %s: %w", line.OfferSnapshotRef, err)
		}
		if err := ValidateLaunchOfferSnapshot(snapshot); err != nil {
			return err
		}
		snapshotHash, err := DeriveLaunchOfferSnapshotHash(snapshot)
		if err != nil || snapshot.SnapshotID != line.OfferSnapshotRef || !launchConstantEqual(snapshotHash, line.OfferSnapshotHash) {
			return fmt.Errorf("launch route quote placement %s offer snapshot hash mismatch", line.PlacementID)
		}
		if snapshot.TenantID != tenantID || snapshot.WorkspaceID != workspaceID || snapshot.ProviderID != placement.ProviderID || snapshot.ProviderAccountRef != placement.ProviderAccountRef || !launchConstantEqual(snapshot.ProviderAccountHash, placement.ProviderAccountHash) || snapshot.Currency != quote.Currency || snapshot.Status != line.CreditStatus || snapshot.VerifiedCreditMinor != line.VerifiedCreditMinor || !launchConstantEqual(snapshot.TermsHash, line.TermsEvidenceHash) {
			return fmt.Errorf("launch route quote placement %s offer snapshot does not bind its exact account, terms, or credit", line.PlacementID)
		}
		snapshotRetrieved, _ := time.Parse(time.RFC3339Nano, snapshot.RetrievedAt)
		snapshotExpiry, _ := time.Parse(time.RFC3339Nano, snapshot.ExpiresAt)
		quoteRetrieved, _ := time.Parse(time.RFC3339Nano, quote.RetrievedAt)
		quoteExpiry, _ := time.Parse(time.RFC3339Nano, quote.ExpiresAt)
		if quoteRetrieved.Before(snapshotRetrieved) || quoteExpiry.After(snapshotExpiry) {
			return fmt.Errorf("launch route quote placement %s outlives or predates its offer evidence", line.PlacementID)
		}
	}
	return nil
}

func findLaunchProviderOffering(profile LaunchProviderCapabilityProfile, regionID, offeringID string) (LaunchProviderRegion, LaunchProviderOffering, bool) {
	for _, region := range profile.Regions {
		if region.RegionID != regionID {
			continue
		}
		for _, offering := range region.Offerings {
			if offering.OfferingID == offeringID {
				return region, offering, true
			}
		}
	}
	return LaunchProviderRegion{}, LaunchProviderOffering{}, false
}

func findLaunchWorkloadNode(graph LaunchWorkloadGraph, nodeID string) (LaunchWorkloadNode, bool) {
	index := sort.Search(len(graph.Nodes), func(i int) bool { return graph.Nodes[i].NodeID >= nodeID })
	if index < len(graph.Nodes) && graph.Nodes[index].NodeID == nodeID {
		return graph.Nodes[index], true
	}
	return LaunchWorkloadNode{}, false
}

func launchRouteDependencyKey(value LaunchRouteDependency) string {
	return value.FromPlacementID + "\x00" + value.ToPlacementID + "\x00" + value.Relationship + "\x00" + value.WorkloadEdgeHash
}

func launchLifecycleClassKnown(value string) bool {
	_, ok := launchLifecycleClasses[value]
	return ok
}

func validateSortedUniqueKnownWorkloads(values []string) error {
	if err := validateSortedUniqueNonEmpty(values, "supported workload kinds"); err != nil {
		return err
	}
	for _, value := range values {
		if !launchWorkloadKindPattern.MatchString(value) || value == "unknown" {
			return fmt.Errorf("launch provider profile has invalid or unresolved workload kind %q", value)
		}
	}
	return nil
}

func validateSortedUniqueKnownValues(values []string, name string, known map[string]struct{}) error {
	if err := validateSortedUniqueOptional(values, name); err != nil {
		return err
	}
	for _, value := range values {
		if _, ok := known[value]; !ok {
			return fmt.Errorf("%s has unknown value %q", name, value)
		}
	}
	return nil
}

func validateSortedUniqueNonEmpty(values []string, name string) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must not be empty", name)
	}
	if !sort.StringsAreSorted(values) {
		return fmt.Errorf("%s must be sorted", name)
	}
	previous := ""
	for _, value := range values {
		if strings.TrimSpace(value) == "" || value == previous {
			return fmt.Errorf("%s must contain unique non-empty values", name)
		}
		previous = value
	}
	return nil
}
