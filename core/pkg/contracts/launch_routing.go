package contracts

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
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
	LaunchProviderProfileCertified = "CERTIFIED"
	LaunchProviderProfileRevoked   = "REVOKED"
)

var launchCommitPattern = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)

// LaunchRepositoryAnalysis records what was actually inspected. It never
// equates "repository accepted" with "repository deployable": unsupported,
// incomplete, and unknown analyses are first-class signed outcomes.
type LaunchRepositoryAnalysis struct {
	SchemaVersion        string `json:"schema_version"`
	AnalysisID           string `json:"analysis_id"`
	TenantID             string `json:"tenant_id"`
	WorkspaceID          string `json:"workspace_id"`
	RepositoryRef        string `json:"repository_ref"`
	SourceCommitSHA      string `json:"source_commit_sha"`
	SourceTreeHash       string `json:"source_tree_hash"`
	AnalyzerContractHash string `json:"analyzer_contract_hash"`
	Status               string `json:"status"`
	WorkloadGraphRef     string `json:"workload_graph_ref,omitempty"`
	WorkloadGraphHash    string `json:"workload_graph_hash,omitempty"`
	FindingSetHash       string `json:"finding_set_hash"`
	AnalyzedAt           string `json:"analyzed_at"`
}

// LaunchWorkloadGraph is provider-neutral. Nodes describe desired workload
// capabilities, not cloud SKUs, so one graph can be evaluated against several
// independently versioned provider profiles.
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

// LaunchProviderCapabilityProfile is provider-owned routing evidence. Kernel
// contracts never enumerate cloud regions, hostnames, or SKUs; those facts are
// supplied by a content-addressed profile and certified connector contract.
type LaunchProviderCapabilityProfile struct {
	SchemaVersion         string                 `json:"schema_version"`
	ProfileID             string                 `json:"profile_id"`
	ProviderID            string                 `json:"provider_id"`
	ConnectorID           string                 `json:"connector_id"`
	ConnectorContractHash string                 `json:"connector_contract_hash"`
	ProfileVersion        string                 `json:"profile_version"`
	CertificationStatus   string                 `json:"certification_status"`
	DispatchAdmitted      bool                   `json:"dispatch_admitted"`
	SupportedWorkloads    []string               `json:"supported_workload_kinds"`
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
	RegionID      string   `json:"region_id"`
	Jurisdiction  string   `json:"jurisdiction"`
	ResidencyTags []string `json:"residency_tags"`
}

type LaunchProviderAction struct {
	EffectID           string `json:"effect_id"`
	ActionURN          string `json:"action_urn"`
	ReconciliationMode string `json:"reconciliation_mode"`
	IdempotencyMode    string `json:"idempotency_mode"`
}

// LaunchRouteBinding is the exact, approval-bound choice produced after a
// workload graph is matched to one provider profile. ProviderPayloadSetHash
// covers the connector-specific requests without admitting them into the
// provider-neutral schema.
type LaunchRouteBinding struct {
	SchemaVersion                 string                     `json:"schema_version"`
	RouteID                       string                     `json:"route_id"`
	TenantID                      string                     `json:"tenant_id"`
	WorkspaceID                   string                     `json:"workspace_id"`
	MissionID                     string                     `json:"mission_id"`
	RepositoryAnalysisRef         string                     `json:"repository_analysis_ref"`
	RepositoryAnalysisHash        string                     `json:"repository_analysis_hash"`
	WorkloadGraphRef              string                     `json:"workload_graph_ref"`
	WorkloadGraphHash             string                     `json:"workload_graph_hash"`
	ProviderProfileRef            string                     `json:"provider_profile_ref"`
	ProviderProfileHash           string                     `json:"provider_profile_hash"`
	ProviderID                    string                     `json:"provider_id"`
	ProviderAccountRef            string                     `json:"provider_account_ref"`
	ProviderAccountHash           string                     `json:"provider_account_hash"`
	Region                        string                     `json:"region"`
	Jurisdiction                  string                     `json:"jurisdiction"`
	ProviderConnectorID           string                     `json:"provider_connector_id"`
	ProviderConnectorContractHash string                     `json:"provider_connector_contract_hash"`
	ActionBindings                []LaunchRouteActionBinding `json:"action_bindings"`
	ResourceGraphHash             string                     `json:"resource_graph_hash"`
	GeneratedSpecHash             string                     `json:"generated_spec_hash"`
	RouteQuoteRef                 string                     `json:"route_quote_ref"`
	RouteQuoteHash                string                     `json:"route_quote_hash"`
	ConstraintSetHash             string                     `json:"constraint_set_hash"`
	ProviderPayloadSetHash        string                     `json:"provider_payload_set_hash"`
	ExpiresAt                     string                     `json:"expires_at"`
}

type LaunchRouteActionBinding struct {
	EffectID            string `json:"effect_id"`
	ProviderActionURN   string `json:"provider_action_urn"`
	ProviderPayloadHash string `json:"provider_payload_hash"`
}

var launchWorkloadKinds = map[string]struct{}{
	"cache": {}, "database": {}, "function": {}, "gpu_service": {},
	"http_service": {}, "kubernetes": {}, "object_storage": {}, "queue": {},
	"scheduled_job": {}, "static_site": {}, "unknown": {}, "virtual_machine": {},
	"worker": {},
}

var launchRelationships = map[string]struct{}{
	"consumes_from": {}, "depends_on": {}, "publishes_to": {}, "reads_from": {},
	"routes_to": {}, "writes_to": {},
}

// ValidateLaunchRepositoryAnalysis validates analysis identity and the
// explicit distinction between known graphs and an UNKNOWN result.
func ValidateLaunchRepositoryAnalysis(analysis LaunchRepositoryAnalysis) error {
	if analysis.SchemaVersion != LaunchRepositoryAnalysisSchemaVersion || analysis.AnalysisID == "" || analysis.TenantID == "" || analysis.WorkspaceID == "" || analysis.RepositoryRef == "" {
		return errors.New("launch repository analysis identity is incomplete")
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

// DeriveLaunchWorkloadGraphHash returns the RFC 8785 content hash used by
// RepositoryAnalysis and RouteBinding.
func DeriveLaunchWorkloadGraphHash(graph LaunchWorkloadGraph) (string, error) {
	hash, err := canonicalize.CanonicalHash(graph)
	if err != nil {
		return "", fmt.Errorf("derive launch workload graph hash: %w", err)
	}
	return "sha256:" + hash, nil
}

// DeriveLaunchProviderCapabilityProfileHash returns the RFC 8785 content hash
// used by an exact route selection.
func DeriveLaunchProviderCapabilityProfileHash(profile LaunchProviderCapabilityProfile) (string, error) {
	hash, err := canonicalize.CanonicalHash(profile)
	if err != nil {
		return "", fmt.Errorf("derive launch provider capability profile hash: %w", err)
	}
	return "sha256:" + hash, nil
}

// ValidateLaunchRepositoryAnalysisGraph proves that a known analysis binds the
// exact repository commit and graph content supplied to routing.
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
	if analysis.SourceCommitSHA != graph.SourceCommitSHA || !launchConstantEqual(analysis.SourceTreeHash, graph.SourceTreeHash) || !launchConstantEqual(analysis.WorkloadGraphHash, hash) {
		return errors.New("launch repository analysis does not bind the supplied workload graph")
	}
	return nil
}

// ValidateLaunchWorkloadGraph enforces deterministic ordering and referential
// integrity so the same arbitrary repository produces a stable routing input.
func ValidateLaunchWorkloadGraph(graph LaunchWorkloadGraph) error {
	if graph.SchemaVersion != LaunchWorkloadGraphSchemaVersion || graph.GraphID == "" || graph.TenantID == "" || graph.WorkspaceID == "" {
		return errors.New("launch workload graph identity is incomplete")
	}
	if !launchCommitPattern.MatchString(graph.SourceCommitSHA) || !validLaunchSHA256(graph.SourceTreeHash) || !validLaunchSHA256(graph.UnknownSetHash) {
		return errors.New("launch workload graph source or unknown-set hash is invalid")
	}
	if len(graph.Nodes) == 0 {
		return errors.New("launch workload graph must contain at least one node")
	}
	nodes := make(map[string]struct{}, len(graph.Nodes))
	previousNode := ""
	for _, node := range graph.Nodes {
		if node.NodeID == "" || node.NodeID <= previousNode {
			return errors.New("launch workload graph nodes must be unique and sorted by node_id")
		}
		previousNode = node.NodeID
		if _, ok := launchWorkloadKinds[node.Kind]; !ok {
			return fmt.Errorf("launch workload graph node %s has unknown kind %q", node.NodeID, node.Kind)
		}
		if !validLaunchSHA256(node.DefinitionHash) || !validLaunchSHA256(node.RequirementsHash) {
			return fmt.Errorf("launch workload graph node %s has an invalid definition or requirements hash", node.NodeID)
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
	previousEdge := ""
	for _, edge := range graph.Edges {
		key := edge.FromNodeID + "\x00" + edge.ToNodeID + "\x00" + edge.Relationship
		if key <= previousEdge {
			return errors.New("launch workload graph edges must be unique and canonically sorted")
		}
		previousEdge = key
		if _, ok := nodes[edge.FromNodeID]; !ok {
			return fmt.Errorf("launch workload graph edge references unknown source node %q", edge.FromNodeID)
		}
		if _, ok := nodes[edge.ToNodeID]; !ok {
			return fmt.Errorf("launch workload graph edge references unknown target node %q", edge.ToNodeID)
		}
		if _, ok := launchRelationships[edge.Relationship]; !ok {
			return fmt.Errorf("launch workload graph edge has unknown relationship %q", edge.Relationship)
		}
	}
	return nil
}

// ValidateLaunchProviderCapabilityProfile validates a versioned provider fact
// set without treating a candidate profile as certified execution authority.
func ValidateLaunchProviderCapabilityProfile(profile LaunchProviderCapabilityProfile) error {
	if profile.SchemaVersion != LaunchProviderProfileSchemaVersion || profile.ProfileID == "" || profile.ProviderID == "" || profile.ConnectorID == "" || profile.ProfileVersion == "" {
		return errors.New("launch provider capability profile identity is incomplete")
	}
	if !validLaunchSHA256(profile.ConnectorContractHash) || !validLaunchSHA256(profile.PricingEvidenceHash) || !validLaunchSHA256(profile.TermsEvidenceHash) || profile.PricingEvidenceRef == "" || profile.TermsEvidenceRef == "" {
		return errors.New("launch provider capability profile contract or commercial evidence is invalid")
	}
	switch profile.CertificationStatus {
	case LaunchProviderProfileCandidate:
		if profile.DispatchAdmitted {
			return errors.New("candidate launch provider profile cannot be admitted for dispatch")
		}
	case LaunchProviderProfileCertified:
	case LaunchProviderProfileRevoked:
		if profile.DispatchAdmitted {
			return errors.New("revoked launch provider profile cannot be admitted for dispatch")
		}
	default:
		return errors.New("launch provider capability certification status is invalid")
	}
	if err := validateSortedUniqueKnownWorkloads(profile.SupportedWorkloads); err != nil {
		return err
	}
	if len(profile.Regions) == 0 || len(profile.Actions) == 0 {
		return errors.New("launch provider capability profile must declare regions and actions")
	}
	previousRegion := ""
	for _, region := range profile.Regions {
		if region.RegionID == "" || region.RegionID <= previousRegion || region.Jurisdiction == "" {
			return errors.New("launch provider profile regions must be complete, unique, and sorted")
		}
		previousRegion = region.RegionID
		if err := validateSortedUniqueNonEmpty(region.ResidencyTags, "residency tags"); err != nil {
			return fmt.Errorf("launch provider region %s: %w", region.RegionID, err)
		}
	}
	previousAction := ""
	for _, action := range profile.Actions {
		if action.EffectID == "" || action.EffectID <= previousAction || !launchEffectIsProviderMutation(action.EffectID) || action.ActionURN == "" {
			return errors.New("launch provider actions must be registered, unique, and sorted by effect_id")
		}
		previousAction = action.EffectID
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

// ValidateLaunchRouteBinding proves that an exact route is a subset of one
// profile and one workload graph. requireDispatchAuthority must be true at the
// production boundary; preview/conformance code may inspect candidate routes.
func ValidateLaunchRouteBinding(route LaunchRouteBinding, profile LaunchProviderCapabilityProfile, graph LaunchWorkloadGraph, now time.Time, requireDispatchAuthority bool) error {
	if err := ValidateLaunchProviderCapabilityProfile(profile); err != nil {
		return err
	}
	if err := ValidateLaunchWorkloadGraph(graph); err != nil {
		return err
	}
	if route.SchemaVersion != LaunchRouteBindingSchemaVersion || route.RouteID == "" || route.TenantID == "" || route.WorkspaceID == "" || route.MissionID == "" || route.RepositoryAnalysisRef == "" || route.WorkloadGraphRef == "" || route.ProviderProfileRef == "" || route.ProviderAccountRef == "" || route.RouteQuoteRef == "" {
		return errors.New("launch route binding identity is incomplete")
	}
	if route.TenantID != graph.TenantID || route.WorkspaceID != graph.WorkspaceID || route.WorkloadGraphRef != graph.GraphID || route.ProviderProfileRef != profile.ProfileID {
		return errors.New("launch route binding crosses workload or provider profile identity")
	}
	for name, value := range map[string]string{
		"repository_analysis_hash":         route.RepositoryAnalysisHash,
		"workload_graph_hash":              route.WorkloadGraphHash,
		"provider_profile_hash":            route.ProviderProfileHash,
		"provider_account_hash":            route.ProviderAccountHash,
		"provider_connector_contract_hash": route.ProviderConnectorContractHash,
		"resource_graph_hash":              route.ResourceGraphHash,
		"generated_spec_hash":              route.GeneratedSpecHash,
		"route_quote_hash":                 route.RouteQuoteHash,
		"constraint_set_hash":              route.ConstraintSetHash,
		"provider_payload_set_hash":        route.ProviderPayloadSetHash,
	} {
		if !validLaunchSHA256(value) {
			return fmt.Errorf("launch route binding %s is invalid", name)
		}
	}
	graphHash, err := DeriveLaunchWorkloadGraphHash(graph)
	if err != nil {
		return err
	}
	profileHash, err := DeriveLaunchProviderCapabilityProfileHash(profile)
	if err != nil {
		return err
	}
	if !launchConstantEqual(route.WorkloadGraphHash, graphHash) || !launchConstantEqual(route.ProviderProfileHash, profileHash) {
		return errors.New("launch route binding does not match workload graph or provider profile content")
	}
	if route.ProviderID != profile.ProviderID || route.ProviderConnectorID != profile.ConnectorID || !launchConstantEqual(route.ProviderConnectorContractHash, profile.ConnectorContractHash) {
		return errors.New("launch route binding provider or connector does not match capability profile")
	}
	if requireDispatchAuthority && (profile.CertificationStatus != LaunchProviderProfileCertified || !profile.DispatchAdmitted) {
		return errors.New("launch route provider profile is not certified and admitted for dispatch")
	}
	regionFound := false
	for _, region := range profile.Regions {
		if region.RegionID == route.Region && region.Jurisdiction == route.Jurisdiction {
			regionFound = true
			break
		}
	}
	if !regionFound {
		return errors.New("launch route region and jurisdiction are not present in provider profile")
	}
	supported := make(map[string]struct{}, len(profile.SupportedWorkloads))
	for _, kind := range profile.SupportedWorkloads {
		supported[kind] = struct{}{}
	}
	for _, node := range graph.Nodes {
		if _, ok := supported[node.Kind]; !ok {
			return fmt.Errorf("launch route provider does not support workload kind %q", node.Kind)
		}
		if node.Deployability != LaunchAnalysisSupported {
			return fmt.Errorf("launch route cannot bind workload node %s with deployability %s", node.NodeID, node.Deployability)
		}
	}
	profileActions := make(map[string]string, len(profile.Actions))
	for _, action := range profile.Actions {
		profileActions[action.EffectID] = action.ActionURN
	}
	if len(route.ActionBindings) == 0 {
		return errors.New("launch route must bind at least one provider action")
	}
	previousAction := ""
	for _, action := range route.ActionBindings {
		if action.EffectID <= previousAction || action.ProviderActionURN == "" || !validLaunchSHA256(action.ProviderPayloadHash) {
			return errors.New("launch route actions must be complete, unique, and sorted")
		}
		previousAction = action.EffectID
		if expected, ok := profileActions[action.EffectID]; !ok || expected != action.ProviderActionURN {
			return fmt.Errorf("launch route action %s is absent from provider profile", action.EffectID)
		}
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, route.ExpiresAt)
	if err != nil || now.IsZero() || !now.Before(expiresAt) {
		return errors.New("launch route binding is expired or verification time is invalid")
	}
	profileExpiry, _ := time.Parse(time.RFC3339Nano, profile.ExpiresAt)
	if expiresAt.After(profileExpiry) {
		return errors.New("launch route binding outlives its provider profile")
	}
	return nil
}

func validateSortedUniqueKnownWorkloads(values []string) error {
	if len(values) == 0 {
		return errors.New("launch provider profile must support at least one workload kind")
	}
	if err := validateSortedUniqueNonEmpty(values, "supported workload kinds"); err != nil {
		return err
	}
	for _, value := range values {
		if _, ok := launchWorkloadKinds[value]; !ok || value == "unknown" {
			return fmt.Errorf("launch provider profile has unknown workload kind %q", value)
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
