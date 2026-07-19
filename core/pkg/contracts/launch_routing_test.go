package contracts_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestLaunchRoutingSchemasAndDigitalOceanCandidateProfile(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "protocols", "conformance", "launch", "providers", "digitalocean", "app_platform.candidate.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if err := compileSchema(t, "effects/launch/provider_capability_profile.v1.json").Validate(raw); err != nil {
		t.Fatalf("DigitalOcean candidate profile violates provider-neutral schema: %v", err)
	}
	var profile contracts.LaunchProviderCapabilityProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatal(err)
	}
	if err := contracts.ValidateLaunchProviderCapabilityProfile(profile); err != nil {
		t.Fatalf("DigitalOcean candidate profile violates semantic contract: %v", err)
	}
	if profile.CertificationStatus != contracts.LaunchProviderProfileCandidate || profile.DispatchAdmitted {
		t.Fatal("DigitalOcean conformance fixture must not claim completed connector certification or dispatch authority")
	}

	graph := launchHTTPWorkloadGraph()
	analysis := launchRepositoryAnalysis(t, graph, contracts.LaunchAnalysisSupported)
	for schema, value := range map[string]any{
		"effects/launch/workload_graph.v1.json":      graph,
		"effects/launch/repository_analysis.v1.json": analysis,
	} {
		if err := validateAgainstSchema(t, compileSchema(t, schema), value); err != nil {
			t.Fatalf("%s rejected provider-neutral routing fixture: %v", schema, err)
		}
	}
	if err := contracts.ValidateLaunchRepositoryAnalysisGraph(analysis, graph); err != nil {
		t.Fatalf("repository analysis graph binding rejected: %v", err)
	}

	now := time.Date(2026, 7, 19, 1, 0, 0, 0, time.UTC)
	route := launchRouteForProfile(t, profile, graph, "fra", "EU")
	if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/route_binding.v1.json"), route); err != nil {
		t.Fatalf("provider-neutral route schema rejected DigitalOcean route: %v", err)
	}
	if err := contracts.ValidateLaunchRouteBinding(route, profile, graph, now, false); err != nil {
		t.Fatalf("candidate DigitalOcean route rejected during non-executable analysis: %v", err)
	}
	if err := contracts.ValidateLaunchRouteBinding(route, profile, graph, now, true); err == nil {
		t.Fatal("candidate DigitalOcean profile was treated as certified dispatch authority")
	}
}

func TestOneWorkloadGraphRoutesAcrossDifferentCloudProfiles(t *testing.T) {
	graph := launchHTTPWorkloadGraph()
	digitalOcean := launchProviderProfile("digitalocean", "digitalocean-app-platform", "fra", "EU", "do")
	aws := launchProviderProfile("aws", "aws-application-runtime", "eu-central-1", "EU", "aws")
	now := time.Date(2026, 7, 19, 1, 0, 0, 0, time.UTC)

	for name, candidate := range map[string]struct {
		profile contracts.LaunchProviderCapabilityProfile
		region  string
	}{
		"digitalocean": {digitalOcean, "fra"},
		"aws":          {aws, "eu-central-1"},
	} {
		t.Run(name, func(t *testing.T) {
			route := launchRouteForProfile(t, candidate.profile, graph, candidate.region, "EU")
			if err := contracts.ValidateLaunchRouteBinding(route, candidate.profile, graph, now, false); err != nil {
				t.Fatalf("same workload graph failed provider-neutral routing: %v", err)
			}
		})
	}
}

func TestArbitraryRepositoryWorkloadsRemainExplicitInsteadOfBecomingWebsite(t *testing.T) {
	graph := contracts.LaunchWorkloadGraph{
		SchemaVersion: contracts.LaunchWorkloadGraphSchemaVersion,
		GraphID:       "workload-graph-composite", TenantID: "tenant-1", WorkspaceID: "workspace-1",
		SourceCommitSHA: strings.Repeat("b", 40), SourceTreeHash: launchHash("1"), UnknownSetHash: launchHash("2"),
		Nodes: []contracts.LaunchWorkloadNode{
			{NodeID: "database", Kind: "database", DefinitionHash: launchHash("3"), RequirementsHash: launchHash("4"), RequiredCapabilities: []string{"managed-postgresql", "persistent-storage"}, Deployability: contracts.LaunchAnalysisNeedsInput},
			{NodeID: "worker", Kind: "worker", DefinitionHash: launchHash("5"), RequirementsHash: launchHash("6"), RequiredCapabilities: []string{"background-process", "queue-consumer"}, Deployability: contracts.LaunchAnalysisNeedsInput},
		},
		Edges: []contracts.LaunchWorkloadEdge{{FromNodeID: "worker", ToNodeID: "database", Relationship: "writes_to"}},
	}
	if err := contracts.ValidateLaunchWorkloadGraph(graph); err != nil {
		t.Fatalf("non-website workload graph was not representable: %v", err)
	}
	analysis := launchRepositoryAnalysis(t, graph, contracts.LaunchAnalysisNeedsInput)
	if err := contracts.ValidateLaunchRepositoryAnalysisGraph(analysis, graph); err != nil {
		t.Fatalf("non-website repository analysis was not representable: %v", err)
	}

	digitalOceanStaticProfile := launchProviderProfile("digitalocean", "digitalocean-app-platform", "fra", "EU", "do")
	route := launchRouteForProfile(t, digitalOceanStaticProfile, graph, "fra", "EU")
	if err := contracts.ValidateLaunchRouteBinding(route, digitalOceanStaticProfile, graph, time.Date(2026, 7, 19, 1, 0, 0, 0, time.UTC), false); err == nil {
		t.Fatal("static/stateless provider profile silently collapsed database and worker workloads into a website route")
	}
}

func TestUnknownRepositoryAnalysisCannotFabricateAWorkloadGraph(t *testing.T) {
	analysis := contracts.LaunchRepositoryAnalysis{
		SchemaVersion: contracts.LaunchRepositoryAnalysisSchemaVersion,
		AnalysisID:    "analysis-unknown", TenantID: "tenant-1", WorkspaceID: "workspace-1", RepositoryRef: "repo-1",
		SourceCommitSHA: strings.Repeat("c", 40), SourceTreeHash: launchHash("1"), AnalyzerContractHash: launchHash("2"),
		Status: contracts.LaunchAnalysisUnknown, FindingSetHash: launchHash("3"), AnalyzedAt: "2026-07-19T01:00:00Z",
	}
	if err := contracts.ValidateLaunchRepositoryAnalysis(analysis); err != nil {
		t.Fatalf("truthful UNKNOWN repository analysis was rejected: %v", err)
	}
	analysis.WorkloadGraphRef = "fabricated-graph"
	analysis.WorkloadGraphHash = launchHash("4")
	if err := contracts.ValidateLaunchRepositoryAnalysis(analysis); err == nil {
		t.Fatal("UNKNOWN repository analysis fabricated a workload graph")
	}
}

func launchHTTPWorkloadGraph() contracts.LaunchWorkloadGraph {
	return contracts.LaunchWorkloadGraph{
		SchemaVersion: contracts.LaunchWorkloadGraphSchemaVersion,
		GraphID:       "workload-graph-http", TenantID: "tenant-1", WorkspaceID: "workspace-1",
		SourceCommitSHA: strings.Repeat("a", 40), SourceTreeHash: launchHash("1"), UnknownSetHash: launchHash("2"),
		Nodes: []contracts.LaunchWorkloadNode{{
			NodeID: "api", Kind: "http_service", DefinitionHash: launchHash("3"), RequirementsHash: launchHash("4"),
			RequiredCapabilities: []string{"health-check", "https-endpoint", "stateless-runtime"}, Deployability: contracts.LaunchAnalysisSupported,
		}},
		Edges: []contracts.LaunchWorkloadEdge{},
	}
}

func launchRepositoryAnalysis(t *testing.T, graph contracts.LaunchWorkloadGraph, status string) contracts.LaunchRepositoryAnalysis {
	t.Helper()
	graphHash, err := contracts.DeriveLaunchWorkloadGraphHash(graph)
	if err != nil {
		t.Fatal(err)
	}
	return contracts.LaunchRepositoryAnalysis{
		SchemaVersion: contracts.LaunchRepositoryAnalysisSchemaVersion,
		AnalysisID:    "analysis-1", TenantID: graph.TenantID, WorkspaceID: graph.WorkspaceID, RepositoryRef: "repository-1",
		SourceCommitSHA: graph.SourceCommitSHA, SourceTreeHash: graph.SourceTreeHash, AnalyzerContractHash: launchHash("5"),
		Status: status, WorkloadGraphRef: graph.GraphID, WorkloadGraphHash: graphHash, FindingSetHash: launchHash("6"), AnalyzedAt: "2026-07-19T01:00:00Z",
	}
}

func launchProviderProfile(provider, connector, region, jurisdiction, urnPrefix string) contracts.LaunchProviderCapabilityProfile {
	return contracts.LaunchProviderCapabilityProfile{
		SchemaVersion: contracts.LaunchProviderProfileSchemaVersion,
		ProfileID:     provider + "-candidate", ProviderID: provider, ConnectorID: connector, ConnectorContractHash: launchHash("d"), ProfileVersion: "candidate-1",
		CertificationStatus: contracts.LaunchProviderProfileCandidate, DispatchAdmitted: false,
		SupportedWorkloads: []string{"http_service", "static_site"},
		Regions:            []contracts.LaunchProviderRegion{{RegionID: region, Jurisdiction: jurisdiction, ResidencyTags: []string{"eu"}}},
		Actions: []contracts.LaunchProviderAction{
			{EffectID: contracts.EffectTypeDeployProductionActivate, ActionURN: "urn:test:" + urnPrefix + ":activate", ReconciliationMode: "OPERATION_POLL", IdempotencyMode: "RECONCILE_BEFORE_RETRY"},
			{EffectID: contracts.EffectTypeProviderProvision, ActionURN: "urn:test:" + urnPrefix + ":provision", ReconciliationMode: "OPERATION_POLL", IdempotencyMode: "RECONCILE_BEFORE_RETRY"},
			{EffectID: contracts.EffectTypeProviderRollback, ActionURN: "urn:test:" + urnPrefix + ":rollback", ReconciliationMode: "OPERATION_POLL", IdempotencyMode: "COMPARE_AND_SET"},
			{EffectID: contracts.EffectTypeProviderTeardown, ActionURN: "urn:test:" + urnPrefix + ":teardown", ReconciliationMode: "READ_AFTER_WRITE", IdempotencyMode: "RECONCILE_BEFORE_RETRY"},
		},
		PricingEvidenceRef: "fixture://" + provider + "/pricing", PricingEvidenceHash: launchHash("a"),
		TermsEvidenceRef: "fixture://" + provider + "/terms", TermsEvidenceHash: launchHash("b"),
		RetrievedAt: "2026-07-19T00:00:00Z", ExpiresAt: "2026-07-20T00:00:00Z",
	}
}

func launchRouteForProfile(t *testing.T, profile contracts.LaunchProviderCapabilityProfile, graph contracts.LaunchWorkloadGraph, region, jurisdiction string) contracts.LaunchRouteBinding {
	t.Helper()
	graphHash, err := contracts.DeriveLaunchWorkloadGraphHash(graph)
	if err != nil {
		t.Fatal(err)
	}
	profileHash, err := contracts.DeriveLaunchProviderCapabilityProfileHash(profile)
	if err != nil {
		t.Fatal(err)
	}
	actions := []contracts.LaunchRouteActionBinding{
		{EffectID: contracts.EffectTypeDeployProductionActivate, ProviderActionURN: profile.Actions[0].ActionURN, ProviderPayloadHash: launchHash("7")},
		{EffectID: contracts.EffectTypeProviderProvision, ProviderActionURN: profile.Actions[1].ActionURN, ProviderPayloadHash: launchHash("8")},
	}
	return contracts.LaunchRouteBinding{
		SchemaVersion: contracts.LaunchRouteBindingSchemaVersion,
		RouteID:       "route-" + profile.ProviderID, TenantID: graph.TenantID, WorkspaceID: graph.WorkspaceID, MissionID: "mission-1",
		RepositoryAnalysisRef: "analysis-1", RepositoryAnalysisHash: launchHash("0"),
		WorkloadGraphRef: graph.GraphID, WorkloadGraphHash: graphHash,
		ProviderProfileRef: profile.ProfileID, ProviderProfileHash: profileHash,
		ProviderID: profile.ProviderID, ProviderAccountRef: "provider-account-1", ProviderAccountHash: launchHash("1"),
		Region: region, Jurisdiction: jurisdiction, ProviderConnectorID: profile.ConnectorID, ProviderConnectorContractHash: profile.ConnectorContractHash,
		ActionBindings: actions, ResourceGraphHash: launchHash("2"), GeneratedSpecHash: launchHash("3"),
		RouteQuoteRef: "route-quote-1", RouteQuoteHash: launchHash("4"), ConstraintSetHash: launchHash("5"), ProviderPayloadSetHash: launchHash("6"),
		ExpiresAt: "2026-07-19T12:00:00Z",
	}
}
