package contracts_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

var launchRoutingNow = time.Date(2026, 7, 19, 1, 0, 0, 0, time.UTC)

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
	if profile.ProfileStatus != contracts.LaunchProviderProfileCandidate {
		t.Fatal("DigitalOcean fixture must remain a candidate, not certification proof")
	}

	fixture := singleLaunchRouteFixture(t, profile, false)
	for schema, value := range map[string]any{
		"effects/launch/workload_graph.v1.json":       fixture.graph,
		"effects/launch/repository_analysis.v1.json":  fixture.analysis,
		"effects/launch/constraint_set.v1.json":       fixture.constraints,
		"effects/launch/offer_snapshot.v1.json":       fixture.offer,
		"effects/launch/route_quote.v1.json":          fixture.quote,
		"effects/launch/resource_graph.v1.json":       fixture.resources,
		"effects/launch/provider_payload_set.v1.json": fixture.payloads,
		"effects/launch/route_binding.v1.json":        fixture.route,
	} {
		if err := validateAgainstSchema(t, compileSchema(t, schema), value); err != nil {
			t.Fatalf("%s rejected universal route fixture: %v", schema, err)
		}
	}
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err != nil {
		t.Fatalf("candidate DigitalOcean route rejected during non-executable analysis: %v", err)
	}
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, true); err == nil {
		t.Fatal("candidate DigitalOcean profile was treated as certified dispatch authority")
	}
}

func TestProviderNeutralProfilePortabilityIsNotCertificationProof(t *testing.T) {
	for name, profile := range map[string]contracts.LaunchProviderCapabilityProfile{
		"digitalocean-shaped": launchProviderProfile("digitalocean", "digitalocean-app-platform", "fra", "do-basic", []string{"http_service", "static_site"}, []string{"health-check", "https-endpoint", "stateless-runtime"}, []string{contracts.LaunchLifecycleEphemeral}, "do"),
		"aws-shaped":          launchProviderProfile("aws", "aws-application-runtime", "eu-central-1", "aws-app", []string{"http_service", "static_site"}, []string{"health-check", "https-endpoint", "stateless-runtime"}, []string{contracts.LaunchLifecycleEphemeral}, "aws"),
	} {
		t.Run(name, func(t *testing.T) {
			fixture := singleLaunchRouteFixture(t, profile, false)
			if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err != nil {
				t.Fatalf("provider-neutral schema portability failed: %v", err)
			}
			if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, true); err == nil {
				t.Fatal("synthetic profile portability was promoted into connector certification")
			}
		})
	}
}

func TestWorkloadKindsAndRelationshipsAreProviderExtensible(t *testing.T) {
	graph := contracts.LaunchWorkloadGraph{
		SchemaVersion: contracts.LaunchWorkloadGraphSchemaVersion, GraphID: "graph-custom", TenantID: "tenant-1", WorkspaceID: "workspace-1",
		SourceCommitSHA: strings.Repeat("c", 40), SourceTreeHash: launchRoutingHash("1"), UnknownSetHash: launchRoutingHash("2"),
		Nodes: []contracts.LaunchWorkloadNode{
			{NodeID: "engine", Kind: "acme.state-machine", LifecycleClass: contracts.LaunchLifecycleStatefulResource, DefinitionHash: launchRoutingHash("3"), RequirementsHash: launchRoutingHash("4"), RequiredCapabilities: []string{"acme-snapshot"}, Deployability: contracts.LaunchAnalysisSupported},
			{NodeID: "replica", Kind: "acme.state-machine", LifecycleClass: contracts.LaunchLifecycleStatefulResource, DefinitionHash: launchRoutingHash("5"), RequirementsHash: launchRoutingHash("6"), RequiredCapabilities: []string{"acme-replication"}, Deployability: contracts.LaunchAnalysisSupported},
		},
		Edges: []contracts.LaunchWorkloadEdge{{FromNodeID: "engine", ToNodeID: "replica", Relationship: "acme.replicates_to"}},
	}
	if err := contracts.ValidateLaunchWorkloadGraph(graph); err != nil {
		t.Fatalf("vendor-extensible workload graph was rejected: %v", err)
	}
	profile := launchProviderProfile("acme-cloud", "acme-connector", "eu-acme-1", "state-machine", []string{"acme.state-machine"}, []string{"acme-replication", "acme-snapshot"}, []string{contracts.LaunchLifecycleStatefulResource}, "acme")
	if err := contracts.ValidateLaunchProviderCapabilityProfile(profile); err != nil {
		t.Fatalf("provider-specific workload capability was rejected: %v", err)
	}
	blueprint, err := contracts.ProjectLaunchBlueprint("blueprint-custom", graph, launchConstraintSet())
	if err != nil {
		t.Fatalf("clean-room fork lost extensible workload semantics: %v", err)
	}
	if blueprint.Nodes[0].Kind != "acme.state-machine" || blueprint.Edges[0].Relationship != "acme.replicates_to" {
		t.Fatal("clean-room blueprint did not preserve provider-neutral workload semantics")
	}

	profile.Regions[0].Offerings[0].SupportedWorkloads = []string{"unknown"}
	if err := contracts.ValidateLaunchProviderCapabilityProfile(profile); err == nil {
		t.Fatal("provider profile claimed analyzer uncertainty as executable workload support")
	}
}

func TestRequiredCapabilitiesAndLifecycleAreMatched(t *testing.T) {
	profile := launchProviderProfile("cloud", "connector", "eu-1", "app", []string{"http_service"}, []string{"health-check", "https-endpoint", "stateless-runtime"}, []string{contracts.LaunchLifecycleEphemeral}, "cloud")
	fixture := singleLaunchRouteFixture(t, profile, false)

	mutated := profile
	mutated.Regions[0].Offerings[0].SupportedCapabilities = []string{"health-check", "https-endpoint"}
	mutatedHash, err := contracts.DeriveLaunchProviderCapabilityProfileHash(mutated)
	if err != nil {
		t.Fatal(err)
	}
	fixture.resolver.profiles[mutated.ProfileID] = mutated
	fixture.route.Placements[0].ProviderProfileHash = mutatedHash
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err == nil || !strings.Contains(err.Error(), "stateless-runtime") {
		t.Fatalf("missing provider capability was not rejected precisely: %v", err)
	}

	mutated = profile
	mutated.Regions[0].Offerings[0].SupportedLifecycles = []string{contracts.LaunchLifecycleStatefulData}
	mutatedHash, _ = contracts.DeriveLaunchProviderCapabilityProfileHash(mutated)
	fixture.resolver.profiles[mutated.ProfileID] = mutated
	fixture.route.Placements[0].ProviderProfileHash = mutatedHash
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err == nil || !strings.Contains(err.Error(), "kind or lifecycle") {
		t.Fatalf("missing provider lifecycle was not rejected: %v", err)
	}
}

func TestMultiProviderRoutePartitionsOneArbitraryRepositoryGraph(t *testing.T) {
	fixture := multiLaunchRouteFixture(t)
	if len(fixture.route.Placements) != 2 || len(fixture.route.PlacementDependencies) != 1 {
		t.Fatal("multi-cloud fixture does not exercise two placements and one cross-placement dependency")
	}
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err != nil {
		t.Fatalf("valid multi-provider route was rejected: %v", err)
	}

	duplicate := fixture.route
	duplicate = cloneLaunchRouteFixture(fixture).route
	duplicate.Placements[1].WorkloadNodeIDs = []string{"api", "database"}
	if err := contracts.ValidateLaunchRouteBinding(duplicate, fixture.resolver, launchRoutingNow, false); err == nil || !strings.Contains(err.Error(), "multiple placements") {
		t.Fatalf("duplicate cross-cloud workload assignment was not rejected: %v", err)
	}

	missingDependency := cloneLaunchRouteFixture(fixture).route
	missingDependency.PlacementDependencies = []contracts.LaunchRouteDependency{}
	if err := contracts.ValidateLaunchRouteBinding(missingDependency, fixture.resolver, launchRoutingNow, false); err == nil || !strings.Contains(err.Error(), "dependency set") {
		t.Fatalf("missing cross-cloud dependency was not rejected: %v", err)
	}
}

func TestRouteRecomputesEveryApprovalBoundArtifact(t *testing.T) {
	profile := launchProviderProfile("cloud", "connector", "eu-1", "app", []string{"http_service"}, []string{"health-check", "https-endpoint", "stateless-runtime"}, []string{contracts.LaunchLifecycleEphemeral}, "cloud")
	base := singleLaunchRouteFixture(t, profile, false)

	for name, mutate := range map[string]func(*launchRouteFixture){
		"analysis hash":        func(f *launchRouteFixture) { f.route.RepositoryAnalysisHash = launchRoutingHash("9") },
		"quote hash":           func(f *launchRouteFixture) { f.route.RouteQuoteHash = launchRoutingHash("9") },
		"resource hash":        func(f *launchRouteFixture) { f.route.ResourceGraphHash = launchRoutingHash("9") },
		"payload set hash":     func(f *launchRouteFixture) { f.route.ProviderPayloadSetHash = launchRoutingHash("9") },
		"GeneratedSpec source": func(f *launchRouteFixture) { f.resolver.generated[f.route.GeneratedSpecRef] = launchRoutingHash("9") },
		"resolved quote": func(f *launchRouteFixture) {
			q := f.quote
			q.CommercialEvidenceHash = launchRoutingHash("9")
			f.resolver.quotes[q.QuoteID] = q
		},
		"quote price evidence outside certified profile": func(f *launchRouteFixture) {
			q := f.quote
			q.PlacementCosts = append([]contracts.LaunchPlacementCost(nil), f.quote.PlacementCosts...)
			q.PlacementCosts[0].PriceEvidenceHash = launchRoutingHash("9")
			qHash, err := contracts.DeriveLaunchRouteQuoteHash(q)
			if err != nil {
				t.Fatal(err)
			}
			f.quote = q
			f.resolver.quotes[q.QuoteID] = q
			f.route.RouteQuoteHash = qHash
		},
		"resolved offer": func(f *launchRouteFixture) {
			offer := f.offer
			offer.ContentVersionHash = launchRoutingHash("9")
			f.resolver.offers[offer.SnapshotID] = offer
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := cloneLaunchRouteFixture(base)
			mutate(&fixture)
			if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err == nil {
				t.Fatal("tampered approval-bound artifact was accepted")
			}
		})
	}
}

func TestOfferSnapshotNeverPromotesAdvisoryCreditToCashReduction(t *testing.T) {
	active := launchOfferSnapshot("cloud", "offer-active", "account:1", launchRoutingHash("1"), launchRoutingHash("2"), contracts.LaunchCreditVerified, 500)
	if err := contracts.ValidateLaunchOfferSnapshot(active); err != nil {
		t.Fatalf("active connected-account credit evidence was rejected: %v", err)
	}
	if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/offer_snapshot.v1.json"), active); err != nil {
		t.Fatalf("offer snapshot schema rejected active evidence: %v", err)
	}

	advisory := active
	advisory.Status = contracts.LaunchCreditAdvisory
	if err := contracts.ValidateLaunchOfferSnapshot(advisory); err == nil {
		t.Fatal("advisory benefit eligibility reduced expected cash")
	}
	advisory.VerifiedCreditMinor = 0
	if err := contracts.ValidateLaunchOfferSnapshot(advisory); err != nil {
		t.Fatalf("zero-value advisory offer evidence was rejected: %v", err)
	}
	missingAccount := active
	missingAccount.ProviderAccountRef = ""
	missingAccount.ProviderAccountHash = ""
	if err := contracts.ValidateLaunchOfferSnapshot(missingAccount); err == nil {
		t.Fatal("unbound provider credit was represented as active and verified")
	}
	credentialURL := active
	credentialURL.OfficialSourceURL = "https://token@example.invalid/offers"
	if err := contracts.ValidateLaunchOfferSnapshot(credentialURL); err == nil {
		t.Fatal("credential-bearing official offer URL was admitted")
	}
}

func TestProviderCertificationRequiresSignatureTrustAndCurrentRegistryState(t *testing.T) {
	profile := launchProviderProfile("cloud", "connector", "eu-1", "app", []string{"http_service"}, []string{"health-check", "https-endpoint", "stateless-runtime"}, []string{contracts.LaunchLifecycleEphemeral}, "cloud")
	fixture := singleLaunchRouteFixture(t, profile, true)
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, true); err != nil {
		t.Fatalf("signed current certification was rejected: %v", err)
	}

	fixture.resolver.current[fixture.certification.CertificationID] = launchRoutingHash("9")
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, true); err == nil || !strings.Contains(err.Error(), "not current") {
		t.Fatalf("revoked/superseded certification remained authoritative: %v", err)
	}

	fixture = singleLaunchRouteFixture(t, profile, true)
	_, wrongPrivate, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{9}, 64)))
	fixture.resolver.keys[fixture.certification.SignerKeyID] = wrongPrivate.Public().(ed25519.PublicKey)
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, true); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("untrusted certification key was accepted: %v", err)
	}
}

func TestRepositoryAnalysisStatusIsExactGraphAggregate(t *testing.T) {
	graph := launchHTTPWorkloadGraph()
	analysis := launchRepositoryAnalysis(t, graph)
	analysis.Status = contracts.LaunchAnalysisNeedsInput
	if err := contracts.ValidateLaunchRepositoryAnalysisGraph(analysis, graph); err == nil || !strings.Contains(err.Error(), "aggregate") {
		t.Fatalf("analysis status drift was accepted: %v", err)
	}

	graph.Nodes[0].Deployability = contracts.LaunchAnalysisUnknown
	if got := contracts.AggregateLaunchWorkloadGraphStatus(graph); got != contracts.LaunchAnalysisUnknown {
		t.Fatalf("UNKNOWN node did not freeze aggregate analysis: %s", got)
	}
}

func TestOpaqueSourceReferenceRejectsCredentialBearingURL(t *testing.T) {
	graph := launchHTTPWorkloadGraph()
	analysis := launchRepositoryAnalysis(t, graph)
	analysis.SourceConnectionRef = "https://token@example.invalid/private.git?secret=1"
	if err := contracts.ValidateLaunchRepositoryAnalysis(analysis); err == nil {
		t.Fatal("credential-bearing repository URL was accepted as a source reference")
	}
}

func TestLaunchBlueprintIsCleanRoomAndProviderNeutral(t *testing.T) {
	graph := launchHTTPWorkloadGraph()
	graph.Nodes[0].NodeID = "private-service-name"
	constraints := launchConstraintSet()
	constraints.AllowedProviders = []string{"private-cloud-provider"}
	blueprint, err := contracts.ProjectLaunchBlueprint("blueprint-public-1", graph, constraints)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/launch_blueprint.v1.json"), blueprint); err != nil {
		t.Fatalf("clean-room blueprint violates schema: %v", err)
	}
	data, err := json.Marshal(blueprint)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"tenant-1", "workspace-1", "source:", "private-service-name", "private-cloud-provider", "provider_account", "approval", "receipt", "evidence_pack"} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("clean-room blueprint leaked %q: %s", forbidden, data)
		}
	}
	if hash, err := contracts.DeriveLaunchBlueprintHash(blueprint); err != nil || !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("clean-room blueprint is not content addressable: %s %v", hash, err)
	}
}

type launchRouteFixture struct {
	route         contracts.LaunchRouteBinding
	resolver      *launchTestResolver
	analysis      contracts.LaunchRepositoryAnalysis
	graph         contracts.LaunchWorkloadGraph
	constraints   contracts.LaunchConstraintSet
	quote         contracts.LaunchRouteQuote
	offer         contracts.LaunchOfferSnapshot
	resources     contracts.LaunchResourceGraph
	payloads      contracts.LaunchProviderPayloadSet
	certification contracts.LaunchProviderCertificationRecord
}

type launchTestResolver struct {
	analyses       map[string]contracts.LaunchRepositoryAnalysis
	graphs         map[string]contracts.LaunchWorkloadGraph
	profiles       map[string]contracts.LaunchProviderCapabilityProfile
	certifications map[string]contracts.LaunchProviderCertificationRecord
	constraints    map[string]contracts.LaunchConstraintSet
	quotes         map[string]contracts.LaunchRouteQuote
	offers         map[string]contracts.LaunchOfferSnapshot
	resources      map[string]contracts.LaunchResourceGraph
	payloads       map[string]contracts.LaunchProviderPayloadSet
	generated      map[string]string
	keys           map[string]ed25519.PublicKey
	current        map[string]string
}

func (r *launchTestResolver) ResolveLaunchRepositoryAnalysis(ref string) (contracts.LaunchRepositoryAnalysis, error) {
	value, ok := r.analyses[ref]
	if !ok {
		return value, errors.New("analysis not found")
	}
	return value, nil
}
func (r *launchTestResolver) ResolveLaunchWorkloadGraph(ref string) (contracts.LaunchWorkloadGraph, error) {
	value, ok := r.graphs[ref]
	if !ok {
		return value, errors.New("graph not found")
	}
	return value, nil
}
func (r *launchTestResolver) ResolveLaunchProviderProfile(ref string) (contracts.LaunchProviderCapabilityProfile, error) {
	value, ok := r.profiles[ref]
	if !ok {
		return value, errors.New("profile not found")
	}
	return value, nil
}
func (r *launchTestResolver) ResolveLaunchProviderCertification(ref string) (contracts.LaunchProviderCertificationRecord, error) {
	value, ok := r.certifications[ref]
	if !ok {
		return value, errors.New("certification not found")
	}
	return value, nil
}
func (r *launchTestResolver) ResolveLaunchConstraintSet(ref string) (contracts.LaunchConstraintSet, error) {
	value, ok := r.constraints[ref]
	if !ok {
		return value, errors.New("constraints not found")
	}
	return value, nil
}
func (r *launchTestResolver) ResolveLaunchRouteQuote(ref string) (contracts.LaunchRouteQuote, error) {
	value, ok := r.quotes[ref]
	if !ok {
		return value, errors.New("quote not found")
	}
	return value, nil
}
func (r *launchTestResolver) ResolveLaunchOfferSnapshot(ref string) (contracts.LaunchOfferSnapshot, error) {
	value, ok := r.offers[ref]
	if !ok {
		return value, errors.New("offer snapshot not found")
	}
	return value, nil
}
func (r *launchTestResolver) ResolveLaunchResourceGraph(ref string) (contracts.LaunchResourceGraph, error) {
	value, ok := r.resources[ref]
	if !ok {
		return value, errors.New("resources not found")
	}
	return value, nil
}
func (r *launchTestResolver) ResolveLaunchProviderPayloadSet(ref string) (contracts.LaunchProviderPayloadSet, error) {
	value, ok := r.payloads[ref]
	if !ok {
		return value, errors.New("payloads not found")
	}
	return value, nil
}
func (r *launchTestResolver) ResolveLaunchGeneratedSpecHash(ref string) (string, error) {
	value, ok := r.generated[ref]
	if !ok {
		return "", errors.New("GeneratedSpec not found")
	}
	return value, nil
}
func (r *launchTestResolver) ResolveLaunchCertificationKey(ref string) (ed25519.PublicKey, error) {
	value, ok := r.keys[ref]
	if !ok {
		return nil, errors.New("key not found")
	}
	return value, nil
}
func (r *launchTestResolver) AssertLaunchCertificationCurrent(id, hash string) error {
	if r.current[id] != hash {
		return errors.New("record is revoked or superseded")
	}
	return nil
}

func singleLaunchRouteFixture(t *testing.T, profile contracts.LaunchProviderCapabilityProfile, certified bool) launchRouteFixture {
	t.Helper()
	graph := launchHTTPWorkloadGraph()
	analysis := launchRepositoryAnalysis(t, graph)
	constraints := launchConstraintSet()
	graphHash, _ := contracts.DeriveLaunchWorkloadGraphHash(graph)
	constraintHash, _ := contracts.DeriveLaunchConstraintSetHash(constraints)
	profileHash, _ := contracts.DeriveLaunchProviderCapabilityProfileHash(profile)
	region := profile.Regions[0]
	offering := region.Offerings[0]
	resources := contracts.LaunchResourceGraph{
		SchemaVersion: contracts.LaunchResourceGraphSchemaVersion, ResourceGraphID: "resource-graph-1",
		TenantID: "tenant-1", WorkspaceID: "workspace-1", MissionID: "mission-1",
		Nodes: []contracts.LaunchResourceNode{{ResourceID: "resource-api", PlacementID: "placement-1", WorkloadNodeID: "api", ResourceKind: "service", LifecycleClass: contracts.LaunchLifecycleEphemeral, DesiredStateHash: launchRoutingHash("2"), OwnershipTagHash: launchRoutingHash("3")}},
		Edges: []contracts.LaunchResourceEdge{},
	}
	offer := launchOfferSnapshot(profile.ProviderID, "offer-snapshot-1", "account:1", launchRoutingHash("1"), profile.TermsEvidenceHash, contracts.LaunchCreditVerified, 200)
	offerHash, _ := contracts.DeriveLaunchOfferSnapshotHash(offer)
	payloads := contracts.LaunchProviderPayloadSet{
		SchemaVersion: contracts.LaunchProviderPayloadSetSchemaVersion, PayloadSetID: "payload-set-1",
		TenantID: "tenant-1", WorkspaceID: "workspace-1", MissionID: "mission-1",
		Entries: []contracts.LaunchProviderPayloadEntry{
			{PlacementID: "placement-1", EffectID: contracts.EffectTypeDeployProductionActivate, ProviderActionURN: profile.Actions[0].ActionURN, PayloadHash: launchRoutingHash("7")},
			{PlacementID: "placement-1", EffectID: contracts.EffectTypeProviderProvision, ProviderActionURN: profile.Actions[1].ActionURN, PayloadHash: launchRoutingHash("8")},
			{PlacementID: "placement-1", EffectID: contracts.EffectTypeProviderRollback, ProviderActionURN: profile.Actions[2].ActionURN, PayloadHash: launchRoutingHash("9")},
			{PlacementID: "placement-1", EffectID: contracts.EffectTypeProviderTeardown, ProviderActionURN: profile.Actions[3].ActionURN, PayloadHash: launchRoutingHash("a")},
		},
	}
	quote := contracts.LaunchRouteQuote{
		SchemaVersion: contracts.LaunchRouteQuoteSchemaVersion, QuoteID: "quote-1", TenantID: "tenant-1", WorkspaceID: "workspace-1", MissionID: "mission-1",
		WorkloadGraphHash: graphHash, ConstraintSetHash: constraintHash, Currency: "EUR",
		PlacementCosts:        []contracts.LaunchPlacementCost{{PlacementID: "placement-1", ProviderID: profile.ProviderID, ProviderAccountHash: launchRoutingHash("1"), RegionID: region.RegionID, OfferingID: offering.OfferingID, BillingCadence: "monthly", CommitmentTerm: "monthly", BaseCostMinor: 1000, TaxFXReserveMinor: 200, GrossExposureMinor: 1200, VerifiedCreditMinor: 200, ExpectedCashMinor: 1000, CreditStatus: contracts.LaunchCreditVerified, OfferSnapshotRef: offer.SnapshotID, OfferSnapshotHash: offerHash, PriceEvidenceHash: profile.PricingEvidenceHash, TermsEvidenceHash: profile.TermsEvidenceHash}},
		BaseProviderCostMinor: 1000, TaxFXReserveMinor: 200, GrossExposureMinor: 1200, VerifiedCreditMinor: 200, ExpectedCashMinor: 1000,
		CreditStatus: contracts.LaunchCreditVerified, FXSnapshotHash: launchRoutingHash("5"), TaxSnapshotHash: launchRoutingHash("6"), CommercialEvidenceHash: launchRoutingHash("a"),
		RetrievedAt: "2026-07-19T00:00:00Z", ExpiresAt: "2026-07-19T12:00:00Z",
	}
	quote.CreditSnapshotHash, _ = contracts.DeriveLaunchOfferSnapshotSetHash(quote.PlacementCosts)
	resourceSubsetHash, _ := contracts.DeriveLaunchResourceSubsetHash(resources, "placement-1")
	payloadSubsetHash, _ := contracts.DeriveLaunchProviderPayloadSubsetHash(payloads, "placement-1")
	placement := contracts.LaunchRoutePlacement{
		PlacementID: "placement-1", WorkloadNodeIDs: []string{"api"}, ProviderProfileRef: profile.ProfileID, ProviderProfileHash: profileHash,
		ProviderID: profile.ProviderID, ProviderAccountRef: "account:1", ProviderAccountHash: launchRoutingHash("1"), RegionID: region.RegionID, Jurisdiction: region.Jurisdiction, OfferingID: offering.OfferingID,
		ProviderConnectorID: profile.ConnectorID, ProviderConnectorContractHash: profile.ConnectorContractHash,
		ActionBindings: []contracts.LaunchRouteActionBinding{
			{EffectID: contracts.EffectTypeDeployProductionActivate, ProviderActionURN: profile.Actions[0].ActionURN, ProviderPayloadHash: launchRoutingHash("7")},
			{EffectID: contracts.EffectTypeProviderProvision, ProviderActionURN: profile.Actions[1].ActionURN, ProviderPayloadHash: launchRoutingHash("8")},
			{EffectID: contracts.EffectTypeProviderRollback, ProviderActionURN: profile.Actions[2].ActionURN, ProviderPayloadHash: launchRoutingHash("9")},
			{EffectID: contracts.EffectTypeProviderTeardown, ProviderActionURN: profile.Actions[3].ActionURN, ProviderPayloadHash: launchRoutingHash("a")},
		},
		ResourceSubsetHash: resourceSubsetHash, ProviderPayloadSubsetHash: payloadSubsetHash,
	}
	resolver := newLaunchResolver()
	var certification contracts.LaunchProviderCertificationRecord
	if certified {
		seed := bytes.Repeat([]byte{1}, ed25519.SeedSize)
		privateKey := ed25519.NewKeyFromSeed(seed)
		certification, _ = contracts.SignLaunchProviderCertificationRecord(contracts.LaunchProviderCertificationRecord{
			SchemaVersion: contracts.LaunchProviderCertificationSchemaVersion, CertificationID: "certification-1", ProfileRef: profile.ProfileID, ProfileHash: profileHash,
			ProviderID: profile.ProviderID, ConnectorID: profile.ConnectorID, ConnectorContractHash: profile.ConnectorContractHash,
			CertificationTier: "provider-mutation-tier-1", CertificationSuiteHash: launchRoutingHash("b"), CertificationEvidenceHash: launchRoutingHash("c"), AdmissionStatus: contracts.LaunchProviderCertificationActive,
			IssuedAt: "2026-07-19T00:00:00Z", ExpiresAt: "2026-07-20T00:00:00Z", SignerKeyID: "cert-root-1",
		}, privateKey)
		placement.ProviderCertificationRef = certification.CertificationID
		placement.ProviderCertificationHash = certification.RecordHash
		resolver.certifications[certification.CertificationID] = certification
		resolver.keys[certification.SignerKeyID] = privateKey.Public().(ed25519.PublicKey)
		resolver.current[certification.CertificationID] = certification.RecordHash
	}
	analysisHash, _ := contracts.DeriveLaunchRepositoryAnalysisHash(analysis)
	quoteHash, _ := contracts.DeriveLaunchRouteQuoteHash(quote)
	resourceHash, _ := contracts.DeriveLaunchResourceGraphHash(resources)
	payloadHash, _ := contracts.DeriveLaunchProviderPayloadSetHash(payloads)
	route := contracts.LaunchRouteBinding{
		SchemaVersion: contracts.LaunchRouteBindingSchemaVersion, RouteID: "route-1", TenantID: "tenant-1", WorkspaceID: "workspace-1", MissionID: "mission-1",
		RepositoryAnalysisRef: analysis.AnalysisID, RepositoryAnalysisHash: analysisHash, WorkloadGraphRef: graph.GraphID, WorkloadGraphHash: graphHash,
		ConstraintSetRef: constraints.ConstraintSetID, ConstraintSetHash: constraintHash, RouteQuoteRef: quote.QuoteID, RouteQuoteHash: quoteHash,
		ResourceGraphRef: resources.ResourceGraphID, ResourceGraphHash: resourceHash, ProviderPayloadSetRef: payloads.PayloadSetID, ProviderPayloadSetHash: payloadHash,
		GeneratedSpecRef: "generated-spec-1", GeneratedSpecHash: launchRoutingHash("d"), Placements: []contracts.LaunchRoutePlacement{placement}, PlacementDependencies: []contracts.LaunchRouteDependency{},
		ExpiresAt: "2026-07-19T11:00:00Z",
	}
	resolver.analyses[analysis.AnalysisID] = analysis
	resolver.graphs[graph.GraphID] = graph
	resolver.profiles[profile.ProfileID] = profile
	resolver.constraints[constraints.ConstraintSetID] = constraints
	resolver.quotes[quote.QuoteID] = quote
	resolver.offers[offer.SnapshotID] = offer
	resolver.resources[resources.ResourceGraphID] = resources
	resolver.payloads[payloads.PayloadSetID] = payloads
	resolver.generated[route.GeneratedSpecRef] = route.GeneratedSpecHash
	return launchRouteFixture{route: route, resolver: resolver, analysis: analysis, graph: graph, constraints: constraints, quote: quote, offer: offer, resources: resources, payloads: payloads, certification: certification}
}

func multiLaunchRouteFixture(t *testing.T) launchRouteFixture {
	t.Helper()
	graph := contracts.LaunchWorkloadGraph{
		SchemaVersion: contracts.LaunchWorkloadGraphSchemaVersion, GraphID: "graph-multi", TenantID: "tenant-1", WorkspaceID: "workspace-1",
		SourceCommitSHA: strings.Repeat("b", 40), SourceTreeHash: launchRoutingHash("1"), UnknownSetHash: launchRoutingHash("2"),
		Nodes: []contracts.LaunchWorkloadNode{
			{NodeID: "api", Kind: "http_service", LifecycleClass: contracts.LaunchLifecycleEphemeral, DefinitionHash: launchRoutingHash("3"), RequirementsHash: launchRoutingHash("4"), RequiredCapabilities: []string{"https-endpoint", "stateless-runtime"}, Deployability: contracts.LaunchAnalysisSupported},
			{NodeID: "database", Kind: "database", LifecycleClass: contracts.LaunchLifecycleStatefulData, DefinitionHash: launchRoutingHash("5"), RequirementsHash: launchRoutingHash("6"), RequiredCapabilities: []string{"managed-postgresql", "persistent-storage"}, Deployability: contracts.LaunchAnalysisSupported},
		},
		Edges: []contracts.LaunchWorkloadEdge{{FromNodeID: "api", ToNodeID: "database", Relationship: "writes_to"}},
	}
	analysis := launchRepositoryAnalysis(t, graph)
	constraints := launchConstraintSet()
	webProfile := launchProviderProfile("edge-cloud", "edge-connector", "eu-edge", "app", []string{"http_service"}, []string{"https-endpoint", "stateless-runtime"}, []string{contracts.LaunchLifecycleEphemeral}, "edge")
	dbProfile := launchProviderProfile("data-cloud", "data-connector", "eu-data", "postgres", []string{"database"}, []string{"managed-postgresql", "persistent-storage"}, []string{contracts.LaunchLifecycleStatefulData}, "data")
	graphHash, _ := contracts.DeriveLaunchWorkloadGraphHash(graph)
	constraintHash, _ := contracts.DeriveLaunchConstraintSetHash(constraints)
	webProfileHash, _ := contracts.DeriveLaunchProviderCapabilityProfileHash(webProfile)
	dbProfileHash, _ := contracts.DeriveLaunchProviderCapabilityProfileHash(dbProfile)
	resources := contracts.LaunchResourceGraph{
		SchemaVersion: contracts.LaunchResourceGraphSchemaVersion, ResourceGraphID: "resources-multi", TenantID: "tenant-1", WorkspaceID: "workspace-1", MissionID: "mission-1",
		Nodes: []contracts.LaunchResourceNode{
			{ResourceID: "resource-api", PlacementID: "placement-a", WorkloadNodeID: "api", ResourceKind: "service", LifecycleClass: contracts.LaunchLifecycleEphemeral, DesiredStateHash: launchRoutingHash("7"), OwnershipTagHash: launchRoutingHash("8")},
			{ResourceID: "resource-db", PlacementID: "placement-b", WorkloadNodeID: "database", ResourceKind: "managed-database", LifecycleClass: contracts.LaunchLifecycleStatefulData, DesiredStateHash: launchRoutingHash("9"), OwnershipTagHash: launchRoutingHash("a")},
		},
		Edges: []contracts.LaunchResourceEdge{{FromResourceID: "resource-api", ToResourceID: "resource-db", Relationship: "writes_to"}},
	}
	payloads := contracts.LaunchProviderPayloadSet{
		SchemaVersion: contracts.LaunchProviderPayloadSetSchemaVersion, PayloadSetID: "payloads-multi", TenantID: "tenant-1", WorkspaceID: "workspace-1", MissionID: "mission-1",
		Entries: []contracts.LaunchProviderPayloadEntry{
			{PlacementID: "placement-a", EffectID: contracts.EffectTypeDeployProductionActivate, ProviderActionURN: webProfile.Actions[0].ActionURN, PayloadHash: launchRoutingHash("b")},
			{PlacementID: "placement-a", EffectID: contracts.EffectTypeProviderProvision, ProviderActionURN: webProfile.Actions[1].ActionURN, PayloadHash: launchRoutingHash("c")},
			{PlacementID: "placement-b", EffectID: contracts.EffectTypeDeployProductionActivate, ProviderActionURN: dbProfile.Actions[0].ActionURN, PayloadHash: launchRoutingHash("d")},
			{PlacementID: "placement-b", EffectID: contracts.EffectTypeProviderProvision, ProviderActionURN: dbProfile.Actions[1].ActionURN, PayloadHash: launchRoutingHash("e")},
		},
	}
	webResourceHash, _ := contracts.DeriveLaunchResourceSubsetHash(resources, "placement-a")
	dbResourceHash, _ := contracts.DeriveLaunchResourceSubsetHash(resources, "placement-b")
	webPayloadHash, _ := contracts.DeriveLaunchProviderPayloadSubsetHash(payloads, "placement-a")
	dbPayloadHash, _ := contracts.DeriveLaunchProviderPayloadSubsetHash(payloads, "placement-b")
	placements := []contracts.LaunchRoutePlacement{
		{PlacementID: "placement-a", WorkloadNodeIDs: []string{"api"}, ProviderProfileRef: webProfile.ProfileID, ProviderProfileHash: webProfileHash, ProviderID: webProfile.ProviderID, ProviderAccountRef: "account:web", ProviderAccountHash: launchRoutingHash("1"), RegionID: "eu-edge", Jurisdiction: "EU", OfferingID: "app", ProviderConnectorID: webProfile.ConnectorID, ProviderConnectorContractHash: webProfile.ConnectorContractHash, ActionBindings: []contracts.LaunchRouteActionBinding{{EffectID: contracts.EffectTypeDeployProductionActivate, ProviderActionURN: webProfile.Actions[0].ActionURN, ProviderPayloadHash: launchRoutingHash("b")}, {EffectID: contracts.EffectTypeProviderProvision, ProviderActionURN: webProfile.Actions[1].ActionURN, ProviderPayloadHash: launchRoutingHash("c")}}, ResourceSubsetHash: webResourceHash, ProviderPayloadSubsetHash: webPayloadHash},
		{PlacementID: "placement-b", WorkloadNodeIDs: []string{"database"}, ProviderProfileRef: dbProfile.ProfileID, ProviderProfileHash: dbProfileHash, ProviderID: dbProfile.ProviderID, ProviderAccountRef: "account:data", ProviderAccountHash: launchRoutingHash("2"), RegionID: "eu-data", Jurisdiction: "EU", OfferingID: "postgres", ProviderConnectorID: dbProfile.ConnectorID, ProviderConnectorContractHash: dbProfile.ConnectorContractHash, ActionBindings: []contracts.LaunchRouteActionBinding{{EffectID: contracts.EffectTypeDeployProductionActivate, ProviderActionURN: dbProfile.Actions[0].ActionURN, ProviderPayloadHash: launchRoutingHash("d")}, {EffectID: contracts.EffectTypeProviderProvision, ProviderActionURN: dbProfile.Actions[1].ActionURN, ProviderPayloadHash: launchRoutingHash("e")}}, ResourceSubsetHash: dbResourceHash, ProviderPayloadSubsetHash: dbPayloadHash},
	}
	edgeHash, _ := contracts.DeriveLaunchWorkloadEdgeHash(graph.Edges[0])
	webOffer := launchOfferSnapshot(webProfile.ProviderID, "offer-edge", "account:web", launchRoutingHash("1"), webProfile.TermsEvidenceHash, contracts.LaunchCreditNone, 0)
	dbOffer := launchOfferSnapshot(dbProfile.ProviderID, "offer-data", "account:data", launchRoutingHash("2"), dbProfile.TermsEvidenceHash, contracts.LaunchCreditNone, 0)
	webOfferHash, _ := contracts.DeriveLaunchOfferSnapshotHash(webOffer)
	dbOfferHash, _ := contracts.DeriveLaunchOfferSnapshotHash(dbOffer)
	quote := contracts.LaunchRouteQuote{
		SchemaVersion: contracts.LaunchRouteQuoteSchemaVersion, QuoteID: "quote-multi", TenantID: "tenant-1", WorkspaceID: "workspace-1", MissionID: "mission-1", WorkloadGraphHash: graphHash, ConstraintSetHash: constraintHash, Currency: "EUR",
		PlacementCosts: []contracts.LaunchPlacementCost{
			{PlacementID: "placement-a", ProviderID: webProfile.ProviderID, ProviderAccountHash: launchRoutingHash("1"), RegionID: "eu-edge", OfferingID: "app", BillingCadence: "monthly", CommitmentTerm: "monthly", BaseCostMinor: 1000, TaxFXReserveMinor: 100, GrossExposureMinor: 1100, VerifiedCreditMinor: 0, ExpectedCashMinor: 1100, CreditStatus: contracts.LaunchCreditNone, OfferSnapshotRef: webOffer.SnapshotID, OfferSnapshotHash: webOfferHash, PriceEvidenceHash: webProfile.PricingEvidenceHash, TermsEvidenceHash: webProfile.TermsEvidenceHash},
			{PlacementID: "placement-b", ProviderID: dbProfile.ProviderID, ProviderAccountHash: launchRoutingHash("2"), RegionID: "eu-data", OfferingID: "postgres", BillingCadence: "monthly", CommitmentTerm: "monthly", BaseCostMinor: 2000, TaxFXReserveMinor: 200, GrossExposureMinor: 2200, VerifiedCreditMinor: 0, ExpectedCashMinor: 2200, CreditStatus: contracts.LaunchCreditNone, OfferSnapshotRef: dbOffer.SnapshotID, OfferSnapshotHash: dbOfferHash, PriceEvidenceHash: dbProfile.PricingEvidenceHash, TermsEvidenceHash: dbProfile.TermsEvidenceHash},
		},
		BaseProviderCostMinor: 3000, TaxFXReserveMinor: 300, GrossExposureMinor: 3300, VerifiedCreditMinor: 0, ExpectedCashMinor: 3300, CreditStatus: contracts.LaunchCreditNone,
		FXSnapshotHash: launchRoutingHash("4"), TaxSnapshotHash: launchRoutingHash("5"), CommercialEvidenceHash: launchRoutingHash("6"), RetrievedAt: "2026-07-19T00:00:00Z", ExpiresAt: "2026-07-19T12:00:00Z",
	}
	quote.CreditSnapshotHash, _ = contracts.DeriveLaunchOfferSnapshotSetHash(quote.PlacementCosts)
	analysisHash, _ := contracts.DeriveLaunchRepositoryAnalysisHash(analysis)
	quoteHash, _ := contracts.DeriveLaunchRouteQuoteHash(quote)
	resourceHash, _ := contracts.DeriveLaunchResourceGraphHash(resources)
	payloadHash, _ := contracts.DeriveLaunchProviderPayloadSetHash(payloads)
	route := contracts.LaunchRouteBinding{SchemaVersion: contracts.LaunchRouteBindingSchemaVersion, RouteID: "route-multi", TenantID: "tenant-1", WorkspaceID: "workspace-1", MissionID: "mission-1", RepositoryAnalysisRef: analysis.AnalysisID, RepositoryAnalysisHash: analysisHash, WorkloadGraphRef: graph.GraphID, WorkloadGraphHash: graphHash, ConstraintSetRef: constraints.ConstraintSetID, ConstraintSetHash: constraintHash, RouteQuoteRef: quote.QuoteID, RouteQuoteHash: quoteHash, ResourceGraphRef: resources.ResourceGraphID, ResourceGraphHash: resourceHash, ProviderPayloadSetRef: payloads.PayloadSetID, ProviderPayloadSetHash: payloadHash, GeneratedSpecRef: "generated-spec-multi", GeneratedSpecHash: launchRoutingHash("f"), Placements: placements, PlacementDependencies: []contracts.LaunchRouteDependency{{FromPlacementID: "placement-a", ToPlacementID: "placement-b", Relationship: "writes_to", WorkloadEdgeHash: edgeHash}}, ExpiresAt: "2026-07-19T11:00:00Z"}
	resolver := newLaunchResolver()
	resolver.analyses[analysis.AnalysisID] = analysis
	resolver.graphs[graph.GraphID] = graph
	resolver.profiles[webProfile.ProfileID] = webProfile
	resolver.profiles[dbProfile.ProfileID] = dbProfile
	resolver.constraints[constraints.ConstraintSetID] = constraints
	resolver.quotes[quote.QuoteID] = quote
	resolver.offers[webOffer.SnapshotID] = webOffer
	resolver.offers[dbOffer.SnapshotID] = dbOffer
	resolver.resources[resources.ResourceGraphID] = resources
	resolver.payloads[payloads.PayloadSetID] = payloads
	resolver.generated[route.GeneratedSpecRef] = route.GeneratedSpecHash
	return launchRouteFixture{route: route, resolver: resolver, analysis: analysis, graph: graph, constraints: constraints, quote: quote, resources: resources, payloads: payloads}
}

func launchHTTPWorkloadGraph() contracts.LaunchWorkloadGraph {
	return contracts.LaunchWorkloadGraph{
		SchemaVersion: contracts.LaunchWorkloadGraphSchemaVersion, GraphID: "workload-graph-http", TenantID: "tenant-1", WorkspaceID: "workspace-1",
		SourceCommitSHA: strings.Repeat("a", 40), SourceTreeHash: launchRoutingHash("1"), UnknownSetHash: launchRoutingHash("2"),
		Nodes: []contracts.LaunchWorkloadNode{{NodeID: "api", Kind: "http_service", LifecycleClass: contracts.LaunchLifecycleEphemeral, DefinitionHash: launchRoutingHash("3"), RequirementsHash: launchRoutingHash("4"), RequiredCapabilities: []string{"health-check", "https-endpoint", "stateless-runtime"}, Deployability: contracts.LaunchAnalysisSupported}},
		Edges: []contracts.LaunchWorkloadEdge{},
	}
}

func launchRepositoryAnalysis(t *testing.T, graph contracts.LaunchWorkloadGraph) contracts.LaunchRepositoryAnalysis {
	t.Helper()
	graphHash, err := contracts.DeriveLaunchWorkloadGraphHash(graph)
	if err != nil {
		t.Fatal(err)
	}
	return contracts.LaunchRepositoryAnalysis{SchemaVersion: contracts.LaunchRepositoryAnalysisSchemaVersion, AnalysisID: "analysis-1", TenantID: graph.TenantID, WorkspaceID: graph.WorkspaceID, SourceConnectionRef: "source:repo-1", SourceCommitSHA: graph.SourceCommitSHA, SourceTreeHash: graph.SourceTreeHash, AnalyzerContractHash: launchRoutingHash("5"), Status: contracts.AggregateLaunchWorkloadGraphStatus(graph), WorkloadGraphRef: graph.GraphID, WorkloadGraphHash: graphHash, FindingSetHash: launchRoutingHash("6"), AnalyzedAt: "2026-07-19T01:00:00Z"}
}

func launchConstraintSet() contracts.LaunchConstraintSet {
	return contracts.LaunchConstraintSet{SchemaVersion: contracts.LaunchConstraintSetSchemaVersion, ConstraintSetID: "constraints-1", TenantID: "tenant-1", WorkspaceID: "workspace-1", MissionID: "mission-1", MaximumGrossCurrency: "EUR", MaximumGrossMinor: 5000, AllowedProviders: []string{}, AllowedJurisdictions: []string{"EU"}, RequiredResidencyTags: []string{"eu"}, AllowedCommitmentTerms: []string{"monthly"}, RequiredRouteCapabilities: []string{}, PolicyExpressionHash: launchRoutingHash("0")}
}

func launchOfferSnapshot(providerID, snapshotID, accountRef, accountHash, termsHash, status string, verifiedCredit int64) contracts.LaunchOfferSnapshot {
	return contracts.LaunchOfferSnapshot{
		SchemaVersion: contracts.LaunchOfferSnapshotSchemaVersion, SnapshotID: snapshotID, TenantID: "tenant-1", WorkspaceID: "workspace-1",
		ProviderID: providerID, ProviderAccountRef: accountRef, ProviderAccountHash: accountHash,
		OfficialSourceURL: "https://example.invalid/" + providerID + "/official-offers", ContentVersionHash: launchRoutingHash("c"), TermsHash: termsHash, ExclusionsHash: launchRoutingHash("d"),
		Status: status, Currency: "EUR", VerifiedCreditMinor: verifiedCredit, EvidenceRefs: []string{"evidence:" + snapshotID},
		RetrievedAt: "2026-07-19T00:00:00Z", ExpiresAt: "2026-07-19T13:00:00Z",
	}
}

func launchProviderProfile(provider, connector, region, offering string, workloads, capabilities, lifecycles []string, urnPrefix string) contracts.LaunchProviderCapabilityProfile {
	return contracts.LaunchProviderCapabilityProfile{
		SchemaVersion: contracts.LaunchProviderProfileSchemaVersion, ProfileID: provider + "-candidate", ProviderID: provider, ConnectorID: connector, ConnectorContractHash: launchRoutingHash("d"), ProfileVersion: "candidate-1", ProfileStatus: contracts.LaunchProviderProfileCandidate,
		Regions: []contracts.LaunchProviderRegion{{RegionID: region, Jurisdiction: "EU", ResidencyTags: []string{"eu"}, Offerings: []contracts.LaunchProviderOffering{{OfferingID: offering, SupportedWorkloads: workloads, SupportedCapabilities: capabilities, SupportedLifecycles: lifecycles}}}},
		Actions: []contracts.LaunchProviderAction{
			{EffectID: contracts.EffectTypeDeployProductionActivate, ActionURN: "urn:test:" + urnPrefix + ":activate", ReconciliationMode: "OPERATION_POLL", IdempotencyMode: "RECONCILE_BEFORE_RETRY", SupportedTransitionClasses: []string{contracts.LaunchTransitionReleaseCutover, contracts.LaunchTransitionResourceState}, SupportedCompensationClasses: []string{}},
			{EffectID: contracts.EffectTypeProviderProvision, ActionURN: "urn:test:" + urnPrefix + ":provision", ReconciliationMode: "OPERATION_POLL", IdempotencyMode: "RECONCILE_BEFORE_RETRY", SupportedTransitionClasses: []string{}, SupportedCompensationClasses: []string{}},
			{EffectID: contracts.EffectTypeProviderRollback, ActionURN: "urn:test:" + urnPrefix + ":rollback", ReconciliationMode: "OPERATION_POLL", IdempotencyMode: "COMPARE_AND_SET", SupportedTransitionClasses: []string{}, SupportedCompensationClasses: []string{contracts.LaunchCompensationReleaseRollback, contracts.LaunchCompensationResourceRestore}},
			{EffectID: contracts.EffectTypeProviderTeardown, ActionURN: "urn:test:" + urnPrefix + ":teardown", ReconciliationMode: "READ_AFTER_WRITE", IdempotencyMode: "RECONCILE_BEFORE_RETRY", SupportedTransitionClasses: []string{}, SupportedCompensationClasses: []string{}},
		},
		PricingEvidenceRef: "fixture://" + provider + "/pricing", PricingEvidenceHash: launchRoutingHash("a"), TermsEvidenceRef: "fixture://" + provider + "/terms", TermsEvidenceHash: launchRoutingHash("b"), RetrievedAt: "2026-07-19T00:00:00Z", ExpiresAt: "2026-07-20T00:00:00Z",
	}
}

func newLaunchResolver() *launchTestResolver {
	return &launchTestResolver{analyses: map[string]contracts.LaunchRepositoryAnalysis{}, graphs: map[string]contracts.LaunchWorkloadGraph{}, profiles: map[string]contracts.LaunchProviderCapabilityProfile{}, certifications: map[string]contracts.LaunchProviderCertificationRecord{}, constraints: map[string]contracts.LaunchConstraintSet{}, quotes: map[string]contracts.LaunchRouteQuote{}, offers: map[string]contracts.LaunchOfferSnapshot{}, resources: map[string]contracts.LaunchResourceGraph{}, payloads: map[string]contracts.LaunchProviderPayloadSet{}, generated: map[string]string{}, keys: map[string]ed25519.PublicKey{}, current: map[string]string{}}
}

func cloneLaunchRouteFixture(value launchRouteFixture) launchRouteFixture {
	data, _ := json.Marshal(value.route)
	var route contracts.LaunchRouteBinding
	_ = json.Unmarshal(data, &route)
	resolver := newLaunchResolver()
	for key, item := range value.resolver.analyses {
		resolver.analyses[key] = item
	}
	for key, item := range value.resolver.graphs {
		resolver.graphs[key] = item
	}
	for key, item := range value.resolver.profiles {
		resolver.profiles[key] = item
	}
	for key, item := range value.resolver.certifications {
		resolver.certifications[key] = item
	}
	for key, item := range value.resolver.constraints {
		resolver.constraints[key] = item
	}
	for key, item := range value.resolver.quotes {
		resolver.quotes[key] = item
	}
	for key, item := range value.resolver.offers {
		resolver.offers[key] = item
	}
	for key, item := range value.resolver.resources {
		resolver.resources[key] = item
	}
	for key, item := range value.resolver.payloads {
		resolver.payloads[key] = item
	}
	for key, item := range value.resolver.generated {
		resolver.generated[key] = item
	}
	for key, item := range value.resolver.keys {
		resolver.keys[key] = append(ed25519.PublicKey(nil), item...)
	}
	for key, item := range value.resolver.current {
		resolver.current[key] = item
	}
	value.route = route
	value.resolver = resolver
	return value
}

func launchRoutingHash(char string) string {
	return "sha256:" + strings.Repeat(char, 64)
}
