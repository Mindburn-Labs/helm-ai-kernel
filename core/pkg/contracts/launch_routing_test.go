// quantum_posture: these tests exercise classical Ed25519 certification
// fixtures only; they do not claim hybrid or post-quantum protection.
package contracts_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
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
		"effects/launch/commercial_evidence.v1.json":  fixture.commercial,
		"effects/launch/fx_snapshot.v1.json":          fixture.fxSnapshot,
		"effects/launch/tax_snapshot.v1.json":         fixture.taxSnapshot,
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
	if _, err := contracts.ProjectLaunchBlueprint(graph, launchConstraintSet()); err == nil || !strings.Contains(err.Error(), "non-portable") {
		t.Fatalf("clean-room fork copied unregistered vendor semantics: %v", err)
	}

	profile.Regions[0].Offerings[0].SupportedWorkloads = []string{"unknown"}
	if err := contracts.ValidateLaunchProviderCapabilityProfile(profile); err == nil {
		t.Fatal("provider profile claimed analyzer uncertainty as executable workload support")
	}
}

func TestWorkloadEdgeCanonicalKeysDoNotCollideOnControlCharacters(t *testing.T) {
	node := func(id, hash string) contracts.LaunchWorkloadNode {
		return contracts.LaunchWorkloadNode{
			NodeID: id, Kind: "http_service", LifecycleClass: contracts.LaunchLifecycleEphemeral,
			DefinitionHash: launchRoutingHash(hash), RequirementsHash: launchRoutingHash(hash),
			RequiredCapabilities: []string{"https-endpoint"}, Deployability: contracts.LaunchAnalysisSupported,
		}
	}
	graph := contracts.LaunchWorkloadGraph{
		SchemaVersion: contracts.LaunchWorkloadGraphSchemaVersion, GraphID: "graph-control-characters", TenantID: "tenant-1", WorkspaceID: "workspace-1",
		SourceCommitSHA: strings.Repeat("d", 40), SourceTreeHash: launchRoutingHash("1"), UnknownSetHash: launchRoutingHash("2"),
		Nodes: []contracts.LaunchWorkloadNode{
			node("a", "3"),
			node("a\x00b", "4"),
			node("b\x00c", "5"),
			node("c", "6"),
		},
		Edges: []contracts.LaunchWorkloadEdge{
			{FromNodeID: "a", ToNodeID: "b\x00c", Relationship: "depends_on"},
			{FromNodeID: "a\x00b", ToNodeID: "c", Relationship: "depends_on"},
		},
	}
	if err := contracts.ValidateLaunchWorkloadGraph(graph); err != nil {
		t.Fatalf("distinct workload edges collided in canonical tuple encoding: %v", err)
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

	duplicate := cloneLaunchRouteFixture(fixture).route
	duplicate.Placements[1].WorkloadNodeIDs = []string{"api", "database"}
	if err := contracts.ValidateLaunchRouteBinding(duplicate, fixture.resolver, launchRoutingNow, false); err == nil || !strings.Contains(err.Error(), "multiple placements") {
		t.Fatalf("duplicate cross-cloud workload assignment was not rejected: %v", err)
	}

	missingDependency := cloneLaunchRouteFixture(fixture).route
	missingDependency.PlacementDependencies = []contracts.LaunchRouteDependency{}
	if err := contracts.ValidateLaunchRouteBinding(missingDependency, fixture.resolver, launchRoutingNow, false); err == nil || !strings.Contains(err.Error(), "dependency set") {
		t.Fatalf("missing cross-cloud dependency was not rejected: %v", err)
	}

	hiddenResourceDependency := cloneLaunchRouteFixture(fixture)
	hiddenResourceDependency.resources.Edges = append([]contracts.LaunchResourceEdge(nil), hiddenResourceDependency.resources.Edges...)
	hiddenResourceDependency.resources.Edges[0].Relationship = "depends_on"
	resourceHash, err := contracts.DeriveLaunchResourceGraphHash(hiddenResourceDependency.resources)
	if err != nil {
		t.Fatal(err)
	}
	hiddenResourceDependency.route.ResourceGraphHash = resourceHash
	for index := range hiddenResourceDependency.route.Placements {
		subsetHash, subsetErr := contracts.DeriveLaunchResourceSubsetHash(hiddenResourceDependency.resources, hiddenResourceDependency.route.Placements[index].PlacementID)
		if subsetErr != nil {
			t.Fatal(subsetErr)
		}
		hiddenResourceDependency.route.Placements[index].ResourceSubsetHash = subsetHash
	}
	hiddenResourceDependency.resolver.resources[hiddenResourceDependency.resources.ResourceGraphID] = hiddenResourceDependency.resources
	if err := contracts.ValidateLaunchRouteBinding(hiddenResourceDependency.route, hiddenResourceDependency.resolver, launchRoutingNow, false); err == nil || !strings.Contains(err.Error(), "without a matching workload dependency") {
		t.Fatalf("hidden cross-cloud resource dependency was not rejected: %v", err)
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

func TestRouteRejectsCommercialEvidenceUnderstatement(t *testing.T) {
	fixture := cloneLaunchRouteFixture(multiLaunchRouteFixture(t))
	quote := fixture.quote
	quote.PlacementCosts = append([]contracts.LaunchPlacementCost(nil), quote.PlacementCosts...)
	quote.PlacementCosts[0].BaseCostMinor = 1
	quote.PlacementCosts[0].TaxFXReserveMinor = 0
	quote.PlacementCosts[0].GrossExposureMinor = 1
	quote.PlacementCosts[0].ExpectedCashMinor = 1
	quote.BaseProviderCostMinor = 2001
	quote.TaxFXReserveMinor = 200
	quote.GrossExposureMinor = 2201
	quote.ExpectedCashMinor = 2201
	if err := contracts.ValidateLaunchRouteQuote(quote); err != nil {
		t.Fatalf("understated quote must remain internally consistent for this adversarial test: %v", err)
	}
	quoteHash, err := contracts.DeriveLaunchRouteQuoteHash(quote)
	if err != nil {
		t.Fatal(err)
	}
	fixture.resolver.quotes[quote.QuoteID] = quote
	fixture.route.RouteQuoteHash = quoteHash
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err == nil || !strings.Contains(err.Error(), "understates") {
		t.Fatalf("internally consistent quote understated resolved commercial evidence: %v", err)
	}
}

func TestCommercialEvidenceUsesConservativeIntegerCeilings(t *testing.T) {
	profile := launchProviderProfile("cloud", "connector", "eu-1", "app", []string{"http_service"}, []string{"health-check", "https-endpoint", "stateless-runtime"}, []string{contracts.LaunchLifecycleEphemeral}, "cloud")
	fixture := cloneLaunchRouteFixture(singleLaunchRouteFixture(t, profile, false))
	fixture.fxSnapshot.SourceCurrency = "USD"
	fixture.fxSnapshot.RateNumerator = 2
	fixture.fxSnapshot.RateDenominator = 3
	line := &fixture.commercial.PlacementCosts[0]
	line.ProviderCurrency = "USD"
	line.ProviderBaseCostMinor = 1001
	line.FXReserveBPS = 100
	line.BaseCostMinor = 668
	line.TaxReserveMinor = 134
	line.FXReserveMinor = 9
	line.TaxFXReserveMinor = 143
	line.GrossExposureMinor = 811
	quoteLine := &fixture.quote.PlacementCosts[0]
	quoteLine.BaseCostMinor = 668
	quoteLine.TaxFXReserveMinor = 143
	quoteLine.GrossExposureMinor = 811
	quoteLine.ExpectedCashMinor = 611
	fixture.quote.BaseProviderCostMinor = 668
	fixture.quote.TaxFXReserveMinor = 143
	fixture.quote.GrossExposureMinor = 811
	fixture.quote.ExpectedCashMinor = 611
	rebindLaunchCommercialFixture(t, &fixture)
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err != nil {
		t.Fatalf("conservative rational FX, tax, and reserve ceilings were rejected: %v", err)
	}
}

func TestRouteRejectsUnsafeFXAndTaxEvidence(t *testing.T) {
	profile := launchProviderProfile("cloud", "connector", "eu-1", "app", []string{"http_service"}, []string{"health-check", "https-endpoint", "stateless-runtime"}, []string{contracts.LaunchLifecycleEphemeral}, "cloud")
	base := singleLaunchRouteFixture(t, profile, false)
	for name, mutate := range map[string]func(*launchRouteFixture){
		"non-identity same-currency FX rate": func(f *launchRouteFixture) {
			f.fxSnapshot.RateNumerator = 1
			f.fxSnapshot.RateDenominator = 2
		},
		"future FX snapshot": func(f *launchRouteFixture) {
			f.fxSnapshot.RetrievedAt = "2026-07-19T02:00:00Z"
		},
		"zero unknown-tax maximum": func(f *launchRouteFixture) {
			f.taxSnapshot.Status = contracts.LaunchTaxConservativeMaximum
			f.taxSnapshot.TaxRateBPS = 0
		},
		"cross-currency without reserve": func(f *launchRouteFixture) {
			f.fxSnapshot.SourceCurrency = "USD"
			f.commercial.PlacementCosts[0].ProviderCurrency = "USD"
			f.commercial.PlacementCosts[0].FXReserveBPS = 0
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := cloneLaunchRouteFixture(base)
			mutate(&fixture)
			rebindLaunchCommercialFixture(t, &fixture)
			if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err == nil {
				t.Fatal("unsafe commercial evidence was accepted")
			}
		})
	}
}

func TestRouteRejectsPayloadForUnknownPlacement(t *testing.T) {
	profile := launchProviderProfile("cloud", "connector", "eu-1", "app", []string{"http_service"}, []string{"health-check", "https-endpoint", "stateless-runtime"}, []string{contracts.LaunchLifecycleEphemeral}, "cloud")
	fixture := singleLaunchRouteFixture(t, profile, false)
	fixture.payloads.Entries = append(fixture.payloads.Entries, contracts.LaunchProviderPayloadEntry{
		PlacementID:       "placement-z",
		EffectID:          contracts.EffectTypeProviderProvision,
		ProviderActionURN: profile.Actions[1].ActionURN,
		PayloadHash:       launchRoutingHash("9"),
	})
	payloadHash, err := contracts.DeriveLaunchProviderPayloadSetHash(fixture.payloads)
	if err != nil {
		t.Fatal(err)
	}
	fixture.route.ProviderPayloadSetHash = payloadHash
	fixture.resolver.payloads[fixture.payloads.PayloadSetID] = fixture.payloads
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err == nil || !strings.Contains(err.Error(), "unknown route placement") {
		t.Fatalf("payload for an unapproved placement was not rejected: %v", err)
	}
}

func TestRouteQuoteRejectsVerifiedCreditAccountAliasesAcrossPlacements(t *testing.T) {
	base := multiLaunchRouteFixture(t).quote
	for name, testCase := range map[string]struct {
		mutate func([]contracts.LaunchPlacementCost)
		error  string
	}{
		"exact account reuse": {
			mutate: func(lines []contracts.LaunchPlacementCost) {
				for index := range lines {
					lines[index].ProviderAccountRef = "account:shared"
					lines[index].ProviderAccountHash = launchRoutingHash("1")
				}
			},
			error: "more than once",
		},
		"one account reference with multiple hashes": {
			mutate: func(lines []contracts.LaunchPlacementCost) {
				for index := range lines {
					lines[index].ProviderAccountRef = "account:shared"
				}
			},
			error: "multiple identity hashes",
		},
		"one account hash with multiple references": {
			mutate: func(lines []contracts.LaunchPlacementCost) {
				for index := range lines {
					lines[index].ProviderAccountHash = launchRoutingHash("1")
				}
			},
			error: "multiple account references",
		},
	} {
		t.Run(name, func(t *testing.T) {
			quote := base
			quote.PlacementCosts = append([]contracts.LaunchPlacementCost(nil), base.PlacementCosts...)
			for index := range quote.PlacementCosts {
				line := &quote.PlacementCosts[index]
				line.ProviderID = "shared-cloud"
				line.CreditStatus = contracts.LaunchCreditVerified
				line.VerifiedCreditMinor = 100
				line.ExpectedCashMinor = line.GrossExposureMinor - line.VerifiedCreditMinor
			}
			testCase.mutate(quote.PlacementCosts)
			quote.VerifiedCreditMinor = 200
			quote.ExpectedCashMinor = quote.GrossExposureMinor - quote.VerifiedCreditMinor
			quote.CreditStatus = contracts.LaunchCreditVerified
			quote.CreditSnapshotHash, _ = contracts.DeriveLaunchOfferSnapshotSetHash(quote.PlacementCosts)
			if err := contracts.ValidateLaunchRouteQuote(quote); err == nil || !strings.Contains(err.Error(), testCase.error) {
				t.Fatalf("provider account alias reused one credit balance: %v", err)
			}
		})
	}
}

func TestProviderAccountRefsAreCanonicalAcrossLaunchArtifacts(t *testing.T) {
	profile := launchProviderProfile("cloud", "connector", "eu-1", "app", []string{"http_service"}, []string{"health-check", "https-endpoint", "stateless-runtime"}, []string{contracts.LaunchLifecycleEphemeral}, "cloud")
	fixture := singleLaunchRouteFixture(t, profile, false)
	const invalidAccountRef = " account:1"

	offer := fixture.offer
	offer.ProviderAccountRef = invalidAccountRef
	if err := contracts.ValidateLaunchOfferSnapshot(offer); err == nil {
		t.Fatal("offer snapshot admitted a non-canonical provider account reference")
	}
	if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/offer_snapshot.v1.json"), offer); err == nil {
		t.Fatal("offer snapshot schema admitted a non-canonical provider account reference")
	}

	quote := fixture.quote
	quote.PlacementCosts = append([]contracts.LaunchPlacementCost(nil), quote.PlacementCosts...)
	quote.PlacementCosts[0].ProviderAccountRef = invalidAccountRef
	if err := contracts.ValidateLaunchRouteQuote(quote); err == nil {
		t.Fatal("route quote admitted a non-canonical provider account reference")
	}
	if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/route_quote.v1.json"), quote); err == nil {
		t.Fatal("route quote schema admitted a non-canonical provider account reference")
	}

	route := fixture.route
	route.Placements = append([]contracts.LaunchRoutePlacement(nil), route.Placements...)
	route.Placements[0].ProviderAccountRef = invalidAccountRef
	if err := contracts.ValidateLaunchRouteBinding(route, fixture.resolver, launchRoutingNow, false); err == nil {
		t.Fatal("route binding admitted a non-canonical provider account reference")
	}
	if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/route_binding.v1.json"), route); err == nil {
		t.Fatal("route binding schema admitted a non-canonical provider account reference")
	}
}

func TestRouteRejectsFutureDatedCommercialEvidence(t *testing.T) {
	profile := launchProviderProfile("cloud", "connector", "eu-1", "app", []string{"http_service"}, []string{"health-check", "https-endpoint", "stateless-runtime"}, []string{contracts.LaunchLifecycleEphemeral}, "cloud")
	base := singleLaunchRouteFixture(t, profile, false)
	future := launchRoutingNow.Add(time.Minute).Format(time.RFC3339Nano)

	for name, mutate := range map[string]func(*launchRouteFixture){
		"repository analysis": func(f *launchRouteFixture) {
			updated := f.resolver.analyses[f.route.RepositoryAnalysisRef]
			updated.AnalyzedAt = future
			updatedHash, err := contracts.DeriveLaunchRepositoryAnalysisHash(updated)
			if err != nil {
				t.Fatal(err)
			}
			f.resolver.analyses[updated.AnalysisID] = updated
			f.route.RepositoryAnalysisHash = updatedHash
		},
		"provider profile": func(f *launchRouteFixture) {
			updated := f.resolver.profiles[f.route.Placements[0].ProviderProfileRef]
			updated.RetrievedAt = future
			updatedHash, err := contracts.DeriveLaunchProviderCapabilityProfileHash(updated)
			if err != nil {
				t.Fatal(err)
			}
			f.resolver.profiles[updated.ProfileID] = updated
			f.route.Placements[0].ProviderProfileHash = updatedHash
		},
		"route quote": func(f *launchRouteFixture) {
			updated := f.quote
			updated.RetrievedAt = future
			updatedHash, err := contracts.DeriveLaunchRouteQuoteHash(updated)
			if err != nil {
				t.Fatal(err)
			}
			f.quote = updated
			f.resolver.quotes[updated.QuoteID] = updated
			f.route.RouteQuoteHash = updatedHash
		},
		"offer snapshot": func(f *launchRouteFixture) {
			updatedOffer := f.offer
			updatedOffer.RetrievedAt = future
			updatedOfferHash, err := contracts.DeriveLaunchOfferSnapshotHash(updatedOffer)
			if err != nil {
				t.Fatal(err)
			}
			f.offer = updatedOffer
			f.resolver.offers[updatedOffer.SnapshotID] = updatedOffer
			updatedQuote := f.quote
			updatedQuote.PlacementCosts = append([]contracts.LaunchPlacementCost(nil), updatedQuote.PlacementCosts...)
			updatedQuote.PlacementCosts[0].OfferSnapshotHash = updatedOfferHash
			updatedQuote.CreditSnapshotHash, err = contracts.DeriveLaunchOfferSnapshotSetHash(updatedQuote.PlacementCosts)
			if err != nil {
				t.Fatal(err)
			}
			updatedQuoteHash, err := contracts.DeriveLaunchRouteQuoteHash(updatedQuote)
			if err != nil {
				t.Fatal(err)
			}
			f.quote = updatedQuote
			f.resolver.quotes[updatedQuote.QuoteID] = updatedQuote
			f.route.RouteQuoteHash = updatedQuoteHash
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := cloneLaunchRouteFixture(base)
			mutate(&fixture)
			if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err == nil || !strings.Contains(err.Error(), "future") {
				t.Fatalf("future-dated %s was not rejected precisely: %v", name, err)
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
	if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/offer_snapshot.v1.json"), credentialURL); err == nil {
		t.Fatal("offer snapshot schema admitted a credential-bearing official URL")
	}
	for name, officialURL := range map[string]string{
		"query":    "https://example.invalid/offers?token=secret",
		"fragment": "https://example.invalid/offers#private",
	} {
		t.Run(name, func(t *testing.T) {
			mutated := active
			mutated.OfficialSourceURL = officialURL
			if err := contracts.ValidateLaunchOfferSnapshot(mutated); err == nil {
				t.Fatal("semantic validator admitted an authority-unsafe official URL")
			}
			if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/offer_snapshot.v1.json"), mutated); err == nil {
				t.Fatal("offer snapshot schema admitted an authority-unsafe official URL")
			}
		})
	}
}

func TestProviderCertificationRequiresSignatureTrustAndCurrentRegistryState(t *testing.T) {
	profile := launchProviderProfile("cloud", "connector", "eu-1", "app", []string{"http_service"}, []string{"health-check", "https-endpoint", "stateless-runtime"}, []string{contracts.LaunchLifecycleEphemeral}, "cloud")
	fixture := singleLaunchRouteFixture(t, profile, true)
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err != nil {
		t.Fatalf("signed current certification was rejected: %v", err)
	}
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, true); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("preview effect crossed the production dispatch catalog boundary: %v", err)
	}

	fixture = singleLaunchRouteFixture(t, profile, true)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	fixture.certification.ExpiresAt = "2026-07-19T10:00:00Z"
	fixture.certification = signLaunchProviderCertificationRecord(t, fixture.certification, privateKey)
	fixture.route.Placements[0].ProviderCertificationHash = fixture.certification.RecordHash
	fixture.resolver.certifications[fixture.certification.CertificationID] = fixture.certification
	fixture.resolver.current[fixture.certification.CertificationID] = fixture.certification.RecordHash
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err == nil || !strings.Contains(err.Error(), "outlives its provider certification") {
		t.Fatalf("route outliving its provider certification was accepted: %v", err)
	}

	fixture = singleLaunchRouteFixture(t, profile, true)
	fixture.resolver.current[fixture.certification.CertificationID] = launchRoutingHash("9")
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err == nil || !strings.Contains(err.Error(), "not current") {
		t.Fatalf("revoked/superseded certification remained authoritative: %v", err)
	}

	fixture = singleLaunchRouteFixture(t, profile, true)
	_, wrongPrivate, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{9}, 64)))
	fixture.resolver.keys[fixture.certification.SignerKeyID] = wrongPrivate.Public().(ed25519.PublicKey)
	if err := contracts.ValidateLaunchRouteBinding(fixture.route, fixture.resolver, launchRoutingNow, false); err == nil || !strings.Contains(err.Error(), "signature") {
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
	blueprint, err := contracts.ProjectLaunchBlueprint(graph, constraints)
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
	tampered := blueprint
	tampered.Constraints.MaximumGrossMinor++
	if err := contracts.ValidateLaunchBlueprint(tampered); err == nil {
		t.Fatal("content-addressed clean-room blueprint accepted tampered content")
	}
	identityBearing := blueprint
	identityBearing.Nodes = append([]contracts.LaunchBlueprintNode(nil), blueprint.Nodes...)
	identityBearing.Nodes[0].NodeID = "tenant-private-service"
	identityBearing.BlueprintID, err = contracts.DeriveLaunchBlueprintID(identityBearing)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.ValidateLaunchBlueprint(identityBearing); err == nil || !strings.Contains(err.Error(), "nodes") {
		t.Fatalf("correctly rehashed blueprint retained a private node identity: %v", err)
	}
	gapped := blueprint
	gapped.Nodes = append([]contracts.LaunchBlueprintNode(nil), blueprint.Nodes...)
	gapped.Nodes[0].NodeID = "node-0042"
	gapped.BlueprintID, err = contracts.DeriveLaunchBlueprintID(gapped)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.ValidateLaunchBlueprint(gapped); err == nil || !strings.Contains(err.Error(), "contiguous deterministic ordinals") {
		t.Fatalf("correctly rehashed blueprint encoded private data in ordinal gaps: %v", err)
	}

	blueprintSchema := compileSchema(t, "effects/launch/launch_blueprint.v1.json")
	for name, mutate := range map[string]func(*contracts.LaunchBlueprint){
		"unregistered currency": func(value *contracts.LaunchBlueprint) {
			value.Constraints.MaximumGrossCurrency = "ABC"
		},
		"unregistered jurisdiction": func(value *contracts.LaunchBlueprint) {
			value.Constraints.AllowedJurisdictions = []string{"ZZ"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := blueprint
			mutate(&mutated)
			mutated.BlueprintID, err = contracts.DeriveLaunchBlueprintID(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if err := contracts.ValidateLaunchBlueprint(mutated); err == nil {
				t.Fatal("correctly rehashed blueprint retained an unregistered commercial token")
			}
			if err := validateAgainstSchema(t, blueprintSchema, mutated); err == nil {
				t.Fatal("blueprint schema retained an unregistered commercial token")
			}
		})
	}
}

func TestLaunchBlueprintRejectsIdentityBearingPortableFields(t *testing.T) {
	for name, mutate := range map[string]func(*contracts.LaunchWorkloadGraph, *contracts.LaunchConstraintSet){
		"capability": func(graph *contracts.LaunchWorkloadGraph, _ *contracts.LaunchConstraintSet) {
			graph.Nodes[0].RequiredCapabilities = []string{"health-check", "tenant-secret-capability"}
		},
		"workload kind": func(graph *contracts.LaunchWorkloadGraph, _ *contracts.LaunchConstraintSet) {
			graph.Nodes[0].Kind = "tenant-private-service"
		},
		"residency tag": func(_ *contracts.LaunchWorkloadGraph, constraints *contracts.LaunchConstraintSet) {
			constraints.RequiredResidencyTags = []string{"tenant-private-region"}
		},
		"jurisdiction": func(_ *contracts.LaunchWorkloadGraph, constraints *contracts.LaunchConstraintSet) {
			constraints.AllowedJurisdictions = []string{"tenant-private-jurisdiction"}
		},
		"pattern-shaped jurisdiction": func(_ *contracts.LaunchWorkloadGraph, constraints *contracts.LaunchConstraintSet) {
			constraints.AllowedJurisdictions = []string{"ZZ"}
		},
		"pattern-shaped currency": func(_ *contracts.LaunchWorkloadGraph, constraints *contracts.LaunchConstraintSet) {
			constraints.MaximumGrossCurrency = "ABC"
		},
	} {
		t.Run(name, func(t *testing.T) {
			graph := launchHTTPWorkloadGraph()
			constraints := launchConstraintSet()
			mutate(&graph, &constraints)
			if _, err := contracts.ProjectLaunchBlueprint(graph, constraints); err == nil {
				t.Fatal("identity-bearing field was copied into clean-room blueprint")
			}
		})
	}
}

type launchRouteFixture struct {
	route         contracts.LaunchRouteBinding
	resolver      *launchTestResolver
	analysis      contracts.LaunchRepositoryAnalysis
	graph         contracts.LaunchWorkloadGraph
	constraints   contracts.LaunchConstraintSet
	quote         contracts.LaunchRouteQuote
	commercial    contracts.LaunchCommercialEvidence
	fxSnapshot    contracts.LaunchFXSnapshot
	taxSnapshot   contracts.LaunchTaxSnapshot
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
	commercial     map[string]contracts.LaunchCommercialEvidence
	fxSnapshots    map[string]contracts.LaunchFXSnapshot
	taxSnapshots   map[string]contracts.LaunchTaxSnapshot
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
func (r *launchTestResolver) ResolveLaunchCommercialEvidence(ref string) (contracts.LaunchCommercialEvidence, error) {
	value, ok := r.commercial[ref]
	if !ok {
		return value, errors.New("commercial evidence not found")
	}
	return value, nil
}
func (r *launchTestResolver) ResolveLaunchFXSnapshot(ref string) (contracts.LaunchFXSnapshot, error) {
	value, ok := r.fxSnapshots[ref]
	if !ok {
		return value, errors.New("FX snapshot not found")
	}
	return value, nil
}
func (r *launchTestResolver) ResolveLaunchTaxSnapshot(ref string) (contracts.LaunchTaxSnapshot, error) {
	value, ok := r.taxSnapshots[ref]
	if !ok {
		return value, errors.New("tax snapshot not found")
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
			{PlacementID: "placement-1", EffectID: contracts.EffectTypeDeployProductionActivate, ProviderActionURN: profile.Actions[0].ActionURN, PayloadHash: canonicalize.ComputeArtifactHash(launchProviderPayloadFixture(contracts.EffectTypeDeployProductionActivate))},
			{PlacementID: "placement-1", EffectID: contracts.EffectTypeProviderProvision, ProviderActionURN: profile.Actions[1].ActionURN, PayloadHash: canonicalize.ComputeArtifactHash(launchProviderPayloadFixture(contracts.EffectTypeProviderProvision))},
			{PlacementID: "placement-1", EffectID: contracts.EffectTypeProviderRollback, ProviderActionURN: profile.Actions[2].ActionURN, PayloadHash: canonicalize.ComputeArtifactHash(launchProviderPayloadFixture(contracts.EffectTypeProviderRollback))},
			{PlacementID: "placement-1", EffectID: contracts.EffectTypeProviderTeardown, ProviderActionURN: profile.Actions[3].ActionURN, PayloadHash: canonicalize.ComputeArtifactHash(launchProviderPayloadFixture(contracts.EffectTypeProviderTeardown))},
		},
	}
	fxSnapshot := launchFXSnapshot("fx-1", "EUR", "EUR")
	fxHash, _ := contracts.DeriveLaunchFXSnapshotHash(fxSnapshot)
	taxSnapshot := launchTaxSnapshot("tax-1", profile.ProviderID, "account:1", launchRoutingHash("1"), region.Jurisdiction, 2000)
	taxHash, _ := contracts.DeriveLaunchTaxSnapshotHash(taxSnapshot)
	commercial := contracts.LaunchCommercialEvidence{
		SchemaVersion: contracts.LaunchCommercialEvidenceSchemaVersion, EvidenceID: "commercial-1", TenantID: "tenant-1", WorkspaceID: "workspace-1", MissionID: "mission-1", QuoteCurrency: "EUR",
		PlacementCosts: []contracts.LaunchCommercialPlacementEvidence{{PlacementID: "placement-1", ProviderID: profile.ProviderID, ProviderAccountRef: "account:1", ProviderAccountHash: launchRoutingHash("1"), RegionID: region.RegionID, OfferingID: offering.OfferingID, BillingCadence: "monthly", CommitmentTerm: "monthly", ProviderCurrency: "EUR", ProviderBaseCostMinor: 1000, PriceEvidenceRef: profile.PricingEvidenceRef, PriceEvidenceHash: profile.PricingEvidenceHash, TermsEvidenceRef: profile.TermsEvidenceRef, TermsEvidenceHash: profile.TermsEvidenceHash, FXSnapshotRef: fxSnapshot.SnapshotID, FXSnapshotHash: fxHash, TaxSnapshotRef: taxSnapshot.SnapshotID, TaxSnapshotHash: taxHash, FXReserveBPS: 0, BaseCostMinor: 1000, TaxReserveMinor: 200, FXReserveMinor: 0, TaxFXReserveMinor: 200, GrossExposureMinor: 1200}},
		RetrievedAt:    "2026-07-19T00:00:00Z", ExpiresAt: "2026-07-19T12:00:00Z",
	}
	commercialHash, _ := contracts.DeriveLaunchCommercialEvidenceHash(commercial)
	fxSetHash, _ := contracts.DeriveLaunchFXSnapshotSetHash(commercial.PlacementCosts)
	taxSetHash, _ := contracts.DeriveLaunchTaxSnapshotSetHash(commercial.PlacementCosts)
	quote := contracts.LaunchRouteQuote{
		SchemaVersion: contracts.LaunchRouteQuoteSchemaVersion, QuoteID: "quote-1", TenantID: "tenant-1", WorkspaceID: "workspace-1", MissionID: "mission-1",
		WorkloadGraphHash: graphHash, ConstraintSetHash: constraintHash, Currency: "EUR",
		PlacementCosts:        []contracts.LaunchPlacementCost{{PlacementID: "placement-1", ProviderID: profile.ProviderID, ProviderAccountRef: "account:1", ProviderAccountHash: launchRoutingHash("1"), RegionID: region.RegionID, OfferingID: offering.OfferingID, BillingCadence: "monthly", CommitmentTerm: "monthly", BaseCostMinor: 1000, TaxFXReserveMinor: 200, GrossExposureMinor: 1200, VerifiedCreditMinor: 200, ExpectedCashMinor: 1000, CreditStatus: contracts.LaunchCreditVerified, OfferSnapshotRef: offer.SnapshotID, OfferSnapshotHash: offerHash, PriceEvidenceHash: profile.PricingEvidenceHash, TermsEvidenceHash: profile.TermsEvidenceHash}},
		BaseProviderCostMinor: 1000, TaxFXReserveMinor: 200, GrossExposureMinor: 1200, VerifiedCreditMinor: 200, ExpectedCashMinor: 1000,
		CreditStatus: contracts.LaunchCreditVerified, FXSnapshotHash: fxSetHash, TaxSnapshotHash: taxSetHash, CommercialEvidenceRef: commercial.EvidenceID, CommercialEvidenceHash: commercialHash,
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
			{EffectID: contracts.EffectTypeDeployProductionActivate, ProviderActionURN: profile.Actions[0].ActionURN, ProviderPayloadHash: canonicalize.ComputeArtifactHash(launchProviderPayloadFixture(contracts.EffectTypeDeployProductionActivate))},
			{EffectID: contracts.EffectTypeProviderProvision, ProviderActionURN: profile.Actions[1].ActionURN, ProviderPayloadHash: canonicalize.ComputeArtifactHash(launchProviderPayloadFixture(contracts.EffectTypeProviderProvision))},
			{EffectID: contracts.EffectTypeProviderRollback, ProviderActionURN: profile.Actions[2].ActionURN, ProviderPayloadHash: canonicalize.ComputeArtifactHash(launchProviderPayloadFixture(contracts.EffectTypeProviderRollback))},
			{EffectID: contracts.EffectTypeProviderTeardown, ProviderActionURN: profile.Actions[3].ActionURN, ProviderPayloadHash: canonicalize.ComputeArtifactHash(launchProviderPayloadFixture(contracts.EffectTypeProviderTeardown))},
		},
		ResourceSubsetHash: resourceSubsetHash, ProviderPayloadSubsetHash: payloadSubsetHash,
	}
	resolver := newLaunchResolver()
	var certification contracts.LaunchProviderCertificationRecord
	if certified {
		seed := bytes.Repeat([]byte{1}, ed25519.SeedSize)
		privateKey := ed25519.NewKeyFromSeed(seed)
		certification = signLaunchProviderCertificationRecord(t, contracts.LaunchProviderCertificationRecord{
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
	resolver.commercial[commercial.EvidenceID] = commercial
	resolver.fxSnapshots[fxSnapshot.SnapshotID] = fxSnapshot
	resolver.taxSnapshots[taxSnapshot.SnapshotID] = taxSnapshot
	resolver.offers[offer.SnapshotID] = offer
	resolver.resources[resources.ResourceGraphID] = resources
	resolver.payloads[payloads.PayloadSetID] = payloads
	resolver.generated[route.GeneratedSpecRef] = route.GeneratedSpecHash
	return launchRouteFixture{route: route, resolver: resolver, analysis: analysis, graph: graph, constraints: constraints, quote: quote, commercial: commercial, fxSnapshot: fxSnapshot, taxSnapshot: taxSnapshot, offer: offer, resources: resources, payloads: payloads, certification: certification}
}

func launchProviderPayloadFixture(effectID string) []byte {
	return []byte(`{"effect_id":"` + effectID + `","fixture":"provider-payload"}`)
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
	webFX := launchFXSnapshot("fx-edge", "EUR", "EUR")
	dbFX := launchFXSnapshot("fx-data", "EUR", "EUR")
	webFXHash, _ := contracts.DeriveLaunchFXSnapshotHash(webFX)
	dbFXHash, _ := contracts.DeriveLaunchFXSnapshotHash(dbFX)
	webTax := launchTaxSnapshot("tax-edge", webProfile.ProviderID, "account:web", launchRoutingHash("1"), "EU", 1000)
	dbTax := launchTaxSnapshot("tax-data", dbProfile.ProviderID, "account:data", launchRoutingHash("2"), "EU", 1000)
	webTaxHash, _ := contracts.DeriveLaunchTaxSnapshotHash(webTax)
	dbTaxHash, _ := contracts.DeriveLaunchTaxSnapshotHash(dbTax)
	commercial := contracts.LaunchCommercialEvidence{
		SchemaVersion: contracts.LaunchCommercialEvidenceSchemaVersion, EvidenceID: "commercial-multi", TenantID: "tenant-1", WorkspaceID: "workspace-1", MissionID: "mission-1", QuoteCurrency: "EUR",
		PlacementCosts: []contracts.LaunchCommercialPlacementEvidence{
			{PlacementID: "placement-a", ProviderID: webProfile.ProviderID, ProviderAccountRef: "account:web", ProviderAccountHash: launchRoutingHash("1"), RegionID: "eu-edge", OfferingID: "app", BillingCadence: "monthly", CommitmentTerm: "monthly", ProviderCurrency: "EUR", ProviderBaseCostMinor: 1000, PriceEvidenceRef: webProfile.PricingEvidenceRef, PriceEvidenceHash: webProfile.PricingEvidenceHash, TermsEvidenceRef: webProfile.TermsEvidenceRef, TermsEvidenceHash: webProfile.TermsEvidenceHash, FXSnapshotRef: webFX.SnapshotID, FXSnapshotHash: webFXHash, TaxSnapshotRef: webTax.SnapshotID, TaxSnapshotHash: webTaxHash, FXReserveBPS: 0, BaseCostMinor: 1000, TaxReserveMinor: 100, FXReserveMinor: 0, TaxFXReserveMinor: 100, GrossExposureMinor: 1100},
			{PlacementID: "placement-b", ProviderID: dbProfile.ProviderID, ProviderAccountRef: "account:data", ProviderAccountHash: launchRoutingHash("2"), RegionID: "eu-data", OfferingID: "postgres", BillingCadence: "monthly", CommitmentTerm: "monthly", ProviderCurrency: "EUR", ProviderBaseCostMinor: 2000, PriceEvidenceRef: dbProfile.PricingEvidenceRef, PriceEvidenceHash: dbProfile.PricingEvidenceHash, TermsEvidenceRef: dbProfile.TermsEvidenceRef, TermsEvidenceHash: dbProfile.TermsEvidenceHash, FXSnapshotRef: dbFX.SnapshotID, FXSnapshotHash: dbFXHash, TaxSnapshotRef: dbTax.SnapshotID, TaxSnapshotHash: dbTaxHash, FXReserveBPS: 0, BaseCostMinor: 2000, TaxReserveMinor: 200, FXReserveMinor: 0, TaxFXReserveMinor: 200, GrossExposureMinor: 2200},
		},
		RetrievedAt: "2026-07-19T00:00:00Z", ExpiresAt: "2026-07-19T12:00:00Z",
	}
	commercialHash, _ := contracts.DeriveLaunchCommercialEvidenceHash(commercial)
	fxSetHash, _ := contracts.DeriveLaunchFXSnapshotSetHash(commercial.PlacementCosts)
	taxSetHash, _ := contracts.DeriveLaunchTaxSnapshotSetHash(commercial.PlacementCosts)
	quote := contracts.LaunchRouteQuote{
		SchemaVersion: contracts.LaunchRouteQuoteSchemaVersion, QuoteID: "quote-multi", TenantID: "tenant-1", WorkspaceID: "workspace-1", MissionID: "mission-1", WorkloadGraphHash: graphHash, ConstraintSetHash: constraintHash, Currency: "EUR",
		PlacementCosts: []contracts.LaunchPlacementCost{
			{PlacementID: "placement-a", ProviderID: webProfile.ProviderID, ProviderAccountRef: "account:web", ProviderAccountHash: launchRoutingHash("1"), RegionID: "eu-edge", OfferingID: "app", BillingCadence: "monthly", CommitmentTerm: "monthly", BaseCostMinor: 1000, TaxFXReserveMinor: 100, GrossExposureMinor: 1100, VerifiedCreditMinor: 0, ExpectedCashMinor: 1100, CreditStatus: contracts.LaunchCreditNone, OfferSnapshotRef: webOffer.SnapshotID, OfferSnapshotHash: webOfferHash, PriceEvidenceHash: webProfile.PricingEvidenceHash, TermsEvidenceHash: webProfile.TermsEvidenceHash},
			{PlacementID: "placement-b", ProviderID: dbProfile.ProviderID, ProviderAccountRef: "account:data", ProviderAccountHash: launchRoutingHash("2"), RegionID: "eu-data", OfferingID: "postgres", BillingCadence: "monthly", CommitmentTerm: "monthly", BaseCostMinor: 2000, TaxFXReserveMinor: 200, GrossExposureMinor: 2200, VerifiedCreditMinor: 0, ExpectedCashMinor: 2200, CreditStatus: contracts.LaunchCreditNone, OfferSnapshotRef: dbOffer.SnapshotID, OfferSnapshotHash: dbOfferHash, PriceEvidenceHash: dbProfile.PricingEvidenceHash, TermsEvidenceHash: dbProfile.TermsEvidenceHash},
		},
		BaseProviderCostMinor: 3000, TaxFXReserveMinor: 300, GrossExposureMinor: 3300, VerifiedCreditMinor: 0, ExpectedCashMinor: 3300, CreditStatus: contracts.LaunchCreditNone,
		FXSnapshotHash: fxSetHash, TaxSnapshotHash: taxSetHash, CommercialEvidenceRef: commercial.EvidenceID, CommercialEvidenceHash: commercialHash, RetrievedAt: "2026-07-19T00:00:00Z", ExpiresAt: "2026-07-19T12:00:00Z",
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
	resolver.commercial[commercial.EvidenceID] = commercial
	resolver.fxSnapshots[webFX.SnapshotID] = webFX
	resolver.fxSnapshots[dbFX.SnapshotID] = dbFX
	resolver.taxSnapshots[webTax.SnapshotID] = webTax
	resolver.taxSnapshots[dbTax.SnapshotID] = dbTax
	resolver.offers[webOffer.SnapshotID] = webOffer
	resolver.offers[dbOffer.SnapshotID] = dbOffer
	resolver.resources[resources.ResourceGraphID] = resources
	resolver.payloads[payloads.PayloadSetID] = payloads
	resolver.generated[route.GeneratedSpecRef] = route.GeneratedSpecHash
	return launchRouteFixture{route: route, resolver: resolver, analysis: analysis, graph: graph, constraints: constraints, quote: quote, commercial: commercial, fxSnapshot: webFX, taxSnapshot: webTax, resources: resources, payloads: payloads}
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

func launchFXSnapshot(snapshotID, sourceCurrency, quoteCurrency string) contracts.LaunchFXSnapshot {
	return contracts.LaunchFXSnapshot{
		SchemaVersion: contracts.LaunchFXSnapshotSchemaVersion, SnapshotID: snapshotID, SourceCurrency: sourceCurrency, QuoteCurrency: quoteCurrency,
		RateNumerator: 1, RateDenominator: 1, OfficialSourceURL: "https://example.invalid/fx/" + snapshotID, ContentHash: launchRoutingHash("e"),
		RetrievedAt: "2026-07-19T00:00:00Z", ExpiresAt: "2026-07-19T13:00:00Z",
	}
}

func launchTaxSnapshot(snapshotID, providerID, accountRef, accountHash, jurisdiction string, taxRateBPS int64) contracts.LaunchTaxSnapshot {
	return contracts.LaunchTaxSnapshot{
		SchemaVersion: contracts.LaunchTaxSnapshotSchemaVersion, SnapshotID: snapshotID, TenantID: "tenant-1", WorkspaceID: "workspace-1",
		ProviderID: providerID, ProviderAccountRef: accountRef, ProviderAccountHash: accountHash, Jurisdiction: jurisdiction,
		Status: contracts.LaunchTaxProviderEstimate, TaxRateBPS: taxRateBPS, OfficialSourceURL: "https://example.invalid/tax/" + snapshotID, ContentHash: launchRoutingHash("f"),
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
	return &launchTestResolver{analyses: map[string]contracts.LaunchRepositoryAnalysis{}, graphs: map[string]contracts.LaunchWorkloadGraph{}, profiles: map[string]contracts.LaunchProviderCapabilityProfile{}, certifications: map[string]contracts.LaunchProviderCertificationRecord{}, constraints: map[string]contracts.LaunchConstraintSet{}, quotes: map[string]contracts.LaunchRouteQuote{}, commercial: map[string]contracts.LaunchCommercialEvidence{}, fxSnapshots: map[string]contracts.LaunchFXSnapshot{}, taxSnapshots: map[string]contracts.LaunchTaxSnapshot{}, offers: map[string]contracts.LaunchOfferSnapshot{}, resources: map[string]contracts.LaunchResourceGraph{}, payloads: map[string]contracts.LaunchProviderPayloadSet{}, generated: map[string]string{}, keys: map[string]ed25519.PublicKey{}, current: map[string]string{}}
}

func cloneLaunchRouteFixture(value launchRouteFixture) launchRouteFixture {
	data, _ := json.Marshal(value.route)
	var route contracts.LaunchRouteBinding
	_ = json.Unmarshal(data, &route)
	value.quote.PlacementCosts = append([]contracts.LaunchPlacementCost(nil), value.quote.PlacementCosts...)
	value.commercial.PlacementCosts = append([]contracts.LaunchCommercialPlacementEvidence(nil), value.commercial.PlacementCosts...)
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
	for key, item := range value.resolver.commercial {
		resolver.commercial[key] = item
	}
	for key, item := range value.resolver.fxSnapshots {
		resolver.fxSnapshots[key] = item
	}
	for key, item := range value.resolver.taxSnapshots {
		resolver.taxSnapshots[key] = item
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

func rebindLaunchCommercialFixture(t *testing.T, fixture *launchRouteFixture) {
	t.Helper()
	fxHash, err := contracts.DeriveLaunchFXSnapshotHash(fixture.fxSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	taxHash, err := contracts.DeriveLaunchTaxSnapshotHash(fixture.taxSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	fixture.commercial.PlacementCosts[0].FXSnapshotRef = fixture.fxSnapshot.SnapshotID
	fixture.commercial.PlacementCosts[0].FXSnapshotHash = fxHash
	fixture.commercial.PlacementCosts[0].TaxSnapshotRef = fixture.taxSnapshot.SnapshotID
	fixture.commercial.PlacementCosts[0].TaxSnapshotHash = taxHash
	commercialHash, err := contracts.DeriveLaunchCommercialEvidenceHash(fixture.commercial)
	if err != nil {
		t.Fatal(err)
	}
	fxSetHash, err := contracts.DeriveLaunchFXSnapshotSetHash(fixture.commercial.PlacementCosts)
	if err != nil {
		t.Fatal(err)
	}
	taxSetHash, err := contracts.DeriveLaunchTaxSnapshotSetHash(fixture.commercial.PlacementCosts)
	if err != nil {
		t.Fatal(err)
	}
	fixture.quote.CommercialEvidenceRef = fixture.commercial.EvidenceID
	fixture.quote.CommercialEvidenceHash = commercialHash
	fixture.quote.FXSnapshotHash = fxSetHash
	fixture.quote.TaxSnapshotHash = taxSetHash
	quoteHash, err := contracts.DeriveLaunchRouteQuoteHash(fixture.quote)
	if err != nil {
		t.Fatal(err)
	}
	fixture.route.RouteQuoteHash = quoteHash
	fixture.resolver.quotes[fixture.quote.QuoteID] = fixture.quote
	fixture.resolver.commercial[fixture.commercial.EvidenceID] = fixture.commercial
	fixture.resolver.fxSnapshots[fixture.fxSnapshot.SnapshotID] = fixture.fxSnapshot
	fixture.resolver.taxSnapshots[fixture.taxSnapshot.SnapshotID] = fixture.taxSnapshot
}

func launchRoutingHash(char string) string {
	return "sha256:" + strings.Repeat(char, 64)
}

func signLaunchProviderCertificationRecord(t *testing.T, record contracts.LaunchProviderCertificationRecord, privateKey ed25519.PrivateKey) contracts.LaunchProviderCertificationRecord {
	t.Helper()
	payload, err := contracts.LaunchProviderCertificationSigningBytes(record)
	if err != nil {
		t.Fatal(err)
	}
	record.RecordHash = canonicalize.ComputeArtifactHash(payload)
	record.Signature = "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, payload))
	return record
}
