package launchpad_test

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestNoAppAvailableWithoutFullConformance(t *testing.T) {
	catalog, err := registry.LoadCatalog("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if err := catalog.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, app := range catalog.Apps {
		if app.Availability == registry.AvailabilityOSSSupported && !app.Conformance.FullyVerified() {
			t.Fatalf("%s is oss_supported without full conformance", app.ID)
		}
	}
}

func TestMatrixDoesNotLaunchCandidates(t *testing.T) {
	catalog, err := registry.LoadCatalog("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range catalog.Matrix() {
		if cell.Availability != registry.AvailabilityOSSSupported && cell.Launchable {
			t.Fatalf("%s/%s is launchable without supported availability", cell.AppID, cell.SubstrateID)
		}
	}
}

func TestPlanEscalatesUnverifiedOpenClaw(t *testing.T) {
	catalog, err := registry.LoadCatalog("../../..")
	if err != nil {
		t.Fatal(err)
	}
	app, ok := catalog.App("openclaw")
	if !ok {
		t.Fatal("openclaw missing")
	}
	substrate, ok := catalog.Substrate("local-container")
	if !ok {
		t.Fatal("local-container missing")
	}
	compiled, err := plan.Compile(app, substrate, "test.principal")
	if err == nil {
		t.Fatal("expected unverified app escalation")
	}
	if compiled.KernelVerdict != "ESCALATE" || compiled.Status != "ESCALATED" {
		t.Fatalf("expected ESCALATED plan, got %s/%s", compiled.KernelVerdict, compiled.Status)
	}
}

func TestPlanHashStableAcrossLaunchIDs(t *testing.T) {
	catalog, err := registry.LoadCatalog("../../..")
	if err != nil {
		t.Fatal(err)
	}
	app, ok := catalog.App("openclaw")
	if !ok {
		t.Fatal("openclaw missing")
	}
	substrate, ok := catalog.Substrate("local-container")
	if !ok {
		t.Fatal("local-container missing")
	}
	first, _ := plan.Compile(app, substrate, "test.principal")
	second, _ := plan.Compile(app, substrate, "test.principal")
	if first.LaunchID == second.LaunchID {
		t.Fatal("test expected unique launch ids")
	}
	if first.PlanHash != second.PlanHash {
		t.Fatalf("plan hash must be stable across launch ids: %s != %s", first.PlanHash, second.PlanHash)
	}
}
