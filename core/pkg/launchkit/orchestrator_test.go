package launchkit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

type fakeProvider struct {
	available bool
}

func (f fakeProvider) ID() Target { return TargetLocal }

func (f fakeProvider) SubstrateID() string { return "local-container" }

func (f fakeProvider) Probe() EnvironmentCapability {
	return EnvironmentCapability{
		ID:                    "local.fake",
		Kind:                  "local-container",
		Available:             f.available,
		AuthState:             "not-required",
		CostEstimate:          "none",
		SecretBackend:         "test",
		NetworkBoundary:       "deny",
		RuntimeBoundary:       "fake",
		LogBoundary:           "test",
		TeardownSupport:       "cascade",
		EvidenceExportSupport: "local",
		Detail:                "test provider",
	}
}

func TestUpDemoUsesScopedDemoSecretsAndDoesNotRequireDocker(t *testing.T) {
	catalog := loadTestCatalog(t)
	store := session.NewStore(t.TempDir())
	t.Setenv("OPENROUTER_API_KEY", "")

	orch := New(catalog, store)
	orch.Providers[TargetLocal] = fakeProvider{available: false}
	result, err := orch.Up(Options{AppID: "openclaw", Mode: ModeDemo, Target: TargetLocal, NoOpen: true})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if result.Run == nil || result.Run.KernelVerdict != "ALLOW" || result.Run.State != session.StateRunning {
		t.Fatalf("demo run did not reach receipt-backed running state: %#v", result.Run)
	}
	if result.Mode != ModeDemo {
		t.Fatalf("mode = %s, want demo", result.Mode)
	}
	if os.Getenv("OPENROUTER_API_KEY") != "" {
		t.Fatal("demo secret leaked into process environment after launch")
	}
	if result.ConsoleURL == "" || result.OfflineVerifyCommand == "" {
		t.Fatalf("developer output missing console/evidence refs: %#v", result)
	}
}

func TestUpLiveEscalatesWhenLocalRuntimeUnavailable(t *testing.T) {
	catalog := loadTestCatalog(t)
	store := session.NewStore(t.TempDir())
	t.Setenv("OPENROUTER_API_KEY", "test-key")

	orch := New(catalog, store)
	orch.Providers[TargetLocal] = fakeProvider{available: false}
	result, err := orch.Up(Options{AppID: "openclaw", Mode: ModeLive, Target: TargetLocal, NoOpen: true})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if result.Run == nil || result.Run.KernelVerdict != "ESCALATE" || result.Run.ReasonCode != "ERR_LAUNCHKIT_LOCAL_RUNTIME_UNAVAILABLE" {
		t.Fatalf("live unavailable runtime should escalate before side effects: %#v", result.Run)
	}
	if result.StartedRuntime {
		t.Fatal("runtime should not start after local runtime preflight escalation")
	}
}

func TestUpVerifyOnlyDoesNotCreateRun(t *testing.T) {
	catalog := loadTestCatalog(t)
	t.Setenv("OPENROUTER_API_KEY", "test-key")

	orch := New(catalog, session.NewStore(t.TempDir()))
	orch.Providers[TargetLocal] = fakeProvider{available: true}
	result, err := orch.Up(Options{AppID: "openclaw", Mode: ModeVerifyOnly, Target: TargetLocal, NoOpen: true})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if result.Run != nil {
		t.Fatalf("verify-only must not create a runtime run: %#v", result.Run)
	}
	if result.Plan == nil || result.Plan.KernelVerdict != "ALLOW" {
		t.Fatalf("verify-only should compile an allowed LaunchPlan: %#v", result.Plan)
	}
}

func TestUpCloudEscalatesWithProofAndNoRuntime(t *testing.T) {
	catalog := loadTestCatalog(t)
	orch := New(catalog, session.NewStore(t.TempDir()))
	result, err := orch.Up(Options{AppID: "openclaw", Mode: ModeLive, Target: TargetCloudAWS, NoOpen: true})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if result.Run == nil || result.Run.KernelVerdict != "ESCALATE" || result.Run.ReasonCode != "ERR_LAUNCHKIT_CLOUD_APPROVAL_REQUIRED" {
		t.Fatalf("cloud target should escalate before paid resources: %#v", result.Run)
	}
	if result.StartedRuntime {
		t.Fatal("cloud preflight must not start runtime")
	}
}

func TestSupplyChainRejectsDigestMismatch(t *testing.T) {
	catalog := loadTestCatalog(t)
	for index := range catalog.Apps {
		if catalog.Apps[index].ID == "openclaw" {
			catalog.Apps[index].SupplyChainEvidence.ArtifactDigest = "sha256:bad"
		}
	}
	orch := New(catalog, session.NewStore(t.TempDir()))
	orch.Providers[TargetLocal] = fakeProvider{available: true}
	result, err := orch.Up(Options{AppID: "openclaw", Mode: ModeDemo, Target: TargetLocal, NoOpen: true})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if result.Run == nil || result.Run.KernelVerdict != "DENY" || result.Run.ReasonCode != "ERR_LAUNCHKIT_ARTIFACT_DIGEST_MISMATCH" {
		t.Fatalf("bad digest should deny before runtime: %#v", result.Run)
	}
}

func loadTestCatalog(t *testing.T) *registry.Catalog {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(wd, "../../.."))
	catalog, err := registry.LoadCatalog(root)
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	if err := catalog.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return catalog
}
