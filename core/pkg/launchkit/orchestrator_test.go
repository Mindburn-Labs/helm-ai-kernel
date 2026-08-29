package launchkit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	lpsecrets "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/secrets"
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
	result, err := orch.Up(Options{AppID: "openclaw", Mode: ModeDemo, Target: TargetLocal})
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
	if result.OfflineVerifyCommand == "" {
		t.Fatalf("developer output missing offline evidence command: %#v", result)
	}
}

func TestConcurrentLaunchesKeepSameNameCredentialsLaunchScoped(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "")
	t.Setenv("HELM_TEST_LAUNCH_SECRET_A", "launch-a-only-secret")
	t.Setenv("HELM_TEST_LAUNCH_SECRET_B", "launch-b-only-secret")
	catalog := loadTestCatalog(t)

	var ready sync.WaitGroup
	ready.Add(2)
	release := make(chan struct{})
	seen := make(chan string, 2)
	type launchResult struct {
		result Result
		err    error
	}
	results := make(chan launchResult, 2)
	roots := []string{t.TempDir(), t.TempDir()}
	sourceEnvs := []string{"HELM_TEST_LAUNCH_SECRET_A", "HELM_TEST_LAUNCH_SECRET_B"}
	for i := range roots {
		store := session.NewStore(roots[i])
		if _, err := lpsecrets.NewStore(roots[i]).Set("model_gateway", "openrouter", sourceEnvs[i]); err != nil {
			t.Fatalf("bind launch %d secret: %v", i, err)
		}
		orch := New(catalog, store)
		orch.Providers[TargetLocal] = fakeProvider{available: true}
		orch.Executor.RuntimeStarter = launchScopedSecretStarter{ready: &ready, release: release, seen: seen}
		orch.Executor.HealthcheckRunner = launchScopedHealthcheck{}
		go func() {
			result, err := orch.Up(Options{AppID: "openclaw", Mode: ModeLive, Target: TargetLocal})
			results <- launchResult{result: result, err: err}
		}()
	}

	startersReady := make(chan struct{})
	go func() {
		ready.Wait()
		close(startersReady)
	}()
	select {
	case <-startersReady:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("concurrent launches did not both reach the child runtime boundary")
	}
	close(release)

	var runs []session.LaunchRun
	for range roots {
		got := <-results
		if got.err != nil || got.result.Run == nil || got.result.Run.State != session.StateRunning {
			t.Fatalf("concurrent launch failed: result=%#v err=%v", got.result, got.err)
		}
		if len(got.result.Run.SecretAccessRefs) == 0 {
			t.Fatalf("launch omitted redacted secret access receipt: %#v", got.result.Run)
		}
		runs = append(runs, *got.result.Run)
	}
	gotSecrets := map[string]bool{<-seen: true, <-seen: true}
	if !gotSecrets["launch-a-only-secret"] || !gotSecrets["launch-b-only-secret"] || len(gotSecrets) != 2 {
		t.Fatalf("launch credential overlays crossed: %#v", gotSecrets)
	}
	if got := os.Getenv("OPENROUTER_API_KEY"); got != "" {
		t.Fatalf("launches contaminated process env: %q", got)
	}
	for _, run := range runs {
		receiptPath := filepath.Join(run.EvidencePackRefs[0], "02_PROOFGRAPH", "receipts", "launchpad-secret-binding-access.json")
		data, err := os.ReadFile(receiptPath)
		if err != nil {
			t.Fatalf("read redacted access receipt: %v", err)
		}
		var receipt map[string]any
		if err := json.Unmarshal(data, &receipt); err != nil {
			t.Fatalf("decode redacted access receipt: %v", err)
		}
		encoded := string(data)
		for _, want := range []string{"local.operator", "openclaw", run.LaunchID, "model_gateway:openrouter", "OPENROUTER_API_KEY", "ALLOW"} {
			if !strings.Contains(encoded, want) {
				t.Fatalf("redacted access receipt missing %q: %#v", want, receipt)
			}
		}
		if strings.Contains(encoded, "launch-a-only-secret") || strings.Contains(encoded, "launch-b-only-secret") {
			t.Fatalf("redacted access receipt exposed secret value: %s", data)
		}
	}
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), "launch-a-only-secret") || strings.Contains(string(data), "launch-b-only-secret") {
				t.Fatalf("persisted launch artifact exposed secret value: %s", path)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

type launchScopedSecretStarter struct {
	ready   *sync.WaitGroup
	release <-chan struct{}
	seen    chan<- string
}

func (s launchScopedSecretStarter) Start(_ plan.LaunchPlan, opts session.ExecuteOptions) (session.RuntimeStartResult, error) {
	s.ready.Done()
	<-s.release
	s.seen <- opts.RuntimeSecretEnv["OPENROUTER_API_KEY"]
	return session.RuntimeStartResult{
		ContainerID:       "launch-scoped-container",
		SandboxGrantRef:   "receipt:launch-scoped:sandbox",
		EgressReceiptRef:  "receipt:launch-scoped:egress",
		EgressNetworkName: "launch-scoped-network",
		Runtime:           "local-container",
	}, nil
}

type launchScopedHealthcheck struct{}

func (launchScopedHealthcheck) Run(plan.LaunchPlan, session.RuntimeStartResult, session.ExecuteOptions) (session.HealthcheckResult, error) {
	return session.HealthcheckResult{Type: "command", Status: "passed"}, nil
}

func TestUpLiveEscalatesWhenLocalRuntimeUnavailable(t *testing.T) {
	catalog := loadTestCatalog(t)
	store := session.NewStore(t.TempDir())
	t.Setenv("OPENROUTER_API_KEY", "test-key")

	orch := New(catalog, store)
	orch.Providers[TargetLocal] = fakeProvider{available: false}
	result, err := orch.Up(Options{AppID: "openclaw", Mode: ModeLive, Target: TargetLocal})
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

func TestUpLiveFailsClosedWhenSecretBindingIsMissing(t *testing.T) {
	catalog := loadTestCatalog(t)
	store := session.NewStore(t.TempDir())
	t.Setenv("OPENROUTER_API_KEY", "")

	orch := New(catalog, store)
	orch.Providers[TargetLocal] = fakeProvider{available: true}
	result, err := orch.Up(Options{AppID: "openclaw", Mode: ModeLive, Target: TargetLocal})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if result.Run == nil || result.Run.KernelVerdict != "ESCALATE" || result.Run.ReasonCode != "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING" {
		t.Fatalf("missing binding did not fail closed before runtime: %#v", result.Run)
	}
	if len(result.Run.SecretAccessRefs) == 0 || result.StartedRuntime {
		t.Fatalf("missing binding lacked redacted access proof or started runtime: %#v", result)
	}
}

func TestUpVerifyOnlyDoesNotCreateRun(t *testing.T) {
	catalog := loadTestCatalog(t)
	t.Setenv("OPENROUTER_API_KEY", "test-key")

	orch := New(catalog, session.NewStore(t.TempDir()))
	orch.Providers[TargetLocal] = fakeProvider{available: true}
	result, err := orch.Up(Options{AppID: "openclaw", Mode: ModeVerifyOnly, Target: TargetLocal})
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
	result, err := orch.Up(Options{AppID: "openclaw", Mode: ModeLive, Target: TargetCloudAWS})
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
	result, err := orch.Up(Options{AppID: "openclaw", Mode: ModeDemo, Target: TargetLocal})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if result.Run == nil || result.Run.KernelVerdict != "DENY" || result.Run.ReasonCode != "ERR_LAUNCHKIT_ARTIFACT_DIGEST_MISMATCH" {
		t.Fatalf("bad digest should deny before runtime: %#v", result.Run)
	}
}

func TestBindRunGatesReflectsRuntimeRepairStates(t *testing.T) {
	cases := []struct {
		name          string
		run           session.LaunchRun
		wantRuntime   GateStatus
		wantHealth    GateStatus
		wantRuntimeRC string
		wantHealthRC  string
	}{
		{
			name: "runtime start failure",
			run: session.LaunchRun{
				KernelVerdict: "ALLOW",
				State:         session.StateRepairRequired,
				Reason:        "runtime start failed after ALLOW; repair required before RUNNING",
			},
			wantRuntime:   GateEscalate,
			wantHealth:    GateSkipped,
			wantRuntimeRC: "ERR_LAUNCHKIT_RUNTIME_REPAIR_REQUIRED",
			wantHealthRC:  "ERR_LAUNCHKIT_RUNTIME_REPAIR_REQUIRED",
		},
		{
			name: "healthcheck failure after runtime start",
			run: session.LaunchRun{
				KernelVerdict: "ALLOW",
				State:         session.StateRepairRequired,
				StartReceiptRefs: []string{
					"launchpad.start:run-1",
				},
				RuntimeHandles: session.RuntimeHandles{ContainerID: "container-1"},
			},
			wantRuntime:   GateEscalate,
			wantHealth:    GateEscalate,
			wantRuntimeRC: "ERR_LAUNCHKIT_RUNTIME_REPAIR_REQUIRED",
			wantHealthRC:  "ERR_LAUNCHKIT_RUNTIME_REPAIR_REQUIRED",
		},
		{
			name: "running",
			run: session.LaunchRun{
				KernelVerdict:    "ALLOW",
				State:            session.StateRunning,
				StartReceiptRefs: []string{"launchpad.start:run-1"},
				HealthcheckRefs:  []string{"launchpad.healthcheck:run-1"},
				RuntimeHandles:   session.RuntimeHandles{ContainerID: "container-1"},
			},
			wantRuntime: GateAllow,
			wantHealth:  GateAllow,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gates := bindRunGates(canonicalGates(), tc.run)
			runtimeGate := gateByID(t, gates, "runtime.launch")
			healthGate := gateByID(t, gates, "healthcheck")
			if runtimeGate.Status != tc.wantRuntime || runtimeGate.ReasonCode != tc.wantRuntimeRC {
				t.Fatalf("runtime gate = %s/%q, want %s/%q", runtimeGate.Status, runtimeGate.ReasonCode, tc.wantRuntime, tc.wantRuntimeRC)
			}
			if healthGate.Status != tc.wantHealth || healthGate.ReasonCode != tc.wantHealthRC {
				t.Fatalf("health gate = %s/%q, want %s/%q", healthGate.Status, healthGate.ReasonCode, tc.wantHealth, tc.wantHealthRC)
			}
		})
	}
}

func TestBindRunGatesEscalatesMissingEgressReceipt(t *testing.T) {
	run := session.LaunchRun{
		KernelVerdict:    "ALLOW",
		State:            session.StateRunning,
		StartReceiptRefs: []string{"launchpad.start:run-1"},
		HealthcheckRefs:  []string{"launchpad.healthcheck:run-1"},
		EvidencePackRefs: []string{"evidence-pack:run-1"},
		RuntimeHandles: session.RuntimeHandles{
			ContainerID:       "container-1",
			EgressNetworkName: "launch-egress-run-1",
			EgressProxyID:     "proxy-1",
		},
		VerificationCommand: "helm-ai-kernel verify --bundle evidence-pack.tar",
	}

	gates := bindRunGates(canonicalGates(), run)
	runtimeGate := gateByID(t, gates, "runtime.launch")
	healthGate := gateByID(t, gates, "healthcheck")
	receiptGate := gateByID(t, gates, "receipts.emit")
	if runtimeGate.Status != GateAllow || healthGate.Status != GateAllow {
		t.Fatalf("runtime gates should remain ALLOW with start and health receipts: runtime=%#v health=%#v", runtimeGate, healthGate)
	}
	if receiptGate.Status != GateEscalate || receiptGate.ReasonCode != "ERR_LAUNCHKIT_EGRESS_RECEIPT_MISSING" {
		t.Fatalf("receipts gate = %s/%q, want ESCALATE/ERR_LAUNCHKIT_EGRESS_RECEIPT_MISSING", receiptGate.Status, receiptGate.ReasonCode)
	}
}

func TestHermesProductionScopeIsOpenRouterOnly(t *testing.T) {
	catalog := loadTestCatalog(t)
	app, ok := catalog.App("hermes")
	if !ok {
		t.Fatal("hermes AppSpec missing from catalog")
	}
	groups := launchkitModelGatewayEnvGroups(app)
	if len(groups) != 1 || len(groups[0]) != 1 || groups[0][0] != "OPENROUTER_API_KEY" {
		t.Fatalf("Hermes model gateway groups = %#v, want only OPENROUTER_API_KEY", groups)
	}

	t.Setenv("OPENROUTER_API_KEY", "test-openrouter")
	orch := New(catalog, session.NewStore(t.TempDir()))
	orch.Providers[TargetLocal] = fakeProvider{available: true}
	result, err := orch.Up(Options{AppID: "hermes", Mode: ModeVerifyOnly, Target: TargetLocal})
	if err != nil {
		t.Fatalf("Up verify-only: %v", err)
	}
	if result.Plan == nil || result.Plan.KernelVerdict != "ALLOW" {
		t.Fatalf("Hermes should compile with OpenRouter only: %#v", result.Plan)
	}
	if len(result.Plan.ModelGatewayEnv) != 1 || result.Plan.ModelGatewayEnv[0] != "OPENROUTER_API_KEY" {
		t.Fatalf("Hermes model gateway env = %#v, want OPENROUTER_API_KEY only", result.Plan.ModelGatewayEnv)
	}
	if !hasString(result.Plan.NetworkAllowlist, "https://openrouter.ai/api/v1") ||
		!hasString(result.Plan.NetworkAllowlist, "https://api.openrouter.ai/api/v1") ||
		hasString(result.Plan.NetworkAllowlist, "https://api.openai.com/v1") ||
		hasString(result.Plan.NetworkAllowlist, "https://api.anthropic.com/v1") {
		t.Fatalf("Hermes network allowlist is not OpenRouter-only: %#v", result.Plan.NetworkAllowlist)
	}
}

func gateByID(t *testing.T, gates []Gate, id string) Gate {
	t.Helper()
	for _, gate := range gates {
		if gate.ID == id {
			return gate
		}
	}
	t.Fatalf("missing gate %s in %#v", id, gates)
	return Gate{}
}

func hasString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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
