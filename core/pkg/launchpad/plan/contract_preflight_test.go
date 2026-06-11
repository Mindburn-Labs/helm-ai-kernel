package plan

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestBuildContractPreflightProvesRequiredRuntimeContract(t *testing.T) {
	app := verifiedAppSpec()
	launch := launchPlanForContractTest(app)

	preflight := BuildContractPreflight(app, supportedSubstrate(), launch)
	if preflight.ContractStatus != "PASS" || preflight.Verdict != "ALLOW" || preflight.ResultClass != "" || preflight.RepairClass != RepairClassNone {
		t.Fatalf("preflight = %#v", preflight)
	}
	for _, want := range []string{
		"image.digest_parity",
		"command.parity",
		"sandbox.local_container",
		"egress_proxy.artifact",
		"paths.writable_home_cache_state",
		"secrets.scoped_projection",
		"mcp.manifest_parity",
		"healthcheck.runtime_path",
		"evidence.offline_verify",
		"runtime_installs.forbidden",
	} {
		if !hasContractCheck(preflight, want) {
			t.Fatalf("preflight missing check %s: %#v", want, preflight.Checks)
		}
	}
}

func TestBuildContractPreflightFailsClosedForContractDrift(t *testing.T) {
	base := verifiedAppSpec()
	cases := []struct {
		name        string
		mutateApp   func(*registry.AppSpec)
		mutatePlan  func(*LaunchPlan)
		wantCheckID string
	}{
		{
			name: "digest parity",
			mutateApp: func(app *registry.AppSpec) {
				app.SupplyChainEvidence.ArtifactDigest = "sha256:" + strings.Repeat("c", 64)
			},
			wantCheckID: "image.digest_parity",
		},
		{
			name:        "command parity",
			mutatePlan:  func(launch *LaunchPlan) { launch.RuntimeCommand = []string{"other", "run"} },
			wantCheckID: "command.parity",
		},
		{
			name: "writable home cache state",
			mutateApp: func(app *registry.AppSpec) {
				app.FrameworkContract.WritablePaths = nil
			},
			wantCheckID: "paths.writable_home_cache_state",
		},
		{
			name: "egress proxy required",
			mutateApp: func(app *registry.AppSpec) {
				app.FrameworkContract.EgressProxy = registry.EgressProxyContractSpec{Required: true}
			},
			wantCheckID: "egress_proxy.artifact",
		},
		{
			name: "secret projection",
			mutateApp: func(app *registry.AppSpec) {
				app.RequiredSecrets = []string{"model_gateway"}
				app.ModelGatewayEnv = []string{"OPENAI_API_KEY"}
				app.ModelGateway = registry.ModelGatewaySpec{}
			},
			wantCheckID: "secrets.scoped_projection",
		},
		{
			name: "mcp manifest parity",
			mutateApp: func(app *registry.AppSpec) {
				app.MCPManifests = []string{"openclaw.default"}
			},
			wantCheckID: "mcp.manifest_parity",
		},
		{
			name: "healthcheck proof",
			mutateApp: func(app *registry.AppSpec) {
				app.FrameworkContract.Healthcheck = "wrong-healthcheck"
			},
			wantCheckID: "healthcheck.runtime_path",
		},
		{
			name: "runtime installer pattern",
			mutateApp: func(app *registry.AppSpec) {
				app.Runtime.Command = []string{"/bin/sh", "-c", "npm install && openclaw --serve"}
			},
			wantCheckID: "runtime_installs.forbidden",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := base
			if tc.mutateApp != nil {
				tc.mutateApp(&app)
			}
			launch := launchPlanForContractTest(app)
			if tc.mutatePlan != nil {
				tc.mutatePlan(&launch)
			}
			preflight := BuildContractPreflight(app, supportedSubstrate(), launch)
			if preflight.ContractStatus != "REPAIR_REQUIRED" || preflight.Verdict != "DENY" || preflight.ResultClass != ResultClassRuntimeRepairRequired || preflight.RepairClass != RepairClassContractRepairRequired {
				t.Fatalf("preflight = %#v", preflight)
			}
			check := contractCheck(preflight, tc.wantCheckID)
			if check == nil || check.Verdict != "DENY" {
				t.Fatalf("check %s not denied: %#v", tc.wantCheckID, preflight.Checks)
			}
		})
	}
}

func launchPlanForContractTest(app registry.AppSpec) LaunchPlan {
	return LaunchPlan{
		AppID:            app.ID,
		SubstrateID:      "local-container",
		ArtifactImage:    app.Install.Image,
		ArtifactDigest:   app.Install.Digest,
		SupportLevel:     app.SupportLevel,
		RuntimeCommand:   append([]string{}, app.Runtime.Command...),
		Healthchecks:     append([]registry.HealthcheckSpec{}, app.Healthchecks...),
		FilesystemMounts: append([]string{}, app.FilesystemPolicy.Mounts...),
		StateDirEnv:      app.FilesystemPolicy.StateDirEnv,
		MCPPolicy:        app.MCPPolicy,
	}
}

func hasContractCheck(preflight ContractPreflight, id string) bool {
	return contractCheck(preflight, id) != nil
}

func contractCheck(preflight ContractPreflight, id string) *ContractCheck {
	for index := range preflight.Checks {
		if preflight.Checks[index].ID == id {
			return &preflight.Checks[index]
		}
	}
	return nil
}
