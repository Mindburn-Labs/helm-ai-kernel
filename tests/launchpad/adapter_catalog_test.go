package launchpad_test

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestExternalCLIAdaptersRemainFailClosed(t *testing.T) {
	root := repoRoot(t)
	catalog, err := registry.LoadCatalog(root)
	if err != nil {
		t.Fatal(err)
	}

	type expectation struct {
		command         string
		healthcheck     string
		licenseStatus   string
		licenseSPDX     string
		licenseURL      string
		redistribution  string
		upstreamCLIDocs string
	}
	expected := map[string]expectation{
		"gemini.external": {
			command:        "gemini",
			healthcheck:    "gemini --version",
			licenseStatus:  "upstream_oss_byo",
			licenseSPDX:    "Apache-2.0",
			licenseURL:     "https://github.com/google-gemini/gemini-cli/blob/main/LICENSE",
			redistribution: "helm_does_not_redistribute_byo_tool",
		},
		"grok.external": {
			command:         "grok",
			healthcheck:     "grok version",
			licenseStatus:   "proprietary_byo",
			redistribution:  "prohibited",
			upstreamCLIDocs: "https://docs.x.ai/build/cli/reference",
		},
		"kimi.external": {
			command:        "kimi",
			healthcheck:    "kimi --version",
			licenseStatus:  "upstream_oss_byo",
			licenseSPDX:    "MIT",
			licenseURL:     "https://github.com/MoonshotAI/kimi-code/blob/main/LICENSE",
			redistribution: "helm_does_not_redistribute_byo_tool",
		},
		"pi.external": {
			command:        "pi",
			healthcheck:    "pi --version",
			licenseStatus:  "upstream_oss_byo",
			licenseSPDX:    "MIT",
			licenseURL:     "https://github.com/earendil-works/pi/blob/main/LICENSE",
			redistribution: "helm_does_not_redistribute_byo_tool",
		},
	}

	for id, want := range expected {
		app, ok := catalog.App(id)
		if !ok {
			t.Fatalf("%s missing from Launchpad catalog", id)
		}
		if app.Availability != registry.AvailabilityExternalProprietaryAdapter {
			t.Fatalf("%s availability = %q, want %q", id, app.Availability, registry.AvailabilityExternalProprietaryAdapter)
		}
		if app.SupportLevel != registry.SupportLevelExternalBYOAdapter {
			t.Fatalf("%s support level = %q, want %q", id, app.SupportLevel, registry.SupportLevelExternalBYOAdapter)
		}
		if app.Install.Strategy != "byo_tool" {
			t.Fatalf("%s install strategy = %q, want byo_tool", id, app.Install.Strategy)
		}
		if len(app.Runtime.Command) != 1 || app.Runtime.Command[0] != want.command {
			t.Fatalf("%s runtime command = %#v, want [%q]", id, app.Runtime.Command, want.command)
		}
		if len(app.Healthchecks) != 1 || app.Healthchecks[0].Type != "command" || app.Healthchecks[0].Command != want.healthcheck {
			t.Fatalf("%s healthcheck = %#v, want command %q", id, app.Healthchecks, want.healthcheck)
		}
		if app.FrameworkContract.Healthcheck != want.healthcheck {
			t.Fatalf("%s framework healthcheck = %q, want %q", id, app.FrameworkContract.Healthcheck, want.healthcheck)
		}
		if app.BudgetCeiling.USDMax != 0 || app.BudgetCeiling.APICallsMax != 0 || app.BudgetCeiling.TimeMSMax != 0 {
			t.Fatalf("%s budget ceiling = %#v, want all zero", id, app.BudgetCeiling)
		}
		if app.Conformance.LicenseVerified || app.Conformance.ArtifactVerified || app.Conformance.SandboxVerified || app.Conformance.HealthcheckPassing || app.Conformance.E2EPassing || app.Conformance.TeardownVerified || app.Conformance.ReceiptVerified || app.Conformance.EvidencePackVerified || app.Conformance.FullyVerified() {
			t.Fatalf("%s has verified conformance: %#v", id, app.Conformance)
		}
		if app.License.Status != want.licenseStatus || app.License.SPDX != want.licenseSPDX || app.License.URL != want.licenseURL {
			t.Fatalf("%s license = %#v, want status=%q spdx=%q url=%q", id, app.License, want.licenseStatus, want.licenseSPDX, want.licenseURL)
		}
		if app.Redistribution != want.redistribution {
			t.Fatalf("%s redistribution = %q, want %q", id, app.Redistribution, want.redistribution)
		}
		if want.upstreamCLIDocs != "" && app.Metadata["upstream_cli_docs"] != want.upstreamCLIDocs {
			t.Fatalf("%s upstream CLI docs = %q, want %q", id, app.Metadata["upstream_cli_docs"], want.upstreamCLIDocs)
		}
	}
}
