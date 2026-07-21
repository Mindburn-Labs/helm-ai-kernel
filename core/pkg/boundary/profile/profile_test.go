package profile

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/firewall"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

func fixtureInput() ProfileInput {
	return ProfileInput{
		SchemaVersion: ProfileInputSchemaVersion,
		ProfileID:     "harsh-mdc-01",
		ModeTier:      TierEnforce,
		Topology: Topology{
			GatewayUnit:   "helm-gateway.service",
			WorkloadUnits: []string{"orchestrator.service"},
			Gateway:       GatewayEndpoint{Kind: "tcp", Address: "127.0.0.1:7714"},
		},
		Egress: firewall.EgressPolicy{
			AllowedDomains:   []string{"api.openai.com"},
			AllowedCIDRs:     []string{"203.0.113.0/24"},
			AllowedProtocols: []string{"https"},
			MaxPayloadBytes:  1048576,
		},
		Resources:     sandbox.ResourceLimits{CPUMillis: 500, MemoryMB: 512, MaxProcesses: 128},
		Hardening:     DefaultHardening(),
		DevicePermits: []string{"/dev/null rw"},
	}
}

func TestValidateFixture(t *testing.T) {
	if err := fixtureInput().Validate(); err != nil {
		t.Fatalf("fixture input must validate: %v", err)
	}
}

func TestValidateRejections(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*ProfileInput)
		wantSub string
	}{
		{"wrong schema version", func(in *ProfileInput) { in.SchemaVersion = "v2" }, "schema_version"},
		{"uppercase profile id", func(in *ProfileInput) { in.ProfileID = "Harsh" }, "profile_id"},
		{"unknown tier", func(in *ProfileInput) { in.ModeTier = "guarded" }, "mode_tier"},
		{"gateway unit not a service", func(in *ProfileInput) { in.Topology.GatewayUnit = "helm-gateway" }, "gateway_unit"},
		{"workload unit not a service", func(in *ProfileInput) { in.Topology.WorkloadUnits = []string{"orchestrator"} }, "workload unit"},
		{"duplicate workload unit", func(in *ProfileInput) {
			in.Topology.WorkloadUnits = []string{"orchestrator.service", "orchestrator.service"}
		}, "more than once"},
		{"workload equals gateway", func(in *ProfileInput) {
			in.Topology.WorkloadUnits = []string{"helm-gateway.service"}
		}, "more than once"},
		{"tcp gateway with hostname", func(in *ProfileInput) { in.Topology.Gateway.Address = "gateway.local:7714" }, "literal IP"},
		{"tcp gateway with zero port", func(in *ProfileInput) { in.Topology.Gateway.Address = "127.0.0.1:0" }, "non-zero port"},
		{"tcp gateway with path", func(in *ProfileInput) { in.Topology.Gateway.Path = "/run/helm.sock" }, "must not set path"},
		{"unix gateway relative path", func(in *ProfileInput) {
			in.Topology.Gateway = GatewayEndpoint{Kind: "unix", Path: "run/helm.sock"}
		}, "absolute"},
		{"unix gateway with address", func(in *ProfileInput) {
			in.Topology.Gateway = GatewayEndpoint{Kind: "unix", Path: "/run/helm.sock", Address: "127.0.0.1:1"}
		}, "must not set address"},
		{"unknown endpoint kind", func(in *ProfileInput) { in.Topology.Gateway.Kind = "vsock" }, "kind"},
		{"invalid egress cidr", func(in *ProfileInput) { in.Egress.AllowedCIDRs = []string{"203.0.113.0/40"} }, "CIDR"},
		{"unmapped egress protocol", func(in *ProfileInput) { in.Egress.AllowedProtocols = []string{"gopher"} }, "no OS-level port mapping"},
		{"domains without cidrs unacknowledged", func(in *ProfileInput) {
			in.Egress.AllowedCIDRs = nil
		}, "egress_domains_gateway_only"},
		{"negative payload cap", func(in *ProfileInput) { in.Egress.MaxPayloadBytes = -1 }, "max_payload_bytes"},
		{"negative memory", func(in *ProfileInput) { in.Resources.MemoryMB = -1 }, "negative"},
		{"fractional cpu percent", func(in *ProfileInput) { in.Resources.CPUMillis = 505 }, "multiple of 10"},
		{"cpu overflow bait", func(in *ProfileInput) { in.Resources.CPUMillis = maxCPUMillis * 10 }, "cpu_millis must not exceed"},
		{"memory overflow bait", func(in *ProfileInput) { in.Resources.MemoryMB = 1 << 60 }, "memory_mb must not exceed"},
		{"pid overflow bait", func(in *ProfileInput) { in.Resources.MaxProcesses = 1 << 40 }, "max_processes must not exceed"},
		{"invalid protect_system", func(in *ProfileInput) { in.Hardening.ProtectSystem = "always" }, "protect_system"},
		{"invalid address family", func(in *ProfileInput) { in.Hardening.RestrictAddressFamilies = []string{"INET"} }, "AF_*"},
		{"relative read-only path", func(in *ProfileInput) { in.Hardening.ReadOnlyPaths = []string{"etc/helm"} }, "absolute"},
		{"invalid device permit", func(in *ProfileInput) { in.DevicePermits = []string{"/dev/null rwx"} }, "device permit"},
		{"device permit traversal", func(in *ProfileInput) { in.DevicePermits = []string{"/dev/../proc/kcore rw"} }, "clean path under /dev"},
		{"device permit dot segment", func(in *ProfileInput) { in.DevicePermits = []string{"/dev/./mem rw"} }, "clean path under /dev"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := fixtureInput()
			tc.mutate(&in)
			err := in.Validate()
			if err == nil {
				t.Fatalf("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestEnforceTierRequiresHardenedMinimum pins the fail-closed rule that an
// omitted or zero-value hardening block cannot compile an unhardened unit
// under the enforce tier.
func TestEnforceTierRequiresHardenedMinimum(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*ProfileInput)
		wantSub string
	}{
		{"zero-value hardening", func(in *ProfileInput) { in.Hardening = HardeningOptions{} }, "no_new_privileges"},
		{"privileges not dropped", func(in *ProfileInput) { in.Hardening.NoNewPrivileges = false }, "no_new_privileges"},
		{"protect_system omitted", func(in *ProfileInput) { in.Hardening.ProtectSystem = "" }, "protect_system"},
		{"protect_system too weak", func(in *ProfileInput) { in.Hardening.ProtectSystem = "yes" }, "protect_system"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := fixtureInput()
			tc.mutate(&in)
			err := in.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("enforce tier must reject %s, got %v", tc.name, err)
			}
			// The same posture is a legitimate observe-tier profile.
			in.ModeTier = TierObserve
			if err := in.Validate(); err != nil {
				t.Fatalf("observe tier must still accept it: %v", err)
			}
		})
	}
}

func TestDomainsWithoutCIDRsAcknowledged(t *testing.T) {
	in := fixtureInput()
	in.Egress.AllowedCIDRs = nil
	in.EgressDomainsGatewayOnly = true
	if err := in.Validate(); err != nil {
		t.Fatalf("acknowledged gateway-only domains must validate: %v", err)
	}
}

func TestHashStableAndInputSensitive(t *testing.T) {
	first, err := fixtureInput().Hash()
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixtureInput().Hash()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("hash must be stable: %s vs %s", first, second)
	}
	if !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("hash must be sha256:-prefixed, got %s", first)
	}
	observe := fixtureInput()
	observe.ModeTier = TierObserve
	third, err := observe.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Fatalf("hash must change when the input changes")
	}
}
