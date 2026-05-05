package sandbox

import (
	"testing"
	"time"
)

func TestDefaultBackendProfilesAreDenyNetworkByDefault(t *testing.T) {
	for _, profile := range DefaultBackendProfiles() {
		if !profile.DenyNetworkByDefault {
			t.Fatalf("profile %s is not deny-network-by-default", profile.Name)
		}
	}
}

func TestGrantFromPolicySealsSandboxGrant(t *testing.T) {
	policy := &SandboxPolicy{
		PolicyID:       "build",
		FSAllowlist:    []string{"/workspace"},
		NetworkDenyAll: true,
		MaxMemoryBytes: 512 * 1024 * 1024,
		MaxCPUSeconds:  60,
		MaxOpenFiles:   32,
		ReadOnly:       true,
	}
	grant, err := GrantFromPolicy(policy, "wazero", "build-ro", "sha256:image", "epoch-42", time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("grant from policy: %v", err)
	}
	if grant.GrantHash == "" {
		t.Fatal("grant hash not populated")
	}
	if grant.Network.Mode != "deny-all" {
		t.Fatalf("network mode = %s, want deny-all", grant.Network.Mode)
	}
	if len(grant.FilesystemPreopens) != 1 || grant.FilesystemPreopens[0].Mode != "ro" {
		t.Fatalf("unexpected preopens: %#v", grant.FilesystemPreopens)
	}
}

func TestGrantFromPolicyRequiresNetworkAllowlist(t *testing.T) {
	policy := &SandboxPolicy{
		PolicyID:       "bad-net",
		FSAllowlist:    []string{"/workspace"},
		NetworkDenyAll: false,
	}
	if _, err := GrantFromPolicy(policy, "wazero", "bad-net", "", "epoch-42", time.Now().UTC()); err == nil {
		t.Fatal("expected allowlist network policy without destinations to fail")
	}
}
