package sandbox

import (
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type BackendKind string

const (
	BackendWazero      BackendKind = "wasi-wazero"
	BackendWasmtime    BackendKind = "wasi-wasmtime"
	BackendNSJail      BackendKind = "native-nsjail"
	BackendGVisor      BackendKind = "native-gvisor"
	BackendFirecracker BackendKind = "native-firecracker"
	BackendHosted      BackendKind = "hosted-adapter"
)

type BackendProfile struct {
	Name                 string      `json:"name"`
	Kind                 BackendKind `json:"kind"`
	Runtime              string      `json:"runtime"`
	Hosted               bool        `json:"hosted"`
	DenyNetworkByDefault bool        `json:"deny_network_by_default"`
	NativeIsolation      bool        `json:"native_isolation"`
	Experimental         bool        `json:"experimental,omitempty"`
}

func DefaultBackendProfiles() []BackendProfile {
	return []BackendProfile{
		{Name: "wazero-deny-default", Kind: BackendWazero, Runtime: "wazero", DenyNetworkByDefault: true},
		{Name: "wasmtime-deny-default", Kind: BackendWasmtime, Runtime: "wasmtime", DenyNetworkByDefault: true},
		{Name: "nsjail-native", Kind: BackendNSJail, Runtime: "nsjail", DenyNetworkByDefault: true, NativeIsolation: true},
		{Name: "gvisor-native", Kind: BackendGVisor, Runtime: "gvisor", DenyNetworkByDefault: true, NativeIsolation: true},
		{Name: "firecracker-native", Kind: BackendFirecracker, Runtime: "firecracker", DenyNetworkByDefault: true, NativeIsolation: true},
		{Name: "hosted-adapter", Kind: BackendHosted, Runtime: "hosted", Hosted: true, DenyNetworkByDefault: true, Experimental: true},
	}
}

// GrantFromPolicy converts a sandbox policy into a HELM-native SandboxGrant.
// The grant must be sealed before execution and referenced by receipts.
func GrantFromPolicy(policy *SandboxPolicy, runtimeName, profileName, imageDigest, policyEpoch string, declaredAt time.Time) (contracts.SandboxGrant, error) {
	if policy == nil {
		policy = DefaultPolicy()
	}
	if declaredAt.IsZero() {
		declaredAt = time.Now().UTC()
	}
	if runtimeName == "" {
		return contracts.SandboxGrant{}, fmt.Errorf("runtime is required")
	}
	if profileName == "" {
		profileName = policy.PolicyID
	}

	preopens := make([]contracts.FilesystemPreopen, 0, len(policy.FSAllowlist))
	mode := "rw"
	if policy.ReadOnly {
		mode = "ro"
	}
	for _, path := range policy.FSAllowlist {
		if path == "" {
			continue
		}
		preopens = append(preopens, contracts.FilesystemPreopen{Path: path, Mode: mode})
	}

	network := contracts.NetworkGrant{Mode: "deny-all"}
	if !policy.NetworkDenyAll {
		network.Mode = "allowlist"
		network.Destinations = append([]string(nil), policy.NetworkAllowlist...)
	}

	grant := contracts.SandboxGrant{
		GrantID:            fmt.Sprintf("grant-%s-%d", policy.PolicyID, declaredAt.UnixNano()),
		Runtime:            runtimeName,
		Profile:            profileName,
		ImageDigest:        imageDigest,
		FilesystemPreopens: preopens,
		Env:                contracts.EnvExposurePolicy{Mode: "deny-all"},
		Network:            network,
		Limits: contracts.SandboxGrantLimits{
			MemoryBytes: policy.MaxMemoryBytes,
			CPUTime:     time.Duration(policy.MaxCPUSeconds) * time.Second,
			OpenFiles:   policy.MaxOpenFiles,
		},
		DeclaredAt:  declaredAt.UTC(),
		PolicyEpoch: policyEpoch,
	}
	return grant.Seal()
}
