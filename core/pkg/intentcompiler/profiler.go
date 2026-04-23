package intentcompiler

import "github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"

// SandboxBackend constants for execution binding.
const (
	BackendNative = "native" // Local process execution (R0-R1)
	BackendWASI   = "wasi"   // WASI sandbox (R2)
	BackendDocker = "docker" // Docker container (R3-R4)
)

// SandboxProfile constants for execution profiles.
const (
	ProfileReadOnly       = "read-only"
	ProfileWorkspaceWrite = "workspace-write"
	ProfileBuildRunner    = "build-runner"
	ProfileNetLimited     = "net-limited"
	ProfilePrivileged     = "privileged-denied" // Always denied in HELM.
)

// SandboxProfiler assigns execution backends and profiles based on effect risk class.
type SandboxProfiler struct{}

// NewSandboxProfiler creates a new profiler.
func NewSandboxProfiler() *SandboxProfiler {
	return &SandboxProfiler{}
}

// AssignProfile determines the appropriate backend and profile for a plan step
// based on its effect type's risk classification.
func (p *SandboxProfiler) AssignProfile(step *contracts.PlanStep) (backend string, profile string) {
	riskClass := contracts.EffectRiskClass(step.EffectType)

	switch riskClass {
	case "E0":
		return BackendNative, ProfileReadOnly
	case "E1":
		return BackendNative, ProfileReadOnly
	case "E2":
		return BackendWASI, ProfileWorkspaceWrite
	case "E3":
		return BackendDocker, ProfileNetLimited
	case "E4":
		return BackendDocker, ProfileNetLimited
	default:
		// Fail-closed: unknown risk → docker + net-limited.
		return BackendDocker, ProfileNetLimited
	}
}
