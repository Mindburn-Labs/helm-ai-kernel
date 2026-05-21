package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

const (
	IsolationModeDockerDefault      = "docker-default"
	IsolationModeDockerRootlessUser = "docker-rootless-userns"
	IsolationModeDockerECI          = "docker-eci"
	IsolationModeGVisor             = "gvisor"
	IsolationModeKataFirecracker    = "kata-firecracker"
	IsolationModeDedicatedVM        = "dedicated-vm"
)

type IsolationEvidence struct {
	Mode               string   `json:"mode"`
	Hardened           bool     `json:"hardened"`
	RuntimeClass       string   `json:"runtime_class,omitempty"`
	DockerRootless     bool     `json:"docker_rootless"`
	DockerUserns       bool     `json:"docker_userns"`
	DockerECI          bool     `json:"docker_eci"`
	DedicatedVM        bool     `json:"dedicated_vm"`
	DockerRuntimes     []string `json:"docker_runtimes,omitempty"`
	DefaultRuntime     string   `json:"default_runtime,omitempty"`
	DetectionStatus    string   `json:"detection_status"`
	UnsupportedReason  string   `json:"unsupported_reason,omitempty"`
	HostileAgentGrade  bool     `json:"hostile_agent_grade"`
	PayloadInspection  string   `json:"payload_inspection"`
	NetworkProof       string   `json:"network_proof"`
	TokenBrokerEnabled bool     `json:"token_broker_enabled"`
}

type DockerIsolationInfo struct {
	Rootless       bool
	UserNamespaces bool
	ECI            bool
	DedicatedVM    bool
	Runtimes       []string
	DefaultRuntime string
}

type DockerInfoProvider func(string) (DockerIsolationInfo, error)

type IsolationModeError struct {
	Evidence IsolationEvidence
	Reason   string
	Cause    error
}

func (e *IsolationModeError) Error() string {
	if e == nil {
		return ""
	}
	if e.Reason != "" {
		return e.Reason
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return "Launchpad isolation mode denied"
}

func (e *IsolationModeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func IsolationEvidenceFromError(err error) (IsolationEvidence, bool) {
	var isolationErr *IsolationModeError
	if errors.As(err, &isolationErr) && isolationErr != nil {
		return isolationErr.Evidence, true
	}
	return IsolationEvidence{}, false
}

func ResolveIsolationMode(mode string) string {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		return IsolationModeDockerDefault
	}
	return mode
}

func ValidateIsolationMode(mode string) error {
	switch ResolveIsolationMode(mode) {
	case IsolationModeDockerDefault,
		IsolationModeDockerRootlessUser,
		IsolationModeDockerECI,
		IsolationModeGVisor,
		IsolationModeKataFirecracker,
		IsolationModeDedicatedVM:
		return nil
	default:
		return fmt.Errorf("unsupported Launchpad isolation mode %q", mode)
	}
}

func ResolveIsolationProfile(mode, dockerBin string, provider DockerInfoProvider) (IsolationEvidence, error) {
	mode = ResolveIsolationMode(mode)
	evidence := IsolationEvidence{
		Mode:              mode,
		DetectionStatus:   "not_required",
		PayloadInspection: "opaque_connect",
		NetworkProof:      "destination_allowlist_only",
	}
	if err := ValidateIsolationMode(mode); err != nil {
		evidence.DetectionStatus = "unsupported"
		evidence.UnsupportedReason = err.Error()
		return evidence, &IsolationModeError{Evidence: evidence, Reason: err.Error(), Cause: err}
	}
	if mode == IsolationModeDockerDefault {
		return evidence, nil
	}
	if provider == nil {
		provider = DockerIsolationInfoFromCLI
	}
	info, err := provider(dockerBin)
	if err != nil {
		evidence.DetectionStatus = "unavailable"
		evidence.UnsupportedReason = err.Error()
		reason := fmt.Sprintf("%s isolation detection failed: %v", mode, err)
		evidence.UnsupportedReason = reason
		return evidence, &IsolationModeError{Evidence: evidence, Reason: reason, Cause: err}
	}
	applyDockerInfo(&evidence, info)
	evidence.DetectionStatus = "detected"

	switch mode {
	case IsolationModeDockerRootlessUser:
		if !info.Rootless && !info.UserNamespaces {
			return unsupportedIsolation(evidence, "docker-rootless-userns requires Docker rootless mode or user namespace remapping")
		}
		evidence.Hardened = true
	case IsolationModeDockerECI:
		if !info.ECI {
			return unsupportedIsolation(evidence, "docker-eci requires Docker Enhanced Container Isolation evidence")
		}
		evidence.Hardened = true
	case IsolationModeGVisor:
		runtimeClass := runtimeClassFromEnv("runsc")
		if !hasRuntime(info.Runtimes, runtimeClass) {
			return unsupportedIsolation(evidence, fmt.Sprintf("gvisor requires Docker runtime %q", runtimeClass))
		}
		evidence.RuntimeClass = runtimeClass
		evidence.Hardened = true
	case IsolationModeKataFirecracker:
		runtimeClass := runtimeClassFromEnv("kata-fc")
		if !hasRuntime(info.Runtimes, runtimeClass) && !hasAnyRuntime(info.Runtimes, "io.containerd.kata-fc.v2", "kata-runtime", "kata") {
			return unsupportedIsolation(evidence, "kata-firecracker requires a configured Kata/Firecracker Docker runtime")
		}
		evidence.RuntimeClass = runtimeClass
		evidence.Hardened = true
	case IsolationModeDedicatedVM:
		if !info.DedicatedVM {
			return unsupportedIsolation(evidence, "dedicated-vm requires HELM_LAUNCHPAD_DEDICATED_VM=1 or external VM attestation")
		}
		evidence.Hardened = true
		evidence.HostileAgentGrade = true
	}
	if evidence.Hardened && mode != IsolationModeDockerRootlessUser {
		evidence.HostileAgentGrade = true
	}
	return evidence, nil
}

func DockerIsolationInfoFromCLI(dockerBin string) (DockerIsolationInfo, error) {
	if strings.TrimSpace(dockerBin) == "" {
		dockerBin = "docker"
	}
	if _, err := exec.LookPath(dockerBin); err != nil {
		return DockerIsolationInfo{}, err
	}
	out, err := exec.Command(dockerBin, "info", "--format", "{{json .}}").Output()
	if err != nil {
		return DockerIsolationInfo{}, err
	}
	var raw struct {
		SecurityOptions []string       `json:"SecurityOptions"`
		Runtimes        map[string]any `json:"Runtimes"`
		DefaultRuntime  string         `json:"DefaultRuntime"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return DockerIsolationInfo{}, err
	}
	info := DockerIsolationInfo{DefaultRuntime: raw.DefaultRuntime}
	for _, option := range raw.SecurityOptions {
		normalized := strings.ToLower(option)
		if strings.Contains(normalized, "rootless") {
			info.Rootless = true
		}
		if strings.Contains(normalized, "userns") || strings.Contains(normalized, "user namespace") {
			info.UserNamespaces = true
		}
		if strings.Contains(normalized, "enhanced") || strings.Contains(normalized, "eci") {
			info.ECI = true
		}
	}
	for name := range raw.Runtimes {
		info.Runtimes = append(info.Runtimes, name)
	}
	sort.Strings(info.Runtimes)
	info.ECI = info.ECI || truthyEnv("HELM_LAUNCHPAD_DOCKER_ECI")
	info.DedicatedVM = truthyEnv("HELM_LAUNCHPAD_DEDICATED_VM")
	return info, nil
}

func applyDockerInfo(evidence *IsolationEvidence, info DockerIsolationInfo) {
	evidence.DockerRootless = info.Rootless
	evidence.DockerUserns = info.UserNamespaces
	evidence.DockerECI = info.ECI
	evidence.DedicatedVM = info.DedicatedVM
	evidence.DockerRuntimes = append([]string{}, info.Runtimes...)
	evidence.DefaultRuntime = info.DefaultRuntime
}

func unsupportedIsolation(evidence IsolationEvidence, reason string) (IsolationEvidence, error) {
	evidence.DetectionStatus = "unsupported"
	evidence.UnsupportedReason = reason
	return evidence, &IsolationModeError{Evidence: evidence, Reason: reason}
}

func runtimeClassFromEnv(defaultClass string) string {
	if override := strings.TrimSpace(os.Getenv("HELM_LAUNCHPAD_DOCKER_RUNTIME")); override != "" {
		return override
	}
	return defaultClass
}

func hasAnyRuntime(runtimes []string, candidates ...string) bool {
	for _, candidate := range candidates {
		if hasRuntime(runtimes, candidate) {
			return true
		}
	}
	return false
}

func hasRuntime(runtimes []string, target string) bool {
	for _, runtime := range runtimes {
		if runtime == target {
			return true
		}
	}
	return false
}

func truthyEnv(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
