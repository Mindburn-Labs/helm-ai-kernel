package launchkit

import (
	"context"
	"os/exec"
	"runtime"
	"time"
)

func NormalizeTarget(value string) Target {
	switch value {
	case "", "local", "local.docker", "local-container":
		return TargetLocal
	case "cloud":
		return TargetCloudHELM
	case "cloud:helm", "helm":
		return TargetCloudHELM
	case "cloud:aws", "aws":
		return TargetCloudAWS
	case "cloud:kubernetes", "kubernetes", "k8s":
		return TargetCloudKubernetes
	default:
		return Target(value)
	}
}

func DefaultProviders() map[Target]EnvironmentProvider {
	return map[Target]EnvironmentProvider{
		TargetLocal:           LocalDockerProvider{},
		TargetCloudHELM:       CloudProvider{Target: TargetCloudHELM, Region: "managed"},
		TargetCloudAWS:        CloudProvider{Target: TargetCloudAWS, Region: "unset"},
		TargetCloudKubernetes: CloudProvider{Target: TargetCloudKubernetes, Region: "current-context"},
	}
}

type LocalDockerProvider struct{}

func (LocalDockerProvider) ID() Target {
	return TargetLocal
}

func (LocalDockerProvider) SubstrateID() string {
	return "local-container"
}

func (LocalDockerProvider) Probe() EnvironmentCapability {
	capability := EnvironmentCapability{
		ID:                    "local.docker",
		Kind:                  "local-container",
		Available:             false,
		AuthState:             "not-required",
		CostEstimate:          "none",
		SecretBackend:         "local-env-grants",
		NetworkBoundary:       "deny-by-default-with-launch-scoped-egress",
		RuntimeBoundary:       "docker-container",
		LogBoundary:           "local-redacted-log",
		TeardownSupport:       "cascade",
		EvidenceExportSupport: "local-offline",
		Metadata: map[string]string{
			"os":   runtime.GOOS,
			"arch": runtime.GOARCH,
		},
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		capability.Detail = "docker binary was not found"
		return capability
	}
	capability.Metadata["docker_path"] = docker
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, docker, "info").Run(); err != nil {
		capability.Detail = "docker is installed but the daemon is not ready"
		return capability
	}
	capability.Available = true
	capability.Detail = "docker daemon is ready"
	return capability
}

type CloudProvider struct {
	Target Target
	Region string
}

func (p CloudProvider) ID() Target {
	return p.Target
}

func (p CloudProvider) SubstrateID() string {
	return string(p.Target)
}

func (p CloudProvider) Probe() EnvironmentCapability {
	id := string(p.Target)
	secretBackend := "helm-cloud-secrets"
	runtimeBoundary := "managed-container"
	if p.Target == TargetCloudAWS {
		secretBackend = "aws-secrets-manager"
		runtimeBoundary = "aws-container-task"
	}
	if p.Target == TargetCloudKubernetes {
		secretBackend = "kubernetes-secret"
		runtimeBoundary = "kubernetes-pod"
	}
	return EnvironmentCapability{
		ID:                    id,
		Kind:                  "cloud",
		Available:             false,
		AuthState:             "not-authenticated",
		CostEstimate:          "requires-explicit-approval",
		Region:                p.Region,
		SecretBackend:         secretBackend,
		NetworkBoundary:       "provider-private-network-deny-by-default",
		RuntimeBoundary:       runtimeBoundary,
		LogBoundary:           "provider-redacted-log",
		TeardownSupport:       "cascade-required",
		EvidenceExportSupport: "local-offline-export-required",
		Detail:                "cloud target requires authenticated provider state and explicit cost approval before launch",
	}
}
